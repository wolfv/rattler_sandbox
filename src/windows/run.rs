//! Legacy Windows capture orchestrator.
//!
//! Direct port of the `windows_impl` block from `codex-rs/windows-sandbox-rs/src/lib.rs`.
//! Provides [`run_windows_sandbox_capture`] (and the workspace-write preflight
//! variant) plus the `CaptureResult` type — these are the entry points the
//! caller invokes for direct (non-elevated) sandbox runs.

use crate::windows::acl::add_allow_ace;
use crate::windows::acl::add_deny_write_ace;
use crate::windows::acl::allow_null_device;
use crate::windows::acl::revoke_ace;
use crate::windows::allow::AllowDenyPaths;
use crate::windows::allow::compute_allow_paths;
use crate::windows::cap::load_or_create_cap_sids;
use crate::windows::cap::workspace_cap_sid_for_cwd;
use crate::windows::logging::log_failure;
use crate::windows::logging::log_success;
use crate::windows::path_normalization::canonicalize_path;
use crate::windows::policy::SandboxPolicy;
use crate::windows::process::create_process_as_user;
use crate::windows::sandbox_utils::ensure_codex_home_exists;
use crate::windows::spawn_prep::prepare_legacy_spawn_context;
use crate::windows::token::convert_string_sid_to_sid;
use crate::windows::token::create_workspace_write_token_with_caps_from;
use crate::windows::workspace_acl::is_command_cwd_root;
use anyhow::Result;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT;
use windows_sys::Win32::Foundation::SetHandleInformation;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::GetExitCodeProcess;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

type PipeHandles = ((HANDLE, HANDLE), (HANDLE, HANDLE), (HANDLE, HANDLE));

unsafe fn setup_stdio_pipes() -> io::Result<PipeHandles> {
    let mut in_r: HANDLE = 0;
    let mut in_w: HANDLE = 0;
    let mut out_r: HANDLE = 0;
    let mut out_w: HANDLE = 0;
    let mut err_r: HANDLE = 0;
    let mut err_w: HANDLE = 0;
    if CreatePipe(&mut in_r, &mut in_w, ptr::null_mut(), 0) == 0 {
        return Err(io::Error::from_raw_os_error(GetLastError() as i32));
    }
    if CreatePipe(&mut out_r, &mut out_w, ptr::null_mut(), 0) == 0 {
        return Err(io::Error::from_raw_os_error(GetLastError() as i32));
    }
    if CreatePipe(&mut err_r, &mut err_w, ptr::null_mut(), 0) == 0 {
        return Err(io::Error::from_raw_os_error(GetLastError() as i32));
    }
    if SetHandleInformation(in_r, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
        return Err(io::Error::from_raw_os_error(GetLastError() as i32));
    }
    if SetHandleInformation(out_w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
        return Err(io::Error::from_raw_os_error(GetLastError() as i32));
    }
    if SetHandleInformation(err_w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
        return Err(io::Error::from_raw_os_error(GetLastError() as i32));
    }
    Ok(((in_r, in_w), (out_r, out_w), (err_r, err_w)))
}

pub struct CaptureResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn run_windows_sandbox_capture(
    policy_json_or_preset: &str,
    sandbox_policy_cwd: &Path,
    codex_home: &Path,
    command: Vec<String>,
    cwd: &Path,
    env_map: HashMap<String, String>,
    timeout_ms: Option<u64>,
    use_private_desktop: bool,
) -> Result<CaptureResult> {
    run_windows_sandbox_capture_with_extra_deny_write_paths(
        policy_json_or_preset,
        sandbox_policy_cwd,
        codex_home,
        command,
        cwd,
        env_map,
        timeout_ms,
        &[],
        use_private_desktop,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_windows_sandbox_capture_with_extra_deny_write_paths(
    policy_json_or_preset: &str,
    sandbox_policy_cwd: &Path,
    codex_home: &Path,
    command: Vec<String>,
    cwd: &Path,
    mut env_map: HashMap<String, String>,
    timeout_ms: Option<u64>,
    additional_deny_write_paths: &[PathBuf],
    use_private_desktop: bool,
) -> Result<CaptureResult> {
    let common = prepare_legacy_spawn_context(
        policy_json_or_preset,
        codex_home,
        cwd,
        &mut env_map,
        &command,
        /*inherit_path*/ false,
        /*add_git_safe_directory*/ false,
    )?;
    let policy = common.policy;
    let current_dir = common.current_dir;
    let logs_base_dir = common.logs_base_dir.as_deref();
    let is_workspace_write = common.is_workspace_write;
    if !policy.has_full_disk_read_access() {
        anyhow::bail!("Restricted read-only access requires the elevated Windows sandbox backend");
    }
    let caps = load_or_create_cap_sids(codex_home)?;
    let (h_token, psid_generic, psid_workspace): (HANDLE, *mut c_void, Option<*mut c_void>) = unsafe {
        match &policy {
            SandboxPolicy::ReadOnly { .. } => {
                #[allow(clippy::expect_used)]
                let psid = convert_string_sid_to_sid(&caps.readonly).expect("valid readonly SID");
                let (h, _) = crate::windows::token::create_readonly_token_with_cap(psid)?;
                (h, psid, None)
            }
            SandboxPolicy::WorkspaceWrite { .. } => {
                #[allow(clippy::expect_used)]
                let psid_generic =
                    convert_string_sid_to_sid(&caps.workspace).expect("valid workspace SID");
                let ws_sid = workspace_cap_sid_for_cwd(codex_home, cwd)?;
                #[allow(clippy::expect_used)]
                let psid_workspace =
                    convert_string_sid_to_sid(&ws_sid).expect("valid workspace SID");
                let base = crate::windows::token::get_current_token_for_restriction()?;
                let h_res = create_workspace_write_token_with_caps_from(
                    base,
                    &[psid_generic, psid_workspace],
                );
                windows_sys::Win32::Foundation::CloseHandle(base);
                let h = h_res?;
                (h, psid_generic, Some(psid_workspace))
            }
            SandboxPolicy::DangerFullAccess | SandboxPolicy::ExternalSandbox { .. } => {
                unreachable!("DangerFullAccess handled above")
            }
        }
    };

    unsafe {
        if is_workspace_write
            && let Ok(base) = crate::windows::token::get_current_token_for_restriction()
        {
            if let Ok(bytes) = crate::windows::token::get_logon_sid_bytes(base) {
                let mut tmp = bytes;
                let psid2 = tmp.as_mut_ptr() as *mut c_void;
                allow_null_device(psid2);
            }
            windows_sys::Win32::Foundation::CloseHandle(base);
        }
    }

    let persist_aces = is_workspace_write;
    let AllowDenyPaths { allow, mut deny } =
        compute_allow_paths(&policy, sandbox_policy_cwd, &current_dir, &env_map);
    for path in additional_deny_write_paths {
        if path.exists() {
            deny.insert(path.clone());
        }
    }
    let canonical_cwd = canonicalize_path(&current_dir);
    let mut guards: Vec<(PathBuf, *mut c_void)> = Vec::new();
    unsafe {
        for p in &allow {
            let psid = if is_workspace_write && is_command_cwd_root(p, &canonical_cwd) {
                psid_workspace.unwrap_or(psid_generic)
            } else {
                psid_generic
            };
            if let Ok(added) = add_allow_ace(p, psid)
                && added
            {
                if persist_aces {
                    if p.is_dir() {
                        // best-effort seeding omitted intentionally
                    }
                } else {
                    guards.push((p.clone(), psid));
                }
            }
        }
        for p in &deny {
            if let Ok(added) = add_deny_write_ace(p, psid_generic)
                && added
                && !persist_aces
            {
                guards.push((p.clone(), psid_generic));
            }
        }
        allow_null_device(psid_generic);
        if let Some(psid) = psid_workspace {
            allow_null_device(psid);
        }
    }
    let (stdin_pair, stdout_pair, stderr_pair) = unsafe { setup_stdio_pipes()? };
    let ((in_r, in_w), (out_r, out_w), (err_r, err_w)) = (stdin_pair, stdout_pair, stderr_pair);
    let spawn_res = unsafe {
        create_process_as_user(
            h_token,
            &command,
            cwd,
            &env_map,
            logs_base_dir,
            Some((in_r, out_w, err_w)),
            use_private_desktop,
        )
    };
    let created = match spawn_res {
        Ok(v) => v,
        Err(err) => {
            unsafe {
                CloseHandle(in_r);
                CloseHandle(in_w);
                CloseHandle(out_r);
                CloseHandle(out_w);
                CloseHandle(err_r);
                CloseHandle(err_w);
                CloseHandle(h_token);
            }
            return Err(err);
        }
    };
    let pi = created.process_info;
    let _desktop = created;

    unsafe {
        CloseHandle(in_r);
        // Close the parent's stdin write end so the child sees EOF immediately.
        CloseHandle(in_w);
        CloseHandle(out_w);
        CloseHandle(err_w);
    }

    let (tx_out, rx_out) = std::sync::mpsc::channel::<Vec<u8>>();
    let (tx_err, rx_err) = std::sync::mpsc::channel::<Vec<u8>>();
    let t_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let mut read_bytes: u32 = 0;
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::ReadFile(
                    out_r,
                    tmp.as_mut_ptr(),
                    tmp.len() as u32,
                    &mut read_bytes,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read_bytes == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..read_bytes as usize]);
        }
        let _ = tx_out.send(buf);
    });
    let t_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let mut read_bytes: u32 = 0;
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::ReadFile(
                    err_r,
                    tmp.as_mut_ptr(),
                    tmp.len() as u32,
                    &mut read_bytes,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read_bytes == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..read_bytes as usize]);
        }
        let _ = tx_err.send(buf);
    });

    let timeout = timeout_ms.map(|ms| ms as u32).unwrap_or(INFINITE);
    let res = unsafe { WaitForSingleObject(pi.hProcess, timeout) };
    let timed_out = res == 0x0000_0102;
    let mut exit_code_u32: u32 = 1;
    if !timed_out {
        unsafe {
            GetExitCodeProcess(pi.hProcess, &mut exit_code_u32);
        }
    } else {
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
        }
    }

    unsafe {
        if pi.hThread != 0 {
            CloseHandle(pi.hThread);
        }
        if pi.hProcess != 0 {
            CloseHandle(pi.hProcess);
        }
        CloseHandle(h_token);
    }
    let _ = t_out.join();
    let _ = t_err.join();
    let stdout = rx_out.recv().unwrap_or_default();
    let stderr = rx_err.recv().unwrap_or_default();
    let exit_code = if timed_out {
        128 + 64
    } else {
        exit_code_u32 as i32
    };

    if exit_code == 0 {
        log_success(&command, logs_base_dir);
    } else {
        log_failure(&command, &format!("exit code {exit_code}"), logs_base_dir);
    }

    if !persist_aces {
        unsafe {
            for (p, sid) in guards {
                revoke_ace(&p, sid);
            }
        }
    }
    Ok(CaptureResult {
        exit_code,
        stdout,
        stderr,
        timed_out,
    })
}

pub fn run_windows_sandbox_legacy_preflight(
    sandbox_policy: &SandboxPolicy,
    sandbox_policy_cwd: &Path,
    codex_home: &Path,
    cwd: &Path,
    env_map: &HashMap<String, String>,
) -> Result<()> {
    let is_workspace_write = matches!(sandbox_policy, SandboxPolicy::WorkspaceWrite { .. });
    if !is_workspace_write {
        return Ok(());
    }

    ensure_codex_home_exists(codex_home)?;
    let caps = load_or_create_cap_sids(codex_home)?;
    #[allow(clippy::expect_used)]
    let psid_generic =
        unsafe { convert_string_sid_to_sid(&caps.workspace) }.expect("valid workspace SID");
    let ws_sid = workspace_cap_sid_for_cwd(codex_home, cwd)?;
    #[allow(clippy::expect_used)]
    let psid_workspace =
        unsafe { convert_string_sid_to_sid(&ws_sid) }.expect("valid workspace SID");
    let current_dir = cwd.to_path_buf();
    let AllowDenyPaths { allow, deny } =
        compute_allow_paths(sandbox_policy, sandbox_policy_cwd, &current_dir, env_map);
    let canonical_cwd = canonicalize_path(&current_dir);
    unsafe {
        for p in &allow {
            let psid = if is_command_cwd_root(p, &canonical_cwd) {
                psid_workspace
            } else {
                psid_generic
            };
            let _ = add_allow_ace(p, psid);
        }
        for p in &deny {
            let _ = add_deny_write_ace(p, psid_generic);
        }
        allow_null_device(psid_generic);
        allow_null_device(psid_workspace);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::policy::SandboxPolicy;
    use crate::windows::spawn_prep::should_apply_network_block;

    fn workspace_policy(network_access: bool) -> SandboxPolicy {
        SandboxPolicy::WorkspaceWrite {
            writable_roots: Vec::new(),
            network_access,
            exclude_tmpdir_env_var: false,
            exclude_slash_tmp: false,
        }
    }

    #[test]
    fn applies_network_block_when_access_is_disabled() {
        assert!(should_apply_network_block(&workspace_policy(
            /*network_access*/ false
        )));
    }

    #[test]
    fn skips_network_block_when_access_is_allowed() {
        assert!(!should_apply_network_block(&workspace_policy(
            /*network_access*/ true
        )));
    }

    #[test]
    fn applies_network_block_for_read_only() {
        assert!(should_apply_network_block(
            &SandboxPolicy::new_read_only_policy()
        ));
    }
}
