//! Windows sandboxing engine.
//!
//! Direct port of `codex-rs/windows-sandbox-rs/`. Modules are gated behind
//! `target_os = "windows"`; on other platforms the public API surfaces stubs
//! that bail at runtime.
//!
//! Scope of PR 5: foundational modules (token, ACL, allow, audit, cap, env,
//! identity, etc.). Network filtering (WFP) is included; conpty, the elevated
//! IPC runner, and the setup orchestrator land in later PRs.

#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(any(target_os = "windows", test))]
mod ssh_config_dependencies;

mod otel_stub;
mod utils_string;

macro_rules! windows_modules {
    ($($name:ident),+ $(,)?) => {
        $(#[cfg(target_os = "windows")] pub(crate) mod $name;)+
    };
}

windows_modules!(
    acl,
    allow,
    audit,
    cap,
    desktop,
    dpapi,
    elevated_impl,
    env,
    firewall,
    helper_materialization,
    hide_users,
    identity,
    logging,
    path_normalization,
    policy,
    process,
    proc_thread_attr,
    read_acl_mutex,
    sandbox_users,
    sandbox_utils,
    setup_error,
    setup_main_win,
    setup_orchestrator,
    setup_runtime_bin,
    spawn_prep,
    token,
    wfp,
    wfp_filter_specs,
    wfp_setup,
    winutil,
    workspace_acl,
);

#[cfg(target_os = "windows")]
pub(crate) mod conpty;

#[cfg(target_os = "windows")]
pub(crate) mod elevated {
    pub(crate) mod command_runner_win;
    pub(crate) mod cwd_junction;
    pub(crate) mod ipc_framed;
    pub(crate) mod runner_client;
    pub(crate) mod runner_pipe;
}

#[cfg(target_os = "windows")]
pub(crate) mod unified_exec {
    pub(crate) mod session;
    #[cfg(test)]
    mod tests;
    pub(crate) mod backends {
        pub(crate) mod elevated;
        pub(crate) mod legacy;
        pub(crate) mod windows_common;
    }
}

// ---------------------------------------------------------------------------
// Public re-exports (Windows builds only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub use acl::{
    add_deny_write_ace, allow_null_device, ensure_allow_mask_aces,
    ensure_allow_mask_aces_with_inheritance, ensure_allow_write_aces, fetch_dacl_handle,
    path_mask_allows,
};
#[cfg(target_os = "windows")]
pub use cap::{load_or_create_cap_sids, workspace_cap_sid_for_cwd};
#[cfg(target_os = "windows")]
pub use desktop::LaunchDesktop;
#[cfg(target_os = "windows")]
pub use dpapi::{protect as dpapi_protect, unprotect as dpapi_unprotect};
/// Non-Windows mirror of the `CaptureResult` type returned by the legacy
/// capture orchestrator. Mirrors the Windows definition in `windows::run`.
#[cfg(not(target_os = "windows"))]
#[derive(Debug, Default)]
pub struct CaptureResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

#[cfg(target_os = "windows")]
pub(crate) mod run;

#[cfg(target_os = "windows")]
pub use run::{
    CaptureResult, run_windows_sandbox_capture,
    run_windows_sandbox_capture_with_extra_deny_write_paths,
    run_windows_sandbox_legacy_preflight,
};

#[cfg(target_os = "windows")]
pub use audit::apply_world_writable_scan_and_denies;

// Helper-binary entry points re-exported for the `[[bin]]` targets in `src/bin/`.
#[cfg(target_os = "windows")]
pub mod bins {
    pub fn setup_main() -> anyhow::Result<()> {
        crate::windows::setup_main_win::main()
    }
    pub fn command_runner_main() -> anyhow::Result<()> {
        crate::windows::elevated::command_runner_win::main()
    }
}
#[cfg(target_os = "windows")]
pub use conpty::{ConptyInstance, spawn_conpty_process_as_user};
#[cfg(target_os = "windows")]
pub use unified_exec::session::{
    spawn_windows_sandbox_session_elevated, spawn_windows_sandbox_session_legacy,
};
#[cfg(target_os = "windows")]
pub use elevated_impl::{
    ElevatedSandboxCaptureRequest, run_windows_sandbox_capture as run_windows_sandbox_capture_elevated,
};
#[cfg(target_os = "windows")]
#[doc(hidden)]
pub use spawn_prep::LocalSid;
#[cfg(target_os = "windows")]
pub use elevated::ipc_framed::{
    ErrorPayload, ExitPayload, FramedMessage, Message, OutputPayload, OutputStream, ResizePayload,
    SpawnReady, SpawnRequest, decode_bytes, encode_bytes, read_frame, write_frame,
};
#[cfg(target_os = "windows")]
pub use helper_materialization::resolve_current_exe_for_launch;
#[cfg(target_os = "windows")]
pub use hide_users::{hide_current_user_profile_dir, hide_newly_created_users};
#[cfg(target_os = "windows")]
pub use identity::{require_logon_sandbox_creds, sandbox_setup_is_complete};
#[cfg(target_os = "windows")]
pub use setup_orchestrator::{
    SETUP_VERSION, SandboxSetupRequest, SetupRootOverrides, run_elevated_setup, run_setup_refresh,
    run_setup_refresh_with_extra_read_roots, sandbox_bin_dir, sandbox_dir, sandbox_secrets_dir,
};
#[cfg(target_os = "windows")]
pub use wfp::install_wfp_filters_for_account;
#[cfg(target_os = "windows")]
pub use wfp_setup::install_wfp_filters;
#[cfg(target_os = "windows")]
pub use logging::{LOG_FILE_NAME, log_note};
#[cfg(target_os = "windows")]
pub use path_normalization::canonicalize_path;
#[cfg(target_os = "windows")]
pub use policy::parse_policy;
#[cfg(target_os = "windows")]
pub use process::{
    PipeSpawnHandles, StderrMode, StdinMode, create_process_as_user, read_handle_loop,
    spawn_process_with_pipes,
};
#[cfg(target_os = "windows")]
pub use setup_error::{
    SetupErrorCode, SetupErrorReport, SetupFailure, extract_failure as extract_setup_failure,
    sanitize_setup_metric_tag_value, setup_error_path, write_setup_error_report,
};
#[cfg(target_os = "windows")]
pub use token::{
    convert_string_sid_to_sid, create_readonly_token_with_cap_from,
    create_readonly_token_with_caps_and_user_from, create_readonly_token_with_caps_from,
    create_workspace_write_token_with_caps_and_user_from,
    create_workspace_write_token_with_caps_from, get_current_token_for_restriction,
};
#[cfg(target_os = "windows")]
pub use winutil::{quote_windows_arg, string_from_sid_bytes, to_wide};
#[cfg(target_os = "windows")]
pub use workspace_acl::is_command_cwd_root;

// ---------------------------------------------------------------------------
// Non-Windows stubs for the public API
// ---------------------------------------------------------------------------
//
// Mirrors codex's `mod stub` block in `windows-sandbox-rs/src/lib.rs`. Lets
// cross-platform callers refer to these names unconditionally; on non-Windows
// the stubs return an error explaining the binary needs to be on Windows.

#[cfg(not(target_os = "windows"))]
mod stub {
    use super::CaptureResult;
    use crate::policy::SandboxPolicy;
    use anyhow::{Result, bail};
    use std::collections::HashMap;
    use std::path::Path;

    #[allow(clippy::too_many_arguments)]
    pub fn run_windows_sandbox_capture(
        _policy_json_or_preset: &str,
        _sandbox_policy_cwd: &Path,
        _codex_home: &Path,
        _command: Vec<String>,
        _cwd: &Path,
        _env_map: HashMap<String, String>,
        _timeout_ms: Option<u64>,
        _use_private_desktop: bool,
    ) -> Result<CaptureResult> {
        bail!("Windows sandbox is only available on Windows")
    }

    pub fn run_windows_sandbox_legacy_preflight(
        _sandbox_policy: &SandboxPolicy,
        _sandbox_policy_cwd: &Path,
        _codex_home: &Path,
        _cwd: &Path,
        _env_map: &HashMap<String, String>,
    ) -> Result<()> {
        bail!("Windows sandbox is only available on Windows")
    }

    pub fn apply_world_writable_scan_and_denies(
        _codex_home: &Path,
        _cwd: &Path,
        _env_map: &HashMap<String, String>,
        _sandbox_policy: &SandboxPolicy,
        _logs_base_dir: Option<&Path>,
    ) -> Result<()> {
        bail!("Windows sandbox is only available on Windows")
    }
}

#[cfg(not(target_os = "windows"))]
pub use stub::{
    apply_world_writable_scan_and_denies, run_windows_sandbox_capture,
    run_windows_sandbox_legacy_preflight,
};
