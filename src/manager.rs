//! Sandbox manager: dispatcher that selects an engine and constructs the
//! actual command line.
//!
//! Stub during PR 1; full port lands once the engine modules are in place.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;

use crate::network_proxy::NetworkProxy;
use crate::path::AbsolutePathBuf;
use crate::policy::{
    AdditionalPermissionProfile, FileSystemSandboxPolicy, NetworkSandboxPolicy, PermissionProfile,
    SandboxPolicy, WindowsSandboxLevel,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxType {
    None,
    MacosSeatbelt,
    LinuxSeccomp,
    WindowsRestrictedToken,
}

impl SandboxType {
    pub fn as_metric_tag(self) -> &'static str {
        match self {
            SandboxType::None => "none",
            SandboxType::MacosSeatbelt => "seatbelt",
            SandboxType::LinuxSeccomp => "seccomp",
            SandboxType::WindowsRestrictedToken => "windows_sandbox",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxablePreference {
    Auto,
    Require,
    Forbid,
}

pub fn get_platform_sandbox(windows_sandbox_enabled: bool) -> Option<SandboxType> {
    if cfg!(target_os = "macos") {
        Some(SandboxType::MacosSeatbelt)
    } else if cfg!(target_os = "linux") {
        Some(SandboxType::LinuxSeccomp)
    } else if cfg!(target_os = "windows") {
        if windows_sandbox_enabled {
            Some(SandboxType::WindowsRestrictedToken)
        } else {
            None
        }
    } else {
        None
    }
}

#[derive(Debug)]
pub struct SandboxCommand {
    pub program: OsString,
    pub args: Vec<String>,
    pub cwd: AbsolutePathBuf,
    pub env: HashMap<String, String>,
    pub additional_permissions: Option<AdditionalPermissionProfile>,
}

#[derive(Debug)]
pub struct SandboxExecRequest {
    pub command: Vec<String>,
    pub cwd: AbsolutePathBuf,
    pub env: HashMap<String, String>,
    pub network: Option<NetworkProxy>,
    pub sandbox: SandboxType,
    pub windows_sandbox_level: WindowsSandboxLevel,
    pub windows_sandbox_private_desktop: bool,
    pub permission_profile: PermissionProfile,
    pub file_system_sandbox_policy: FileSystemSandboxPolicy,
    pub network_sandbox_policy: NetworkSandboxPolicy,
    pub arg0: Option<String>,
}

pub struct SandboxTransformRequest<'a> {
    pub command: SandboxCommand,
    pub permissions: &'a PermissionProfile,
    pub sandbox: SandboxType,
    pub enforce_managed_network: bool,
    pub network: Option<&'a NetworkProxy>,
    pub sandbox_policy_cwd: &'a Path,
    pub linux_sandbox_exe: Option<&'a Path>,
    pub use_legacy_landlock: bool,
    pub windows_sandbox_level: WindowsSandboxLevel,
    pub windows_sandbox_private_desktop: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxTransformError {
    #[error("missing linux sandbox executable path")]
    MissingLinuxSandboxExecutable,
    #[cfg(target_os = "linux")]
    #[error("bubblewrap is not supported under WSL1")]
    Wsl1UnsupportedForBubblewrap,
    #[cfg(not(target_os = "macos"))]
    #[error("seatbelt sandbox is only available on macOS")]
    SeatbeltUnavailable,
}

#[derive(Default)]
pub struct SandboxManager;

impl SandboxManager {
    pub fn new() -> Self {
        Self
    }

    pub fn select_initial(
        &self,
        file_system_policy: &FileSystemSandboxPolicy,
        network_policy: NetworkSandboxPolicy,
        pref: SandboxablePreference,
        windows_sandbox_level: WindowsSandboxLevel,
        has_managed_network_requirements: bool,
    ) -> SandboxType {
        match pref {
            SandboxablePreference::Forbid => SandboxType::None,
            SandboxablePreference::Require => {
                get_platform_sandbox(windows_sandbox_level != WindowsSandboxLevel::Disabled)
                    .unwrap_or(SandboxType::None)
            }
            SandboxablePreference::Auto => {
                if crate::policy_transforms::should_require_platform_sandbox(
                    file_system_policy,
                    network_policy,
                    has_managed_network_requirements,
                ) {
                    get_platform_sandbox(windows_sandbox_level != WindowsSandboxLevel::Disabled)
                        .unwrap_or(SandboxType::None)
                } else {
                    SandboxType::None
                }
            }
        }
    }

    pub fn transform(
        &self,
        request: SandboxTransformRequest<'_>,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        let SandboxTransformRequest {
            mut command,
            permissions,
            sandbox,
            enforce_managed_network,
            network,
            sandbox_policy_cwd,
            linux_sandbox_exe,
            use_legacy_landlock,
            windows_sandbox_level,
            windows_sandbox_private_desktop,
        } = request;

        let additional_permissions = command.additional_permissions.take();
        let effective = crate::policy_transforms::effective_permission_profile(
            permissions,
            additional_permissions.as_ref(),
        );
        let (effective_fs_policy, effective_net_policy) = effective.to_runtime_permissions();

        let mut argv: Vec<OsString> = Vec::with_capacity(1 + command.args.len());
        argv.push(command.program);
        argv.extend(command.args.into_iter().map(OsString::from));

        let (argv, arg0_override) = match sandbox {
            SandboxType::None => (os_argv_to_strings(argv), None),

            #[cfg(target_os = "macos")]
            SandboxType::MacosSeatbelt => {
                use crate::seatbelt::{
                    CreateSeatbeltCommandArgsParams, MACOS_PATH_TO_SEATBELT_EXECUTABLE,
                    create_seatbelt_command_args,
                };
                let mut args = create_seatbelt_command_args(CreateSeatbeltCommandArgsParams {
                    command: os_argv_to_strings(argv),
                    file_system_sandbox_policy: &effective_fs_policy,
                    network_sandbox_policy: effective_net_policy,
                    sandbox_policy_cwd,
                    enforce_managed_network,
                    network,
                    extra_allow_unix_sockets: &[],
                });
                let mut full = Vec::with_capacity(1 + args.len());
                full.push(MACOS_PATH_TO_SEATBELT_EXECUTABLE.to_string());
                full.append(&mut args);
                (full, None)
            }
            #[cfg(not(target_os = "macos"))]
            SandboxType::MacosSeatbelt => {
                return Err(SandboxTransformError::SeatbeltUnavailable);
            }

            #[cfg(target_os = "linux")]
            SandboxType::LinuxSeccomp => {
                let exe = linux_sandbox_exe
                    .ok_or(SandboxTransformError::MissingLinuxSandboxExecutable)?;
                let allow_proxy_network =
                    crate::linux::allow_network_for_proxy(enforce_managed_network);
                ensure_linux_bubblewrap_is_supported(
                    &effective_fs_policy,
                    use_legacy_landlock,
                    allow_proxy_network,
                    crate::linux::bwrap::is_wsl1(),
                )?;
                let mut args =
                    crate::linux::create_linux_sandbox_command_args_for_permission_profile(
                        os_argv_to_strings(argv),
                        command.cwd.as_path(),
                        &effective,
                        sandbox_policy_cwd,
                        use_legacy_landlock,
                        allow_proxy_network,
                    );
                let mut full_command = Vec::with_capacity(1 + args.len());
                full_command.push(os_string_to_command_component(exe.as_os_str().to_owned()));
                full_command.append(&mut args);
                (full_command, Some(linux_sandbox_arg0_override(exe)))
            }
            #[cfg(not(target_os = "linux"))]
            SandboxType::LinuxSeccomp => {
                let _ = (
                    linux_sandbox_exe,
                    use_legacy_landlock,
                    enforce_managed_network,
                    sandbox_policy_cwd,
                );
                return Err(SandboxTransformError::MissingLinuxSandboxExecutable);
            }

            SandboxType::WindowsRestrictedToken => {
                // Lands with the Windows PR; passthrough for now.
                (os_argv_to_strings(argv), None)
            }
        };

        Ok(SandboxExecRequest {
            command: argv,
            cwd: command.cwd,
            env: command.env,
            network: network.cloned(),
            sandbox,
            windows_sandbox_level,
            windows_sandbox_private_desktop,
            permission_profile: effective,
            file_system_sandbox_policy: effective_fs_policy,
            network_sandbox_policy: effective_net_policy,
            arg0: arg0_override,
        })
    }
}

/// Drive a Windows-built [`SandboxExecRequest`] through the legacy capture
/// orchestrator and return the captured exit code + stdio.
///
/// Available on every target so cross-platform code can call it; on
/// non-Windows the underlying [`crate::windows::run_windows_sandbox_capture`]
/// stub returns an error explaining the platform mismatch.
///
/// `codex_home` is the directory under which capability SIDs and ACL state
/// are persisted (analogous to codex's `~/.codex/.sandbox/`).
impl SandboxManager {
    pub fn run_windows(
        &self,
        request: &SandboxExecRequest,
        codex_home: &Path,
    ) -> anyhow::Result<crate::windows::CaptureResult> {
        let policy_json =
            serde_json::to_string(&crate::compatibility_sandbox_policy_for_permission_profile(
                &request.permission_profile,
                &request.file_system_sandbox_policy,
                request.network_sandbox_policy,
                request.cwd.as_path(),
            ))?;
        crate::windows::run_windows_sandbox_capture(
            &policy_json,
            request.cwd.as_path(),
            codex_home,
            request.command.clone(),
            request.cwd.as_path(),
            request.env.clone(),
            /*timeout_ms*/ None,
            request.windows_sandbox_private_desktop,
        )
    }
}

fn os_argv_to_strings(argv: Vec<OsString>) -> Vec<String> {
    argv.into_iter()
        .map(os_string_to_command_component)
        .collect()
}

fn os_string_to_command_component(value: OsString) -> String {
    value
        .into_string()
        .unwrap_or_else(|value| value.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn linux_sandbox_arg0_override(exe: &Path) -> String {
    if exe.file_name().and_then(|name| name.to_str())
        == Some(crate::linux::RATTLER_LINUX_SANDBOX_ARG0)
    {
        os_string_to_command_component(exe.as_os_str().to_owned())
    } else {
        crate::linux::RATTLER_LINUX_SANDBOX_ARG0.to_string()
    }
}

#[cfg(target_os = "linux")]
fn ensure_linux_bubblewrap_is_supported(
    file_system_sandbox_policy: &FileSystemSandboxPolicy,
    use_legacy_landlock: bool,
    allow_network_for_proxy: bool,
    is_wsl1: bool,
) -> Result<(), SandboxTransformError> {
    let requires_bubblewrap = !use_legacy_landlock
        && (!file_system_sandbox_policy.has_full_disk_write_access() || allow_network_for_proxy);
    if is_wsl1 && requires_bubblewrap {
        return Err(SandboxTransformError::Wsl1UnsupportedForBubblewrap);
    }
    Ok(())
}

/// Build a legacy [`SandboxPolicy`] from a [`PermissionProfile`], falling back
/// to a workspace-write derivation when the profile does not fit the legacy
/// shape.
pub fn compatibility_sandbox_policy_for_permission_profile(
    permissions: &PermissionProfile,
    file_system_policy: &FileSystemSandboxPolicy,
    network_policy: NetworkSandboxPolicy,
    cwd: &Path,
) -> SandboxPolicy {
    permissions
        .to_legacy_sandbox_policy(cwd)
        .unwrap_or_else(|_| {
            compatibility_workspace_write_policy(file_system_policy, network_policy, cwd)
        })
}

fn compatibility_workspace_write_policy(
    file_system_policy: &FileSystemSandboxPolicy,
    network_policy: NetworkSandboxPolicy,
    cwd: &Path,
) -> SandboxPolicy {
    let cwd_abs = AbsolutePathBuf::from_absolute_path(cwd).ok();
    let writable_roots = file_system_policy
        .get_writable_roots_with_cwd(cwd)
        .into_iter()
        .map(|root| root.root)
        .filter(|root| cwd_abs.as_ref() != Some(root))
        .collect();
    let tmpdir_writable = std::env::var_os("TMPDIR")
        .filter(|t| !t.is_empty())
        .and_then(|t| AbsolutePathBuf::from_absolute_path(std::path::PathBuf::from(t)).ok())
        .is_some_and(|t| file_system_policy.can_write_path_with_cwd(t.as_path(), cwd));
    let slash_tmp = Path::new("/tmp");
    let slash_tmp_writable = slash_tmp.is_absolute()
        && slash_tmp.is_dir()
        && file_system_policy.can_write_path_with_cwd(slash_tmp, cwd);

    SandboxPolicy::WorkspaceWrite {
        writable_roots,
        network_access: network_policy.is_enabled(),
        exclude_tmpdir_env_var: !tmpdir_writable,
        exclude_slash_tmp: !slash_tmp_writable,
    }
}
