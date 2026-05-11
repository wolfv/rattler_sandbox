//! Resolve a [`PermissionProfile`] (plus optional per-call overrides) into the
//! runtime policies the sandbox engines consume.
//!
//! Stub during PR 1; full port lands in PR 1 follow-up.

use std::path::Path;

use crate::policy::{
    AdditionalPermissionProfile, FileSystemSandboxPolicy, NetworkSandboxPolicy, PermissionProfile,
    SandboxPolicy,
};

/// Apply the optional [`AdditionalPermissionProfile`] overrides on top of a base
/// [`PermissionProfile`].
pub fn effective_permission_profile(
    base: &PermissionProfile,
    overrides: Option<&AdditionalPermissionProfile>,
) -> PermissionProfile {
    let mut out = base.clone();
    if let Some(o) = overrides {
        if let Some(fs) = o.file_system.clone() {
            out.file_system = fs;
        }
        if let Some(n) = o.network {
            out.network = n;
        }
    }
    out
}

/// Whether the platform sandbox should be required for the given runtime
/// policies. Currently a permissive heuristic: anything more restrictive than
/// "unrestricted FS + enabled network" requires platform isolation.
pub fn should_require_platform_sandbox(
    file_system_policy: &FileSystemSandboxPolicy,
    network_policy: NetworkSandboxPolicy,
    has_managed_network_requirements: bool,
) -> bool {
    if has_managed_network_requirements {
        return true;
    }
    !file_system_policy.has_full_disk_write_access() || !network_policy.is_enabled()
}

/// Best-effort mapping from a [`PermissionProfile`] back to a legacy
/// [`SandboxPolicy`] enum.
pub(crate) fn permission_profile_to_legacy_sandbox_policy(
    profile: &PermissionProfile,
    cwd: &Path,
) -> Result<SandboxPolicy, String> {
    let net = profile.network.is_enabled();
    if profile.file_system.has_full_disk_write_access() {
        return Ok(if net {
            SandboxPolicy::DangerFullAccess
        } else {
            // ExternalSandbox preserves "trust the outer sandbox" semantics.
            SandboxPolicy::ExternalSandbox {
                network_access: crate::policy::NetworkAccess::Restricted,
            }
        });
    }
    // Treat policies that grant no writable roots as read-only.
    if profile
        .file_system
        .get_writable_roots_with_cwd(cwd)
        .is_empty()
    {
        return Ok(SandboxPolicy::ReadOnly {
            network_access: net,
        });
    }
    // Workspace-write fallback. Writable roots come from the policy's own
    // resolved entries.
    let writable_roots = profile
        .file_system
        .get_writable_roots_with_cwd(cwd)
        .into_iter()
        .map(|r| r.root)
        .collect();
    Ok(SandboxPolicy::WorkspaceWrite {
        writable_roots,
        network_access: net,
        exclude_tmpdir_env_var: false,
        exclude_slash_tmp: false,
    })
}
