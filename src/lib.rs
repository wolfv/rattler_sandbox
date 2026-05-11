//! Cross-platform sandbox for executing untrusted commands.
//!
//! Derived from OpenAI's Codex sandbox. See `NOTICE` for upstream attribution.
//!
//! # Quick orientation
//!
//! A typical caller pipeline:
//!
//! 1. Build a [`PermissionProfile`] (or use [`PermissionProfile::workspace_write`]
//!    / [`PermissionProfile::read_only`] / [`PermissionProfile::unrestricted`]).
//! 2. Construct a [`SandboxCommand`] for the program + args + cwd + env.
//! 3. Wrap them in a [`SandboxTransformRequest`] and call
//!    [`SandboxManager::transform`]. The manager picks the right engine based
//!    on `target_os` and returns a [`SandboxExecRequest`] holding the actual
//!    argv that should be spawned.
//! 4. Spawn the returned argv with [`std::process::Command`] (or your
//!    favourite spawner). The first element is the engine entry point
//!    (e.g. `/usr/bin/sandbox-exec`, the `rattler-sandbox` linux helper, or
//!    the original program for Windows).
//!
//! On Windows the alternative is to skip step 4 and let
//! [`SandboxManager::run_windows`] drive the legacy capture orchestrator
//! directly — it spawns the child, waits, and returns a [`windows::CaptureResult`].
//!
//! # Architecture
//!
//! ```text
//!                  ┌─────────────────────┐
//!                  │   PermissionProfile │
//!                  └──────────┬──────────┘
//!                             │ to_runtime_permissions / overrides
//!                             ▼
//!                  ┌─────────────────────┐
//!                  │   policy_transforms │
//!                  └──────────┬──────────┘
//!                             │ runtime policies
//!                             ▼
//!                  ┌─────────────────────┐
//!  SandboxCommand ─┤   SandboxManager    ├─► SandboxExecRequest
//!                  └──────────┬──────────┘
//!                             │  dispatch on target_os
//!         ┌───────────────────┼───────────────────┐
//!         ▼                   ▼                   ▼
//! ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐
//! │   seatbelt   │  │      linux       │  │     windows      │
//! │ (sandbox-exec│  │ (bwrap+landlock+ │  │ (restricted token│
//! │   on macOS)  │  │  seccomp helper) │  │  + ACL + WFP)    │
//! └──────────────┘  └──────────────────┘  └──────────────────┘
//! ```
//!
//! # Modules
//!
//! Crate-public API:
//!
//! - [`policy`] — policy types: [`PermissionProfile`], [`FileSystemSandboxPolicy`],
//!   [`NetworkSandboxPolicy`], [`SandboxPolicy`] (legacy), [`WindowsSandboxLevel`].
//! - [`policy_transforms`] — resolve a base profile + per-call overrides into
//!   the runtime policies the engines consume.
//! - [`manager`] — [`SandboxManager`] dispatcher and request types.
//! - [`error`] — [`SandboxError`] plus codex-shaped [`error::CodexErr`] /
//!   [`error::SandboxErr`] used by Linux helper internals.
//! - [`path`] — [`AbsolutePathBuf`] guarantee + symlink-preserving canonicalize.
//! - [`network_proxy`] — minimal [`NetworkProxy`] holding addresses + env-var
//!   injection (the codex `rama-*` runtime is intentionally stripped).
//! - [`process_hardening`] — `pre_main_hardening` + Linux ptrace/dump controls.
//! - [`pty`] — `codex-utils-pty` ported in full: pipe/PTY spawning,
//!   `SpawnedProcess`, ConPTY backend on Windows.
//!
//! Engine modules (gated by target_os):
//!
//! - `seatbelt` (macOS) — Seatbelt policy generation; calls `/usr/bin/sandbox-exec`.
//! - `linux` — bubblewrap + landlock + seccomp; the `rattler-sandbox` binary
//!   doubles as the helper executor when invoked under
//!   `linux::RATTLER_LINUX_SANDBOX_ARG0`.
//! - [`windows`] — restricted token + ACL + WFP. Two `[[bin]]` helpers
//!   (`rattler-windows-sandbox-setup`, `rattler-command-runner`) implement
//!   the elevated setup flow and the IPC-driven runner.
//!
//! # Binaries
//!
//! - `rattler-sandbox` — CLI; on Linux also serves as the bubblewrap helper.
//! - `rattler-windows-sandbox-setup` — Windows-only elevated setup helper.
//! - `rattler-command-runner` — Windows-only elevated runner (IPC peer).

pub mod error;
pub mod manager;
pub mod network_proxy;
pub mod path;
pub mod policy;
pub mod policy_transforms;
pub mod process_hardening;
pub mod pty;

#[cfg(target_os = "macos")]
pub mod seatbelt;

#[cfg(target_os = "linux")]
pub mod linux;

/// Windows engine — the public API gates internals behind `target_os = "windows"`
/// but is compiled unconditionally so callers can refer to types and functions
/// (with non-Windows stubs that bail at runtime).
pub mod windows;

pub use error::SandboxError;
pub use manager::{
    SandboxCommand, SandboxExecRequest, SandboxManager, SandboxTransformError,
    SandboxTransformRequest, SandboxType, SandboxablePreference,
    compatibility_sandbox_policy_for_permission_profile, get_platform_sandbox,
};
pub use network_proxy::NetworkProxy;
pub use path::AbsolutePathBuf;
pub use policy::{
    AdditionalPermissionProfile, FileSystemAccessMode, FileSystemPath, FileSystemSandboxEntry,
    FileSystemSandboxKind, FileSystemSandboxPolicy, FileSystemSpecialPath, NetworkSandboxPolicy,
    PermissionProfile, ReadDenyMatcher, SandboxPolicy, WindowsSandboxLevel,
};

/// arg0 sentinel: the basename used when `rattler-sandbox` self-invokes as the
/// Linux sandbox helper. On Linux, [`SandboxManager::transform`] sets argv[0]
/// to this so the helper's `main` can dispatch on it.
#[cfg(target_os = "linux")]
pub use linux::RATTLER_LINUX_SANDBOX_ARG0;

/// Returns a warning string if the system bubblewrap is missing, broken, or
/// the host is WSL1. Non-Linux platforms always return [`None`].
#[cfg(target_os = "linux")]
pub fn system_bwrap_warning(permissions: &PermissionProfile) -> Option<String> {
    linux::system_bwrap_warning(permissions)
}

/// Returns a warning string if the system bubblewrap is missing, broken, or
/// the host is WSL1. Non-Linux platforms always return [`None`].
#[cfg(not(target_os = "linux"))]
pub fn system_bwrap_warning(_permissions: &PermissionProfile) -> Option<String> {
    None
}
