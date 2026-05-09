//! Error types for the sandbox.

use std::path::PathBuf;

/// Top-level error type returned by the public sandbox API.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error(transparent)]
    Transform(#[from] crate::manager::SandboxTransformError),

    #[error("path is not absolute: {0}")]
    NotAbsolutePath(PathBuf),

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Codex-shaped errors used by the Linux helper internals.
//
// The Linux helper port uses CodexErr / SandboxErr / Result widely. Rather
// than rewrite every call site we reproduce those names here. They are not
// re-exported from the public crate root.
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CodexErr {
    #[error("fatal: {0}")]
    Fatal(String),

    #[error(transparent)]
    Sandbox(#[from] SandboxErr),

    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("nul byte in argv: {0}")]
    Nul(#[from] std::ffi::NulError),

    #[cfg(target_os = "linux")]
    #[error("landlock ruleset error: {0}")]
    LandlockRuleset(#[from] landlock::RulesetError),

    #[cfg(target_os = "linux")]
    #[error("landlock path-fd error: {0}")]
    LandlockPathFd(#[from] landlock::PathFdError),
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxErr {
    #[error("landlock restrict failed")]
    LandlockRestrict,

    #[cfg(target_os = "linux")]
    #[error("seccomp setup error")]
    SeccompInstall(#[from] seccompiler::Error),

    #[cfg(target_os = "linux")]
    #[error("seccomp backend error")]
    SeccompBackend(#[from] seccompiler::BackendError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type CodexResult<T> = std::result::Result<T, CodexErr>;
