//! Linux sandboxing engine.
//!
//! Two layers:
//!   - [`bwrap`] / [`landlock`] — sandboxing-side helpers that the manager
//!     calls when constructing a [`SandboxExecRequest`].
//!   - The helper-binary internals (`bwrap_runner`, `landlock_runner`,
//!     `launcher`, `proxy_routing`, `exec_util`, `run_main`) — invoked when
//!     `rattler-sandbox` is exec'd with `argv[0]` ==
//!     [`RATTLER_LINUX_SANDBOX_ARG0`].
//!
//! [`SandboxExecRequest`]: crate::SandboxExecRequest

pub mod bwrap;
pub mod landlock;

mod bwrap_runner;
mod exec_util;
mod landlock_runner;
mod launcher;
mod proxy_routing;
mod run_main;

pub use bwrap::{find_system_bwrap_in_path, system_bwrap_warning};
pub use landlock::{
    RATTLER_LINUX_SANDBOX_ARG0, allow_network_for_proxy,
    create_linux_sandbox_command_args_for_permission_profile,
};

/// Entry point for the Linux helper binary. When the rattler-sandbox executable
/// detects it has been invoked under [`RATTLER_LINUX_SANDBOX_ARG0`], it calls
/// this and never returns.
pub fn run_helper_main() -> ! {
    run_main::run_main();
}
