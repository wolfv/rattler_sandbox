//! Elevated Windows command runner (the IPC peer the sandbox library spawns).
//! Windows-only.

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    rattler_sandbox::windows::bins::command_runner_main()
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("rattler-command-runner is Windows-only");
    std::process::exit(2);
}
