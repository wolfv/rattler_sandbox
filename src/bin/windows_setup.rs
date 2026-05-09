//! Elevated Windows sandbox setup helper. Windows-only.

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    rattler_sandbox::windows::bins::setup_main()
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("rattler-windows-sandbox-setup is Windows-only");
    std::process::exit(2);
}
