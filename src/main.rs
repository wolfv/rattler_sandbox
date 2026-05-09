//! `rattler-sandbox` binary.
//!
//! On Linux this is also the helper executable that the [`SandboxManager`]
//! shells out to. Dispatch follows codex's arg0 convention: when argv[0]'s
//! file basename is `RATTLER_LINUX_SANDBOX_ARG0`, the binary switches into
//! helper mode; otherwise it runs as a plain CLI.
//!
//! [`SandboxManager`]: rattler_sandbox::SandboxManager

fn main() {
    #[cfg(target_os = "linux")]
    {
        let argv0 = std::env::args_os().next();
        if let Some(argv0) = argv0
            && std::path::Path::new(&argv0).file_name()
                == Some(std::ffi::OsStr::new(
                    rattler_sandbox::RATTLER_LINUX_SANDBOX_ARG0,
                ))
        {
            rattler_sandbox::linux::run_helper_main();
        }
    }

    eprintln!("rattler-sandbox CLI not yet implemented");
    std::process::exit(2);
}
