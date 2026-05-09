# rattler_sandbox

A cross-platform sandbox for executing untrusted commands. Derived from
[OpenAI's Codex sandbox](https://github.com/openai/codex), with Codex-specific
dependencies (`codex-protocol`, `codex-network-proxy`'s rama runtime,
`codex-otel`, `codex-utils-*`) stripped out and reduced to a minimal,
self-contained crate.

## Status

Tracking the codex sandbox as of 2026-05. Three-target compile (macOS aarch64,
`x86_64-unknown-linux-gnu`, `x86_64-pc-windows-gnu`); 82 host tests pass on
macOS. Linux and Windows test runs require their respective hosts.

## Backends

| Platform | Mechanism                                                              |
|----------|------------------------------------------------------------------------|
| macOS    | Seatbelt (`/usr/bin/sandbox-exec` with generated `.sbpl` policy)       |
| Linux    | bubblewrap (`bwrap`) + landlock + seccomp via a self-exec helper       |
| Windows  | Restricted token + ACLs + Windows Filtering Platform                   |

On Linux, `bwrap` must be on `PATH` (install via conda-forge:
`pixi global install bubblewrap`). On Windows the elevated path uses two
helper binaries (`rattler-windows-sandbox-setup`, `rattler-command-runner`)
that ship alongside the library.

## Usage

```rust
use rattler_sandbox::{
    AbsolutePathBuf, PermissionProfile, SandboxCommand, SandboxManager,
    SandboxTransformRequest, SandboxablePreference,
};
use std::collections::HashMap;
use std::ffi::OsString;

let cwd = AbsolutePathBuf::current_dir().unwrap();
let perms = PermissionProfile::workspace_write(cwd.as_path());

let mgr = SandboxManager::new();
let sandbox = mgr.select_initial(
    &perms.file_system,
    perms.network,
    SandboxablePreference::Auto,
    rattler_sandbox::WindowsSandboxLevel::Disabled,
    /*has_managed_network_requirements*/ false,
);

let request = SandboxTransformRequest {
    command: SandboxCommand {
        program: OsString::from("/bin/echo"),
        args: vec!["hello".to_string()],
        cwd: cwd.clone(),
        env: HashMap::new(),
        additional_permissions: None,
    },
    permissions: &perms,
    sandbox,
    enforce_managed_network: false,
    network: None,
    sandbox_policy_cwd: cwd.as_path(),
    linux_sandbox_exe: None, // set to your `rattler-sandbox` binary on Linux
    use_legacy_landlock: false,
    windows_sandbox_level: rattler_sandbox::WindowsSandboxLevel::Disabled,
    windows_sandbox_private_desktop: false,
};

let exec_request = mgr.transform(request).unwrap();
// `exec_request.command` is the argv to spawn (sandbox-exec on macOS, the
// linux helper on Linux, the program itself on Windows). Spawn it with
// `std::process::Command` to actually run.
```

## Binaries

| Binary                         | Purpose                                          |
|--------------------------------|--------------------------------------------------|
| `rattler-sandbox`              | CLI; on Linux also acts as the bubblewrap helper |
| `rattler-windows-sandbox-setup`| Elevated Windows setup helper (Windows-only)     |
| `rattler-command-runner`       | Elevated Windows IPC runner (Windows-only)       |

## Architecture

See the crate-level docs (`cargo doc --open`) for a full tour.

- `policy` — `PermissionProfile`, `FileSystemSandboxPolicy`, `NetworkSandboxPolicy`,
  `SandboxPolicy` (legacy enum), `WindowsSandboxLevel`.
- `manager` — `SandboxManager`: builds `SandboxExecRequest`s.
- `seatbelt` (macOS), `linux`, `windows` — engines, gated by `target_os`.
- `pty` — full port of `codex-utils-pty` for interactive sandboxed shells.
- `process_hardening` — `pre_main_hardening` (no-ptrace, no core dumps).

## Crate boundaries with codex

We dropped:

- `codex-network-proxy` — replaced with a 130-line stub holding HTTP/SOCKS
  addresses and env-var injection. The `rama-*` runtime is not ported; ship
  your own proxy server if you need one.
- `codex-otel` — telemetry; replaced with a no-op stub. All metrics calls
  are stubs that return `Ok(())`.
- `codex-protocol` — only the sandbox-relevant types are inlined into
  `policy.rs` (~3.2k lines). Chat / agent / model fields are dropped.
- `schemars`, `ts_rs`, `strum_macros` derives — dropped along with the
  upstream crates that consumed them.

We bundled (top-level modules of this crate):

- `codex-utils-pty` → `crate::pty`
- `codex-process-hardening` → `crate::process_hardening`
- `codex-utils-absolute-path` → `crate::path`
- `codex-utils-string` (only the two helpers consumed by Windows) → inlined
  in `windows::utils_string`

## License

Apache-2.0. See `LICENSE` for the full text and `NOTICE` for upstream
attribution to the codex project.
