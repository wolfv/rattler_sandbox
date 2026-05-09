//! Minimal [`NetworkProxy`] used to inject proxy environment variables into
//! sandboxed child processes.
//!
//! The codex variant runs a full HTTP+SOCKS5 proxy server backed by `rama-*`
//! crates. We strip that runtime and keep only the sandbox-side concerns:
//!
//!   - the addresses children should be pointed at (via env vars)
//!   - whether children may bind locally
//!   - whether all Unix sockets should be allowed through
//!
//! Callers that want a real proxy server can construct their own and wrap
//! the resulting addresses with [`NetworkProxy::new`].

use std::collections::HashMap;
use std::net::SocketAddr;

/// Environment variable keys overwritten when proxy injection is enabled.
pub const PROXY_URL_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "WS_PROXY",
    "WSS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
];

/// Look up `canonical_key` in `env`, falling back to its lowercased twin.
pub fn proxy_url_env_value<'a>(
    env: &'a HashMap<String, String>,
    canonical_key: &str,
) -> Option<&'a str> {
    if let Some(value) = env.get(canonical_key) {
        return Some(value.as_str());
    }
    let lower = canonical_key.to_ascii_lowercase();
    env.get(lower.as_str()).map(String::as_str)
}

/// Returns `true` if any of the proxy URL env keys are set to a non-empty value.
pub fn has_proxy_url_env_vars(env: &HashMap<String, String>) -> bool {
    PROXY_URL_ENV_KEYS
        .iter()
        .any(|key| proxy_url_env_value(env, key).is_some_and(|v| !v.trim().is_empty()))
}

pub const PROXY_ACTIVE_ENV_KEY: &str = "RATTLER_NETWORK_PROXY_ACTIVE";
pub const ALLOW_LOCAL_BINDING_ENV_KEY: &str = "RATTLER_NETWORK_ALLOW_LOCAL_BINDING";

pub const DEFAULT_NO_PROXY_VALUE: &str = concat!(
    "localhost,127.0.0.1,::1,",
    "10.0.0.0/8,",
    "172.16.0.0/12,",
    "192.168.0.0/16"
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkProxy {
    http_addr: SocketAddr,
    socks_addr: SocketAddr,
    socks_enabled: bool,
    allow_local_binding: bool,
    dangerously_allow_all_unix_sockets: bool,
    allow_unix_sockets: Vec<String>,
}

impl NetworkProxy {
    /// Construct a [`NetworkProxy`] given the addresses children should be
    /// directed at.
    pub fn new(http_addr: SocketAddr, socks_addr: SocketAddr) -> Self {
        Self {
            http_addr,
            socks_addr,
            socks_enabled: true,
            allow_local_binding: false,
            dangerously_allow_all_unix_sockets: false,
            allow_unix_sockets: Vec::new(),
        }
    }

    pub fn with_socks_enabled(mut self, enabled: bool) -> Self {
        self.socks_enabled = enabled;
        self
    }

    pub fn with_allow_local_binding(mut self, allow: bool) -> Self {
        self.allow_local_binding = allow;
        self
    }

    pub fn with_dangerously_allow_all_unix_sockets(mut self, allow: bool) -> Self {
        self.dangerously_allow_all_unix_sockets = allow;
        self
    }

    pub fn with_allow_unix_sockets(mut self, sockets: Vec<String>) -> Self {
        self.allow_unix_sockets = sockets;
        self
    }

    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    pub fn socks_enabled(&self) -> bool {
        self.socks_enabled
    }

    pub fn allow_local_binding(&self) -> bool {
        self.allow_local_binding
    }

    pub fn allow_unix_sockets(&self) -> &[String] {
        &self.allow_unix_sockets
    }

    pub fn dangerously_allow_all_unix_sockets(&self) -> bool {
        self.dangerously_allow_all_unix_sockets
    }

    /// Inject proxy settings as environment variables into `env`. Existing
    /// entries are overwritten so command-level env cannot bypass the proxy.
    pub fn apply_to_env(&self, env: &mut HashMap<String, String>) {
        let http_url = format!("http://{}", self.http_addr);
        let socks_url = format!("socks5://{}", self.socks_addr);
        let all_proxy = if self.socks_enabled {
            socks_url.clone()
        } else {
            http_url.clone()
        };

        env.insert("HTTP_PROXY".into(), http_url.clone());
        env.insert("HTTPS_PROXY".into(), http_url.clone());
        env.insert("http_proxy".into(), http_url.clone());
        env.insert("https_proxy".into(), http_url);
        env.insert("ALL_PROXY".into(), all_proxy.clone());
        env.insert("all_proxy".into(), all_proxy);
        env.insert(PROXY_ACTIVE_ENV_KEY.into(), "1".into());
        if self.allow_local_binding {
            env.insert(ALLOW_LOCAL_BINDING_ENV_KEY.into(), "1".into());
        }
        if env.get("NO_PROXY").is_none() && env.get("no_proxy").is_none() {
            env.insert("NO_PROXY".into(), DEFAULT_NO_PROXY_VALUE.into());
            env.insert("no_proxy".into(), DEFAULT_NO_PROXY_VALUE.into());
        }
    }
}
