//! Configuration management for cratedex

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

/// Main configuration structure for the application
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Database configuration
    pub database: DatabaseConfig,

    /// Server configuration
    pub server: ServerConfig,

    /// File watching configuration
    pub watcher: WatcherConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Local path to the SQLite database file.
    ///
    /// Examples:
    /// - `~/.cratedex/cratedex.db`
    /// - `:memory:` (in-memory database)
    #[serde(default = "default_db_path")]
    pub path: PathBuf,

    /// Fixed name for the shared global documentation table.
    #[serde(default = "default_table_name")]
    pub table_name: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Maximum number of search results to return
    #[serde(default = "default_max_results")]
    pub max_search_results: usize,

    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,

    /// Transport protocol: "http" or "stdio"
    #[serde(default = "default_transport")]
    pub transport: Transport,

    /// Host to bind for HTTP(S)
    #[serde(default = "default_host")]
    pub host: String,

    /// Port to bind for HTTP(S)
    #[serde(default = "default_port")]
    pub port: u16,

    /// Allow binding to non-loopback interfaces.
    #[serde(default)]
    pub allow_remote: bool,

    /// Optional bearer token for HTTP authentication.
    ///
    /// When set, clients must send:
    /// `Authorization: Bearer <token>`
    #[serde(default)]
    pub auth_token: Option<String>,

    /// Maximum number of projects that can be registered at once.
    #[serde(default = "default_max_projects")]
    pub max_projects: usize,

    /// Maximum number of concurrent HTTP requests served.
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,

    /// Maximum average HTTP request rate per second.
    #[serde(default = "default_rate_limit_per_sec")]
    pub rate_limit_per_sec: u64,

    /// Maximum accepted HTTP request body size in bytes.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Http,
    Stdio,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WatcherConfig {
    /// Enable file watching for live diagnostics
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Debounce delay in milliseconds
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            table_name: default_table_name(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_search_results: default_max_results(),
            verbose: false,
            transport: default_transport(),
            host: default_host(),
            port: default_port(),
            allow_remote: false,
            auth_token: None,
            max_projects: default_max_projects(),
            max_concurrent_requests: default_max_concurrent_requests(),
            rate_limit_per_sec: default_rate_limit_per_sec(),
            max_request_body_bytes: default_max_request_body_bytes(),
        }
    }
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            debounce_ms: default_debounce_ms(),
        }
    }
}

// Default value functions
fn default_table_name() -> String {
    "docs".to_string()
}

fn default_db_path() -> PathBuf {
    dirs::home_dir()
        .map(|p| p.join(".cratedex").join("cratedex.db"))
        .unwrap_or_else(|| PathBuf::from(".cratedex/cratedex.db"))
}

fn default_max_results() -> usize {
    10
}

fn default_transport() -> Transport {
    Transport::Http
}
fn default_host() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    3737
}

fn default_enabled() -> bool {
    true
}

fn default_debounce_ms() -> u64 {
    300
}

fn default_max_projects() -> usize {
    32
}

fn default_max_concurrent_requests() -> usize {
    64
}

fn default_rate_limit_per_sec() -> u64 {
    30
}

fn default_max_request_body_bytes() -> usize {
    256 * 1024
}

/// Returns `true` if the host string refers to a loopback address.
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl Config {
    /// Load configuration from file and environment variables
    pub fn load() -> Result<Self, config::ConfigError> {
        let mut builder = config::Config::builder()
            // Start with default values
            .set_default(
                "database.path",
                default_db_path().to_string_lossy().to_string(),
            )?
            .set_default("database.table_name", default_table_name())?
            .set_default("server.max_search_results", default_max_results() as i64)?
            .set_default("server.verbose", false)?
            .set_default("server.transport", "http")?
            .set_default("server.host", default_host())?
            .set_default("server.port", default_port() as i64)?
            .set_default("server.allow_remote", false)?
            .set_default("server.max_projects", default_max_projects() as i64)?
            .set_default(
                "server.max_concurrent_requests",
                default_max_concurrent_requests() as i64,
            )?
            .set_default(
                "server.rate_limit_per_sec",
                default_rate_limit_per_sec() as i64,
            )?
            .set_default(
                "server.max_request_body_bytes",
                default_max_request_body_bytes() as i64,
            )?
            .set_default("watcher.enabled", default_enabled())?
            .set_default("watcher.debounce_ms", default_debounce_ms() as i64)?;

        // Try to load from cratedex.toml in the current directory
        if std::path::Path::new("cratedex.toml").exists() {
            builder = builder.add_source(config::File::with_name("cratedex"));
        }

        // Try to load from ~/.cratedex/cratedex.toml
        if let Some(home_dir) = dirs::home_dir() {
            let config_path = home_dir.join(".cratedex").join("cratedex.toml");
            if config_path.exists() {
                builder = builder.add_source(config::File::from(config_path));
            }
        }

        // Override with environment variables (e.g. CRATEDEX__SERVER__TRANSPORT=http)
        builder = builder.add_source(
            config::Environment::with_prefix("CRATEDEX")
                .prefix_separator("__")
                .separator("__")
                .try_parsing(true),
        );

        let settings = builder.build()?;
        settings.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let cfg = Config::default();
        assert_eq!(cfg.database.table_name, "docs");
        assert!(cfg.database.path.to_string_lossy().contains("cratedex.db"));
        assert_eq!(cfg.server.max_search_results, 10);
        assert_eq!(cfg.server.transport, Transport::Http);
        assert!(!cfg.server.allow_remote);
        assert!(cfg.server.auth_token.is_none());
        assert_eq!(cfg.server.max_projects, 32);
        assert_eq!(cfg.server.max_concurrent_requests, 64);
        assert_eq!(cfg.server.rate_limit_per_sec, 30);
        assert_eq!(cfg.server.max_request_body_bytes, 256 * 1024);
        assert!(cfg.watcher.enabled);
        assert_eq!(cfg.watcher.debounce_ms, 300);
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)]
    fn env_overrides_work() {
        // Environment overrides use prefix CRATEDEX_
        unsafe { std::env::set_var("CRATEDEX__SERVER__MAX_SEARCH_RESULTS", "5") };
        unsafe { std::env::set_var("CRATEDEX__DATABASE__TABLE_NAME", "custom_docs") };
        let loaded = Config::load().expect("load config from env");
        assert_eq!(loaded.server.max_search_results, 5);
        assert_eq!(loaded.database.table_name, "custom_docs");
        // Cleanup
        unsafe { std::env::remove_var("CRATEDEX__SERVER__MAX_SEARCH_RESULTS") };
        unsafe { std::env::remove_var("CRATEDEX__DATABASE__TABLE_NAME") };
    }
}
