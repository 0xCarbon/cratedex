//! Defines the command-line interface for Cratedex.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "A Model Context Protocol Server for the Rust Cargo toolchain.",
    subcommand_required = false,
    arg_required_else_help = false,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Starts the Cratedex server.
    Server,
    /// Installs optional prerequisites like cargo-outdated and cargo-audit.
    Setup,
    /// Update cratedex to the latest published version and refresh installed services.
    Update {
        /// Refresh only the system-level service (Linux/macOS). Defaults to auto-detecting installed services.
        #[arg(long)]
        system: bool,
    },
    /// Install cratedex as a background service (HTTP transport).
    InstallService {
        /// HTTP bind address.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// HTTP bind port.
        #[arg(long, default_value_t = 3737)]
        port: u16,
        /// Enable loginctl linger so the service survives logout (Linux only).
        #[arg(long, conflicts_with = "system")]
        linger: bool,
        /// Allow binding to non-loopback addresses (only enable behind TLS+auth reverse proxy).
        #[arg(long)]
        allow_remote: bool,
        /// Install as a system-level service. Linux uses systemd; macOS uses launchd.
        /// On Windows this currently returns a runtime error.
        #[arg(long, conflicts_with = "linger")]
        system: bool,
        /// User account the system service runs as (Linux/macOS, requires --system).
        #[arg(long, default_value = None, requires = "system")]
        run_as: Option<String>,
    },
    /// Remove the cratedex background service.
    RemoveService {
        /// Remove the system-level service. Linux/macOS require root.
        #[arg(long)]
        system: bool,
    },
}
