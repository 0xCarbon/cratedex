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
    /// Install cratedex as a systemd service (HTTP transport).
    InstallService {
        /// HTTP bind address.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// HTTP bind port.
        #[arg(long, default_value_t = 3737)]
        port: u16,
        /// Enable loginctl linger so the service survives logout.
        #[arg(long, conflicts_with = "system")]
        linger: bool,
        /// Allow binding to non-loopback addresses (only enable behind TLS+auth reverse proxy).
        #[arg(long)]
        allow_remote: bool,
        /// Install as a system-level service (writes to /etc/systemd/system,
        /// managed with plain `systemctl`). Requires root.
        #[arg(long, conflicts_with = "linger")]
        system: bool,
        /// User account the system service runs as (default: $SUDO_USER or current user).
        #[arg(long, default_value = None, requires = "system")]
        run_as: Option<String>,
    },
    /// Remove the cratedex systemd service.
    RemoveService {
        /// Remove the system-level service (from /etc/systemd/system). Requires root.
        #[arg(long)]
        system: bool,
    },
}
