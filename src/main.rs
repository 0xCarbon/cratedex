use anyhow::Result;
use cratedex::cli::{Cli, Commands};
use cratedex::engine;
use cratedex::service;
use clap::Parser;

fn init_simple_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the command-line arguments.
    let cli = Cli::parse();

    // Dispatch to the appropriate command handler.
    match cli.command.unwrap_or(Commands::Server) {
        Commands::Server => {
            // start_server() initializes its own tracing (with log capture layer)
            engine::server::start_server().await?;
        }
        Commands::Setup => {
            init_simple_tracing();
            // Best-effort install of optional tools. Do not fail the command if any step fails.
            let tools = [
                ("cargo-outdated", ["install", "cargo-outdated"].as_slice()),
                ("cargo-audit", ["install", "cargo-audit"].as_slice()),
            ];
            for (name, args) in tools {
                let mut cmd = tokio::process::Command::new("cargo");
                cmd.args(args);
                match cmd.status().await {
                    Ok(status) if status.success() => eprintln!("Installed {name}"),
                    Ok(_) => eprintln!("{name} already installed or failed to install; continuing"),
                    Err(e) => eprintln!("Failed to run cargo to install {name}: {e}"),
                }
            }
        }
        Commands::InstallService {
            host,
            port,
            linger,
            allow_remote,
            system,
            run_as,
        } => {
            init_simple_tracing();
            let scope = if system {
                let run_as = run_as
                    .or_else(|| std::env::var("SUDO_USER").ok())
                    .unwrap_or_else(|| {
                        std::env::var("USER").unwrap_or_else(|_| "root".to_string())
                    });
                service::ServiceInstallScope::System { run_as }
            } else {
                service::ServiceInstallScope::CurrentUser
            };
            service::install_service(&host, port, linger, allow_remote, scope)?;
        }
        Commands::RemoveService { system } => {
            init_simple_tracing();
            let scope = if system {
                // run_as doesn't matter for removal, just need the variant
                service::ServiceInstallScope::System {
                    run_as: String::new(),
                }
            } else {
                service::ServiceInstallScope::CurrentUser
            };
            service::remove_service(scope)?;
        }
    }

    Ok(())
}
