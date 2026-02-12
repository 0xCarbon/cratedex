//! A helper module for creating `cargo` commands.

use crate::error::AppResult;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Creates a new `Command` for `cargo` using the default (stable) toolchain,
/// running in the given project directory.
pub fn new_cargo_command(project_path: &Path) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(project_path);
    cmd
}

/// Creates a new `Command` for `cargo +nightly`, running in the given project
/// directory. Use this only for operations that require unstable features
/// (e.g. `rustdoc --output-format json`).
pub fn new_nightly_cargo_command(project_path: &Path) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("+nightly");
    cmd.current_dir(project_path);
    cmd
}

/// Spawns a command and waits for completion with a timeout.
///
/// The child is configured with `kill_on_drop`, so timeouts won't leave
/// background cargo processes running.
pub async fn run_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
    context: &str,
) -> AppResult<std::process::Output> {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = cmd.spawn()?;
    let output = tokio::time::timeout(timeout, child.wait_with_output()).await;
    match output {
        Ok(result) => Ok(result?),
        Err(_) => Err(anyhow::anyhow!("{} timed out after {}s", context, timeout.as_secs()).into()),
    }
}
