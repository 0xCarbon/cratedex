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

/// Return the first `max_lines` lines from stderr for compact logs and errors.
pub fn stderr_preview(stderr: &[u8], max_lines: usize) -> String {
    if max_lines == 0 {
        return String::new();
    }
    let text = String::from_utf8_lossy(stderr);
    text.lines().take(max_lines).collect::<Vec<_>>().join("\n")
}

/// Extract cargo `warning:` and `error:` lines, tagged with the command source.
pub fn extract_cargo_warnings(stderr: &[u8], source: &str) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(stderr);
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("warning:") || trimmed.starts_with("error:") {
                Some((source.to_string(), trimmed.to_string()))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{extract_cargo_warnings, stderr_preview};

    #[test]
    fn stderr_preview_limits_lines() {
        let input = b"line1\nline2\nline3\n";
        assert_eq!(stderr_preview(input, 2), "line1\nline2");
    }

    #[test]
    fn stderr_preview_handles_empty() {
        assert_eq!(stderr_preview(b"", 5), "");
        assert_eq!(stderr_preview(b"line1", 0), "");
    }

    #[test]
    fn extract_cargo_warnings_filters_relevant_lines() {
        let input =
            b"Compiling foo\nwarning: profile ignored\nnote: details\nerror: failed to select\n";
        let warnings = extract_cargo_warnings(input, "cargo test");
        assert_eq!(
            warnings,
            vec![
                (
                    "cargo test".to_string(),
                    "warning: profile ignored".to_string()
                ),
                (
                    "cargo test".to_string(),
                    "error: failed to select".to_string()
                ),
            ]
        );
    }
}
