//! The diagnostics engine is responsible for providing code health information.

use crate::engine::command::{
    extract_cargo_warnings, new_cargo_command, run_with_timeout, stderr_preview,
};
use crate::engine::server::ProjectProgress;
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info};

const CHECK_TIMEOUT: Duration = Duration::from_mins(5);
const OUTDATED_TIMEOUT: Duration = Duration::from_mins(2);
const AUDIT_TIMEOUT: Duration = Duration::from_mins(2);

fn parse_compiler_message_line(line: &str) -> Option<Value> {
    let json_value = serde_json::from_str::<Value>(line).ok()?;
    (json_value.get("reason").and_then(|r| r.as_str()) == Some("compiler-message"))
        .then_some(json_value)
}

/// Summarize raw `cargo check` diagnostics into compact objects.
///
/// Each raw diagnostic is a deeply nested rustc JSON blob (~40+ fields).
/// This extracts only what an LLM or human needs to act on:
/// `{ level, message, code, file, line, suggestion }`.
pub fn summarize_diagnostics(raw: &[Value]) -> Vec<Value> {
    raw.iter().filter_map(summarize_one).collect()
}

fn summarize_one(diag: &Value) -> Option<Value> {
    let msg = diag.get("message")?;

    let level = msg.get("level")?.as_str()?;
    let message = msg.get("message")?.as_str()?;

    // Find the primary span for file location
    let primary_span = msg
        .get("spans")
        .and_then(|s| s.as_array())
        .and_then(|spans| {
            spans
                .iter()
                .find(|s| s.get("is_primary") == Some(&Value::Bool(true)))
        });

    let file = primary_span
        .and_then(|s| s.get("file_name"))
        .and_then(|v| v.as_str());
    let line = primary_span
        .and_then(|s| s.get("line_start"))
        .and_then(|v| v.as_u64());

    // Lint/error code (e.g. "unused_variables")
    let code = msg
        .get("code")
        .and_then(|c| c.get("code"))
        .and_then(|v| v.as_str());

    // Look for a help child with a suggested replacement
    let suggestion = msg
        .get("children")
        .and_then(|c| c.as_array())
        .and_then(|children| {
            children.iter().find_map(|child| {
                if child.get("level").and_then(|l| l.as_str()) == Some("help") {
                    child.get("message").and_then(|m| m.as_str())
                } else {
                    None
                }
            })
        });

    let mut summary = serde_json::json!({
        "level": level,
        "message": message,
    });
    let obj = summary.as_object_mut().unwrap();
    if let Some(code) = code {
        obj.insert("code".into(), Value::String(code.into()));
    }
    if let Some(file) = file {
        obj.insert("file".into(), Value::String(file.into()));
    }
    if let Some(line) = line {
        obj.insert("line".into(), Value::Number(line.into()));
    }
    if let Some(suggestion) = suggestion {
        obj.insert("suggestion".into(), Value::String(suggestion.into()));
    }

    Some(summary)
}

/// Summarize raw `cargo audit --json` output into compact advisory objects.
///
/// Extracts per-advisory: id, title, severity, crate_name, installed_version, patched_versions.
/// Deduplicates by advisory ID.
pub fn summarize_audit(raw: &Value) -> Vec<Value> {
    let Some(vulnerabilities) = raw.get("vulnerabilities") else {
        // If it's an error object or null, return empty
        return Vec::new();
    };
    let Some(list) = vulnerabilities.get("list").and_then(|l| l.as_array()) else {
        return Vec::new();
    };

    let mut seen_ids = std::collections::HashSet::new();
    let mut results = Vec::new();

    for entry in list {
        let advisory = match entry.get("advisory") {
            Some(a) => a,
            None => continue,
        };
        let id = advisory
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        // Deduplicate by advisory ID
        if !seen_ids.insert(id.to_string()) {
            continue;
        }

        let title = advisory
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let severity = advisory
            .get("cvss")
            .and_then(|c| c.as_str())
            .or_else(|| advisory.get("severity").and_then(|s| s.as_str()));

        let crate_name = entry
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let installed_version = entry
            .get("package")
            .and_then(|p| p.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let patched_versions = advisory
            .get("patched_versions")
            .cloned()
            .unwrap_or(Value::Null);

        let mut summary = serde_json::json!({
            "id": id,
            "title": title,
            "crate": crate_name,
            "installed_version": installed_version,
            "patched_versions": patched_versions,
        });
        if let Some(sev) = severity {
            summary
                .as_object_mut()
                .unwrap()
                .insert("severity".into(), Value::String(sev.to_string()));
        }
        results.push(summary);
    }

    results
}

/// Summarize raw `cargo outdated --format json` output into compact objects.
///
/// Extracts per-dep: name, current version, latest version, kind.
pub fn summarize_outdated(raw: &Value) -> Vec<Value> {
    let Some(deps) = raw.get("dependencies").and_then(|d| d.as_array()) else {
        // If it's an error object or null, return empty
        return Vec::new();
    };

    deps.iter()
        .map(|dep| {
            serde_json::json!({
                "name": dep.get("name").and_then(|v| v.as_str()).unwrap_or_default(),
                "current": dep.get("project").and_then(|v| v.as_str()).unwrap_or_default(),
                "latest": dep.get("latest").and_then(|v| v.as_str()).unwrap_or_default(),
                "kind": dep.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown"),
            })
        })
        .collect()
}

/// Runs `cargo check` in the background and continuously updates the diagnostics cache.
pub async fn run_check_on_startup(
    diagnostics_cache: Arc<Mutex<Vec<Value>>>,
    project_path: &Path,
    progress: Arc<Mutex<ProjectProgress>>,
) {
    info!("Running initial `cargo check`...");

    let mut cmd = new_cargo_command(project_path);
    cmd.arg("check").arg("--message-format=json");

    let output = match run_with_timeout(&mut cmd, CHECK_TIMEOUT, "`cargo check`").await {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to execute `cargo check`: {}", e);
            let mut cache = diagnostics_cache.lock().await;
            cache.clear();
            cache.push(serde_json::json!({
                "reason": "cargo-check-error",
                "message": e.to_string(),
            }));
            return;
        }
    };
    let cargo_warnings = extract_cargo_warnings(&output.stderr, "cargo check");
    if !cargo_warnings.is_empty() {
        progress.lock().await.merge_cargo_warnings(cargo_warnings);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut cache = diagnostics_cache.lock().await;
    *cache = stdout
        .lines()
        .filter_map(parse_compiler_message_line)
        .collect();
    info!(
        "Initial `cargo check` complete. Found {} diagnostics.",
        cache.len()
    );
}

/// Runs `cargo outdated` in the background and updates the cache.
pub async fn run_outdated_on_startup(
    outdated_cache: Arc<Mutex<Value>>,
    project_path: &Path,
    progress: Arc<Mutex<ProjectProgress>>,
) {
    info!("Running `cargo outdated`...");

    let mut cmd = new_cargo_command(project_path);
    cmd.arg("outdated").arg("--format").arg("json");

    let output = match run_with_timeout(&mut cmd, OUTDATED_TIMEOUT, "`cargo outdated`").await {
        Ok(output) => output,
        Err(e) => {
            error!(
                "Failed to execute `cargo outdated`: {}. Is `cargo-outdated` installed (`cargo install cargo-outdated`)?",
                e
            );
            let mut cache = outdated_cache.lock().await;
            *cache = serde_json::json!({
                "error": e.to_string(),
            });
            return;
        }
    };
    let cargo_warnings = extract_cargo_warnings(&output.stderr, "cargo outdated");
    if !cargo_warnings.is_empty() {
        progress.lock().await.merge_cargo_warnings(cargo_warnings);
    }

    if !output.status.success() {
        let err = stderr_preview(&output.stderr, 10);
        error!("`cargo outdated` command failed: {}", err);
        let mut cache = outdated_cache.lock().await;
        *cache = serde_json::json!({
            "error": err,
        });
        return;
    }

    let json_value = match serde_json::from_slice::<Value>(&output.stdout) {
        Ok(value) => value,
        Err(e) => {
            error!("Failed to parse `cargo outdated` JSON output: {}", e);
            let mut cache = outdated_cache.lock().await;
            *cache = serde_json::json!({
                "error": e.to_string(),
            });
            return;
        }
    };

    let mut cache = outdated_cache.lock().await;
    *cache = json_value;

    info!("`cargo outdated` check complete.");
}

/// Runs `cargo audit` in the background and updates the cache.
pub async fn run_audit_on_startup(
    audit_cache: Arc<Mutex<Value>>,
    project_path: &Path,
    progress: Arc<Mutex<ProjectProgress>>,
) {
    info!("Running `cargo audit`...");

    let mut cmd = new_cargo_command(project_path);
    cmd.arg("audit").arg("--json");

    let output = match run_with_timeout(&mut cmd, AUDIT_TIMEOUT, "`cargo audit`").await {
        Ok(output) => output,
        Err(e) => {
            error!(
                "Failed to execute `cargo audit`: {}. Is `cargo-audit` installed (`cargo install cargo-audit`)?",
                e
            );
            let mut cache = audit_cache.lock().await;
            *cache = serde_json::json!({
                "error": e.to_string(),
            });
            return;
        }
    };
    let cargo_warnings = extract_cargo_warnings(&output.stderr, "cargo audit");
    if !cargo_warnings.is_empty() {
        progress.lock().await.merge_cargo_warnings(cargo_warnings);
    }

    // `cargo audit` exits with a non-zero status code if vulnerabilities are found,
    // so we check for that specifically. We still want to parse the output.
    if !output.status.success() {
        info!(
            "`cargo audit` command exited with a non-zero status, likely indicating vulnerabilities were found."
        );
    }

    let json_bytes = if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    };
    let json_value = match serde_json::from_slice::<Value>(json_bytes) {
        Ok(value) => value,
        Err(e) => {
            error!("Failed to parse `cargo audit` JSON output: {}", e);
            let mut cache = audit_cache.lock().await;
            *cache = serde_json::json!({
                "error": e.to_string(),
            });
            return;
        }
    };

    let mut cache = audit_cache.lock().await;
    *cache = json_value;

    info!("`cargo audit` check complete.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_run_check_on_startup_parses_json() {
        let mock_output = vec![
            json!({"reason": "compiler-message", "message": {"level":"error","message":"error 1","spans":[],"children":[],"code":null,"rendered":""}}),
            json!({"reason": "compiler-message", "message": {"level":"warning","message":"warning 1","spans":[],"children":[],"code":null,"rendered":""}}),
            json!({"reason": "build-finished", "success": true}),
        ];

        let mut parsed = Vec::new();
        for line in mock_output.into_iter().map(|v| v.to_string()) {
            if let Some(msg) = parse_compiler_message_line(&line) {
                parsed.push(msg);
            }
        }

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["message"]["message"], "error 1");
        assert_eq!(parsed[1]["message"]["message"], "warning 1");
    }

    #[test]
    fn summarize_extracts_key_fields() {
        let raw = vec![json!({
            "reason": "compiler-message",
            "message": {
                "level": "warning",
                "message": "unused variable: `x`",
                "code": {"code": "unused_variables", "explanation": null},
                "spans": [{
                    "file_name": "src/main.rs",
                    "line_start": 5,
                    "is_primary": true
                }],
                "children": [{
                    "level": "help",
                    "message": "prefix it with an underscore",
                    "spans": [],
                    "children": [],
                    "code": null,
                    "rendered": null
                }],
                "rendered": "warning: unused variable...\n"
            }
        })];

        let summary = summarize_diagnostics(&raw);
        assert_eq!(summary.len(), 1);
        let s = &summary[0];
        assert_eq!(s["level"], "warning");
        assert_eq!(s["message"], "unused variable: `x`");
        assert_eq!(s["code"], "unused_variables");
        assert_eq!(s["file"], "src/main.rs");
        assert_eq!(s["line"], 5);
        assert_eq!(s["suggestion"], "prefix it with an underscore");
    }
}
