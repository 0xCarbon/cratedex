//! The diagnostics engine is responsible for providing code health information.

use crate::engine::command::{
    extract_cargo_warnings, new_cargo_command, run_with_timeout, stderr_preview,
};
use crate::engine::server::{ProjectProgress, tool_error_payload};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info};

const CHECK_TIMEOUT: Duration = Duration::from_mins(5);
const OUTDATED_TIMEOUT: Duration = Duration::from_mins(2);
const AUDIT_TIMEOUT: Duration = Duration::from_mins(2);

fn command_error(
    code: &str,
    message: &str,
    stage: &str,
    retryable: bool,
    hints: &[&str],
    raw: Option<&str>,
) -> Value {
    tool_error_payload(code, message, stage, retryable, hints, None, raw)
}

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
    let obj = summary
        .as_object_mut()
        .expect("json! macro always produces an object");
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

    let mut groups: BTreeMap<String, (Value, HashSet<String>)> = BTreeMap::new();

    for entry in list {
        let advisory = match entry.get("advisory") {
            Some(a) => a,
            None => continue,
        };
        let id = advisory
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

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

        let (summary, seen_packages) = groups.entry(id.to_string()).or_insert_with(|| {
            let mut base = serde_json::json!({
                "id": id,
                "title": title,
                "patched_versions": patched_versions,
                "affected_packages": [],
            });
            if let Some(sev) = severity
                && let Some(obj) = base.as_object_mut()
            {
                obj.insert("severity".into(), Value::String(sev.to_string()));
            }
            (base, HashSet::new())
        });

        let package_key = format!("{crate_name}@{installed_version}");
        if seen_packages.insert(package_key)
            && let Some(arr) = summary
                .get_mut("affected_packages")
                .and_then(|v| v.as_array_mut())
        {
            arr.push(serde_json::json!({
                "crate": crate_name,
                "installed_version": installed_version,
            }));
        }
    }

    let mut results = Vec::with_capacity(groups.len());
    for (_, (mut summary, _)) in groups {
        let affected_count = summary
            .get("affected_packages")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        summary["affected_count"] = serde_json::json!(affected_count);
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
            let latest = dep
                .get("latest")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let status = if latest == "Removed" {
                "removed"
            } else {
                "outdated"
            };
            serde_json::json!({
                "name": dep.get("name").and_then(|v| v.as_str()).unwrap_or_default(),
                "current": dep.get("project").and_then(|v| v.as_str()).unwrap_or_default(),
                "latest": latest,
                "kind": dep.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "status": status,
            })
        })
        .collect()
}

/// Probe whether `cargo clippy` is available on this system.
async fn is_clippy_available(project_path: &Path) -> bool {
    let mut cmd = new_cargo_command(project_path);
    cmd.arg("clippy").arg("--version");
    match run_with_timeout(&mut cmd, Duration::from_secs(10), "`cargo clippy --version`").await {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Runs `cargo clippy` (or `cargo check` as fallback) in the background and
/// continuously updates the diagnostics cache.
pub async fn run_check_on_startup(
    diagnostics_cache: Arc<Mutex<Vec<Value>>>,
    project_path: &Path,
    progress: Arc<Mutex<ProjectProgress>>,
) {
    let use_clippy = is_clippy_available(project_path).await;
    let tool_name = if use_clippy { "cargo clippy" } else { "cargo check" };
    info!("Running initial `{tool_name}`...");

    let mut cmd = new_cargo_command(project_path);
    if use_clippy {
        cmd.arg("clippy")
            .arg("--all-targets")
            .arg("--message-format=json")
            .arg("--")
            .arg("-W")
            .arg("clippy::all");
    } else {
        cmd.arg("check").arg("--message-format=json");
    }

    let output = match run_with_timeout(&mut cmd, CHECK_TIMEOUT, &format!("`{tool_name}`")).await {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to execute `{tool_name}`: {}", e);
            let mut cache = diagnostics_cache.lock().await;
            cache.clear();
            cache.push(serde_json::json!({
                "reason": "cargo-check-error",
                "message": e.to_string(),
            }));
            return;
        }
    };
    let cargo_warnings = extract_cargo_warnings(&output.stderr, tool_name);
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
        "Initial `{tool_name}` complete. Found {} diagnostics.",
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
                "error": command_error(
                    "OUTDATED_EXEC_FAILED",
                    "failed to execute cargo outdated",
                    "outdated_diagnostics",
                    true,
                    &["Install cargo-outdated: cargo install cargo-outdated"],
                    Some(&e.to_string()),
                ),
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
            "error": command_error(
                "OUTDATED_COMMAND_FAILED",
                "cargo outdated returned a non-zero exit code",
                "outdated_diagnostics",
                true,
                &[],
                Some(&err),
            ),
        });
        return;
    }

    let json_value = match serde_json::from_slice::<Value>(&output.stdout) {
        Ok(value) => value,
        Err(e) => {
            error!("Failed to parse `cargo outdated` JSON output: {}", e);
            let mut cache = outdated_cache.lock().await;
            *cache = serde_json::json!({
                "error": command_error(
                    "OUTDATED_PARSE_FAILED",
                    "failed to parse cargo outdated output",
                    "outdated_diagnostics",
                    true,
                    &["Retry after updating cargo-outdated"],
                    Some(&e.to_string()),
                ),
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
                "error": command_error(
                    "AUDIT_EXEC_FAILED",
                    "failed to execute cargo audit",
                    "security_diagnostics",
                    true,
                    &["Install cargo-audit: cargo install cargo-audit"],
                    Some(&e.to_string()),
                ),
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
                "error": command_error(
                    "AUDIT_PARSE_FAILED",
                    "failed to parse cargo audit output",
                    "security_diagnostics",
                    true,
                    &[],
                    Some(&e.to_string()),
                ),
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

    #[test]
    fn summarize_audit_groups_and_deduplicates() {
        let raw = json!({
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2001-0001",
                            "title": "vuln A",
                            "patched_versions": [">= 2.0"],
                        },
                        "package": { "name": "foo", "version": "1.0.0" }
                    },
                    // same advisory, different version → groups under same ID
                    {
                        "advisory": {
                            "id": "RUSTSEC-2001-0001",
                            "title": "vuln A",
                            "patched_versions": [">= 2.0"],
                        },
                        "package": { "name": "foo", "version": "1.1.0" }
                    },
                    // same advisory + same version → deduplicated within group
                    {
                        "advisory": {
                            "id": "RUSTSEC-2001-0001",
                            "title": "vuln A",
                            "patched_versions": [">= 2.0"],
                        },
                        "package": { "name": "foo", "version": "1.0.0" }
                    },
                    // different advisory
                    {
                        "advisory": {
                            "id": "RUSTSEC-2002-0002",
                            "title": "vuln B",
                            "patched_versions": [">= 3.0"],
                        },
                        "package": { "name": "bar", "version": "0.5.0" }
                    }
                ]
            }
        });

        let results = summarize_audit(&raw);
        assert_eq!(results.len(), 2);

        let a = &results[0];
        assert_eq!(a["id"], "RUSTSEC-2001-0001");
        assert_eq!(a["affected_count"], 2); // 1.0.0 duplicate collapsed
        assert_eq!(a["affected_packages"].as_array().unwrap().len(), 2);

        assert_eq!(results[1]["id"], "RUSTSEC-2002-0002");
        assert_eq!(results[1]["affected_count"], 1);
    }

    #[test]
    fn clippy_lint_code_passes_through_summarization() {
        // Clippy diagnostics use the same compiler-message format
        let raw = vec![json!({
            "reason": "compiler-message",
            "message": {
                "level": "warning",
                "message": "this function could have a `#[must_use]` attribute",
                "code": {"code": "clippy::must_use_candidate", "explanation": null},
                "spans": [{
                    "file_name": "src/lib.rs",
                    "line_start": 10,
                    "is_primary": true
                }],
                "children": [],
                "rendered": "warning: this function...\n"
            }
        })];

        let summary = summarize_diagnostics(&raw);
        assert_eq!(summary.len(), 1);
        let s = &summary[0];
        assert_eq!(s["code"], "clippy::must_use_candidate");
        assert_eq!(s["file"], "src/lib.rs");
    }
}
