//! The main server implementation using the `rmcp` SDK.

use crate::config::{Config, Transport, is_loopback_host};
use crate::db::Db;
use crate::engine::{diagnostics, docs, prompts, resources};
use crate::error::{AppError, AppResult};
use crate::error_ext::ToMcpError;
use axum::Router;
use axum::{middleware, response::IntoResponse};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::InMemoryState, state::NotKeyed};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use resources::LogBuffer;
use rmcp::model::{
    CallToolRequestMethod, CallToolRequestParams, GetPromptRequestParams, GetPromptResult,
    Implementation, ListPromptsResult, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams, ReadResourceResult,
    ServerCapabilities, ServerInfo, ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    model::{CallToolResult, Content},
    transport::{StreamableHttpServerConfig, StreamableHttpService, stdio},
};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, mpsc};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use tracing::{error, info, info_span, warn};

// ───── Pagination defaults ─────

const DEFAULT_PAGE_LIMIT: usize = 50;
const MAX_PAGE_LIMIT: usize = 200;
const DEFAULT_DETAIL_LIMIT: usize = 20;
const MAX_DETAIL_LIMIT: usize = 100;

#[derive(Clone, Copy, Debug)]
pub enum QueryMode {
    Auto,
    Text,
    Symbol,
}

impl QueryMode {
    fn parse(raw: Option<&str>) -> Result<Self, McpError> {
        match raw.unwrap_or("auto") {
            "auto" => Ok(Self::Auto),
            "text" => Ok(Self::Text),
            "symbol" => Ok(Self::Symbol),
            other => Err(invalid_tool_error(
                "INVALID_QUERY_MODE",
                &format!("invalid query mode '{other}'"),
                "search_docs",
                false,
                &["Use one of: auto, text, symbol"],
                None,
                None,
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Phase {
    Metadata,
    Check,
    Indexing,
    Ready,
    Failed(String),
}

impl Phase {
    fn status(&self) -> &'static str {
        match self {
            Self::Metadata | Self::Check => "queued",
            Self::Indexing => "indexing",
            Self::Ready => "ready",
            Self::Failed(_) => "failed",
        }
    }
}

pub struct SearchDocsRequest<'a> {
    pub project_path: Option<&'a Path>,
    pub query: String,
    pub filter_crates: Option<Vec<String>>,
    pub filter_kinds: Option<Vec<String>>,
    pub mode: QueryMode,
    /// Maximum dependency depth to include (0 = workspace only, 1 = + direct deps, …).
    /// `None` means include all transitive dependencies.
    pub max_depth: Option<u32>,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct CargoWarning {
    pub source: String,
    pub message: String,
    pub count: usize,
}

#[derive(Clone, Debug)]
pub struct ProjectProgress {
    pub phase: Phase,
    pub started_at: Instant,
    pub indexing_started_at: Option<Instant>,
    pub total_dependencies: usize,
    pub new_dependencies: usize,
    pub already_indexed: usize,
    pub processed_count: usize,
    pub failed_count: usize,
    /// Number of crates that were actually indexed into the DB after both phases.
    pub indexed_count: usize,
    pub current_crate: Option<String>,
    pub cargo_warnings: Vec<CargoWarning>,
    pub estimated_total_secs: Option<f64>,
    pub failure_categories: HashMap<String, usize>,
}

impl Default for ProjectProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl ProjectProgress {
    pub fn new() -> Self {
        Self {
            phase: Phase::Metadata,
            started_at: Instant::now(),
            indexing_started_at: None,
            total_dependencies: 0,
            new_dependencies: 0,
            already_indexed: 0,
            processed_count: 0,
            failed_count: 0,
            indexed_count: 0,
            current_crate: None,
            cargo_warnings: Vec::new(),
            estimated_total_secs: None,
            failure_categories: HashMap::new(),
        }
    }

    pub fn merge_cargo_warnings(&mut self, new_warnings: Vec<(String, String)>) {
        for (source, message) in new_warnings {
            if let Some(existing) = self
                .cargo_warnings
                .iter_mut()
                .find(|w| w.source == source && w.message == message)
            {
                existing.count += 1;
            } else {
                self.cargo_warnings.push(CargoWarning {
                    source,
                    message,
                    count: 1,
                });
            }
        }
    }

    fn completed(&self) -> usize {
        self.processed_count + self.failed_count
    }

    fn eta_secs(&self) -> Option<f64> {
        if !matches!(self.phase, Phase::Indexing) {
            return None;
        }
        let done = self.completed();
        let remaining = self.new_dependencies.saturating_sub(done);
        if remaining == 0 {
            return None;
        }
        if done == 0 {
            return self.estimated_total_secs;
        }
        let elapsed = self
            .indexing_started_at
            .unwrap_or(self.started_at)
            .elapsed()
            .as_secs_f64();
        let per_crate = elapsed / done as f64;
        Some(per_crate * remaining as f64)
    }

    fn percent(&self) -> u64 {
        if self.new_dependencies == 0 {
            return if matches!(self.phase, Phase::Ready) {
                100
            } else {
                0
            };
        }
        ((self.completed().saturating_mul(100)) / self.new_dependencies).min(100) as u64
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "status": self.phase.status(),
            "total": self.new_dependencies,
            "indexed": self.indexed_count,
            "percent": self.percent(),
        });

        let map = obj
            .as_object_mut()
            .expect("status JSON should always be an object");

        // During indexing, show progress ETA.
        if let Some(eta) = self.eta_secs() {
            map.insert("eta_secs".to_string(), serde_json::json!(eta));
        }

        // After indexing completes, report actual failures (crates missing from DB).
        if matches!(self.phase, Phase::Ready) {
            let actual_failed = self.new_dependencies.saturating_sub(self.indexed_count);
            if actual_failed > 0 {
                map.insert("failed".to_string(), serde_json::json!(actual_failed));
            }
        } else if self.failed_count > 0 {
            map.insert("failed".to_string(), serde_json::json!(self.failed_count));
        }

        if !self.failure_categories.is_empty() {
            map.insert(
                "failure_reasons".to_string(),
                serde_json::json!(self.failure_categories),
            );
        }

        if matches!(self.phase, Phase::Indexing)
            && let Some(current) = self.current_crate.as_ref()
        {
            map.insert("current_crate".to_string(), serde_json::json!(current));
        }
        if let Phase::Failed(msg) = &self.phase {
            map.insert("error".to_string(), serde_json::json!(msg));
        }

        obj
    }
}

pub fn tool_error_payload(
    code: &str,
    message: &str,
    stage: &str,
    retryable: bool,
    hints: &[&str],
    project_path: Option<&Path>,
    debug_raw: Option<&str>,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "code": code,
        "message": message,
        "stage": stage,
        "retryable": retryable,
        "hints": hints,
    });
    let obj = payload
        .as_object_mut()
        .expect("error payload should always be an object");
    if let Some(path) = project_path {
        obj.insert(
            "project_path".to_string(),
            serde_json::json!(path.display().to_string()),
        );
    }
    if let Some(raw) = debug_raw {
        obj.insert("debug".to_string(), serde_json::json!({ "raw": raw }));
    }
    payload
}

fn invalid_tool_error(
    code: &str,
    message: &str,
    stage: &str,
    retryable: bool,
    hints: &[&str],
    project_path: Option<&Path>,
    debug_raw: Option<&str>,
) -> McpError {
    McpError::invalid_params(
        message.to_string(),
        Some(tool_error_payload(
            code,
            message,
            stage,
            retryable,
            hints,
            project_path,
            debug_raw,
        )),
    )
}

fn internal_tool_error(
    code: &str,
    message: &str,
    stage: &str,
    retryable: bool,
    hints: &[&str],
    project_path: Option<&Path>,
    debug_raw: Option<&str>,
) -> McpError {
    McpError::internal_error(
        message.to_string(),
        Some(tool_error_payload(
            code,
            message,
            stage,
            retryable,
            hints,
            project_path,
            debug_raw,
        )),
    )
}

/// Extract and validate `limit` and `offset` from tool call arguments.
fn extract_pagination(
    args: &Option<serde_json::Map<String, serde_json::Value>>,
    default_limit: usize,
    max_limit: usize,
) -> (usize, usize) {
    let max_limit = max_limit.max(1);
    let default_limit = default_limit.max(1).min(max_limit);
    let limit = args
        .as_ref()
        .and_then(|a| a.get("limit"))
        .and_then(|v| v.as_u64())
        .map(|v| (v as usize).min(max_limit).max(1))
        .unwrap_or(default_limit);
    let offset = args
        .as_ref()
        .and_then(|a| a.get("offset"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(0);
    (limit, offset)
}

/// Build a paginated response envelope.
fn paginated_response(items: serde_json::Value, total: usize, offset: usize) -> serde_json::Value {
    let count = items.as_array().map_or(0, |arr| arr.len());
    let has_more = offset + count < total;
    let next_offset = if has_more { Some(offset + count) } else { None };
    serde_json::json!({
        "total": total,
        "count": count,
        "offset": offset,
        "has_more": has_more,
        "next_offset": next_offset,
        "items": items,
    })
}

fn search_tokens(query: &str) -> Vec<String> {
    query
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter_map(|part| {
            let trimmed = part.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_lowercase())
        })
        .collect()
}

fn build_fts_query(query: &str, mode: QueryMode) -> Result<String, McpError> {
    let query = query.trim();
    if query.is_empty() {
        return Err(invalid_tool_error(
            "EMPTY_QUERY",
            "query must not be empty",
            "search_docs",
            false,
            &["Provide at least one search term"],
            None,
            None,
        ));
    }

    let resolved = match mode {
        QueryMode::Auto if query.contains("::") => QueryMode::Symbol,
        QueryMode::Auto => QueryMode::Text,
        explicit => explicit,
    };

    let tokens = match resolved {
        QueryMode::Text | QueryMode::Symbol => search_tokens(query),
        QueryMode::Auto => unreachable!("auto mode is resolved above"),
    };
    if tokens.is_empty() {
        return Err(invalid_tool_error(
            "INVALID_QUERY",
            "query did not contain searchable terms",
            "search_docs",
            false,
            &["Use words or symbols like tokio::spawn"],
            None,
            None,
        ));
    }

    Ok(tokens
        .into_iter()
        .map(|t| format!("{t}*"))
        .collect::<Vec<_>>()
        .join(" AND "))
}

fn summarize_build_levels(items: &[serde_json::Value]) -> serde_json::Value {
    let errors = items
        .iter()
        .filter(|d| d["level"].as_str() == Some("error"))
        .count();
    let warnings = items
        .iter()
        .filter(|d| d["level"].as_str() == Some("warning"))
        .count();
    serde_json::json!({
        "total": items.len(),
        "errors": errors,
        "warnings": warnings,
    })
}

fn normalize_tool_error(section_raw: &serde_json::Value, stage: &str) -> Option<serde_json::Value> {
    let err = section_raw.get("error")?;
    if err.is_object() {
        return Some(err.clone());
    }
    let msg = err.as_str().unwrap_or("tool execution failed");
    Some(tool_error_payload(
        "COMMAND_FAILED",
        msg,
        stage,
        true,
        &[],
        None,
        None,
    ))
}

/// Per-project state held in the project registry.
pub struct ProjectState {
    pub project_path: PathBuf,
    pub metadata: Arc<cargo_metadata::Metadata>,
    pub diagnostics: Arc<Mutex<Vec<serde_json::Value>>>,
    pub outdated_dependencies: Arc<Mutex<serde_json::Value>>,
    pub security_advisories: Arc<Mutex<serde_json::Value>>,
    pub progress: Arc<Mutex<ProjectProgress>>,
    /// Sends a cancellation signal to all background tasks (watcher, check, docs, outdated, audit).
    pub abort: Option<tokio::sync::watch::Sender<()>>,
}

/// The shared application state, which also acts as our ServerHandler.
///
/// Holds server-level shared resources (config, DB connection) and a
/// registry of per-project states keyed by canonicalized path.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<Db>,
    pub projects: Arc<RwLock<HashMap<PathBuf, Arc<Mutex<ProjectState>>>>>,
    pub log_buffer: LogBuffer,
}

impl AppState {
    /// Constructor — takes only shared resources. No project is registered on startup.
    pub fn new(config: Config, db: Db, log_buffer: LogBuffer) -> Self {
        Self {
            config: Arc::new(config),
            db: Arc::new(db),
            projects: Arc::new(RwLock::new(HashMap::new())),
            log_buffer,
        }
    }

    /// Look up a registered project, returning an Arc to its state.
    pub async fn get_project(
        &self,
        project_path: &Path,
    ) -> Result<Arc<Mutex<ProjectState>>, McpError> {
        let canonical = resolve_project_path(project_path)?;
        let registry = self.projects.read().await;
        registry.get(&canonical).cloned().ok_or_else(|| {
            invalid_tool_error(
                "PROJECT_NOT_REGISTERED",
                "project is not registered",
                "project_lookup",
                false,
                &["Call register_project first"],
                Some(&canonical),
                None,
            )
        })
    }

    async fn create_project_state(
        &self,
        canonical: &Path,
    ) -> Result<(Arc<Mutex<ProjectState>>, tokio::sync::watch::Receiver<()>), McpError> {
        let meta = crate::engine::metadata::load_metadata(canonical)
            .await
            .map_err(|e| {
                internal_tool_error(
                    "METADATA_LOAD_FAILED",
                    "failed to load cargo metadata",
                    "register_project",
                    false,
                    &["Ensure the project has a valid Cargo workspace"],
                    Some(canonical),
                    Some(&e.to_string()),
                )
            })?;
        let index_result = docs::collect_index_packages(&meta).map_err(|e| {
            internal_tool_error(
                "COLLECT_PACKAGES_FAILED",
                "failed to collect dependency package list",
                "register_project",
                false,
                &[],
                Some(canonical),
                Some(&e.to_string()),
            )
        })?;
        let package_hashes: Vec<String> = index_result
            .packages
            .iter()
            .map(docs::package_id_hash)
            .collect();
        let already_indexed = self
            .db
            .call(move |conn| {
                let mut count = 0usize;
                for hash in &package_hashes {
                    if docs::is_crate_indexed(conn, hash)? {
                        count += 1;
                    }
                }
                Ok(count)
            })
            .await
            .map_err(|e| {
                internal_tool_error(
                    "INDEX_INSPECTION_FAILED",
                    "failed to inspect documentation index state",
                    "register_project",
                    true,
                    &["Retry the request"],
                    Some(canonical),
                    Some(&e.to_string()),
                )
            })?;

        let total_dependencies = index_result.packages.len();
        let new_dependencies = total_dependencies.saturating_sub(already_indexed);
        let estimated_total_secs = new_dependencies as f64 * 1.5;

        let (abort_tx, abort_rx) = tokio::sync::watch::channel(());
        let mut progress = ProjectProgress::new();
        progress.total_dependencies = total_dependencies;
        progress.new_dependencies = new_dependencies;
        progress.already_indexed = already_indexed;
        progress.estimated_total_secs = Some(estimated_total_secs);

        let project = Arc::new(Mutex::new(ProjectState {
            project_path: canonical.to_path_buf(),
            metadata: Arc::new(meta),
            diagnostics: Arc::new(Mutex::new(Vec::new())),
            outdated_dependencies: Arc::new(Mutex::new(serde_json::Value::Null)),
            security_advisories: Arc::new(Mutex::new(serde_json::Value::Null)),
            progress: Arc::new(Mutex::new(progress)),
            abort: Some(abort_tx),
        }));

        Ok((project, abort_rx))
    }

    async fn spawn_project_tasks(
        &self,
        project: Arc<Mutex<ProjectState>>,
        canonical: PathBuf,
        abort_rx: tokio::sync::watch::Receiver<()>,
    ) {
        {
            let project_guard = project.lock().await;

            let outdated_cache = Arc::clone(&project_guard.outdated_dependencies);
            let progress = Arc::clone(&project_guard.progress);
            let proj_path = canonical.clone();
            let mut abort = abort_rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = abort.changed() => {}
                    _ = diagnostics::run_outdated_on_startup(outdated_cache, &proj_path, progress) => {}
                }
            });

            let audit_cache = Arc::clone(&project_guard.security_advisories);
            let progress = Arc::clone(&project_guard.progress);
            let proj_path = canonical.clone();
            let mut abort = abort_rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = abort.changed() => {}
                    _ = diagnostics::run_audit_on_startup(audit_cache, &proj_path, progress) => {}
                }
            });
        }

        let project_clone = Arc::clone(&project);
        let db_clone = Arc::clone(&self.db);
        let proj_path = canonical.clone();
        let mut abort_check_docs = abort_rx.clone();

        tokio::spawn(async move {
            {
                let guard = project_clone.lock().await;
                let diag_cache = Arc::clone(&guard.diagnostics);
                let path = guard.project_path.clone();
                let progress = Arc::clone(&guard.progress);
                drop(guard);

                {
                    let mut pg = progress.lock().await;
                    pg.phase = Phase::Check;
                    pg.current_crate = None;
                }

                tokio::select! {
                    _ = abort_check_docs.changed() => { return; }
                    _ = diagnostics::run_check_on_startup(diag_cache, &path, Arc::clone(&progress)) => {}
                }
            }

            let (metadata_clone, progress) = {
                let guard = project_clone.lock().await;
                (Arc::clone(&guard.metadata), Arc::clone(&guard.progress))
            };

            {
                let mut pg = progress.lock().await;
                pg.phase = Phase::Indexing;
                pg.indexing_started_at = Some(Instant::now());
            }

            let result = tokio::select! {
                _ = abort_check_docs.changed() => { return; }
                r = docs::ensure_docs_are_cached_and_indexed(
                    metadata_clone,
                    db_clone,
                    proj_path,
                    Arc::clone(&progress),
                ) => r
            };

            match result {
                Ok(()) => {
                    let mut pg = progress.lock().await;
                    pg.phase = Phase::Ready;
                    pg.current_crate = None;
                    info!("Documentation index is ready.");
                }
                Err(e) => {
                    let msg = e.to_string();
                    error!("Failed to ensure docs are cached: {}", msg);
                    let mut pg = progress.lock().await;
                    pg.phase = Phase::Failed(msg);
                    pg.current_crate = None;
                }
            }
        });

        if self.config.watcher.enabled {
            let project_guard = project.lock().await;
            let diag_cache_for_watcher = Arc::clone(&project_guard.diagnostics);
            let progress_for_watcher = Arc::clone(&project_guard.progress);
            let workspace_root: PathBuf = project_guard.metadata.workspace_root.clone().into();
            drop(project_guard);

            let debounce_ms = self.config.watcher.debounce_ms;
            let proj_path = canonical.clone();
            tokio::spawn(async move {
                if let Err(e) = watch_for_changes(
                    diag_cache_for_watcher,
                    workspace_root,
                    debounce_ms,
                    proj_path,
                    progress_for_watcher,
                    abort_rx,
                )
                .await
                {
                    error!("File watcher failed: {}", e);
                }
            });
        }
    }

    async fn project_index_status(&self, project: &Arc<Mutex<ProjectState>>) -> serde_json::Value {
        let guard = project.lock().await;
        guard.progress.lock().await.to_json()
    }

    // ───── Tool implementations ─────

    pub async fn register_project(
        &self,
        project_path_raw: &str,
    ) -> std::result::Result<CallToolResult, McpError> {
        let raw = PathBuf::from(project_path_raw);
        let canonical = resolve_project_path(&raw)?;

        if !canonical.join("Cargo.toml").exists() {
            return Err(invalid_tool_error(
                "MISSING_CARGO_TOML",
                "no Cargo.toml found in project path",
                "register_project",
                false,
                &[],
                Some(&canonical),
                None,
            ));
        }

        // Single write lock: check existence, check limit, and insert atomically
        // to prevent TOCTOU races where concurrent registrations both pass the limit.
        let (project, abort_rx) = {
            let mut registry = self.projects.write().await;

            if let Some(existing) = registry.get(&canonical).cloned() {
                drop(registry);
                let response = serde_json::json!({
                    "status": "already_registered",
                    "project_path": canonical.display().to_string(),
                    "index": self.project_index_status(&existing).await,
                });
                let content = json_content(response)?;
                return Ok(CallToolResult::success(vec![content]));
            }

            if registry.len() >= self.config.server.max_projects {
                return Err(invalid_tool_error(
                    "PROJECT_LIMIT_REACHED",
                    "project limit reached",
                    "register_project",
                    false,
                    &["Unregister a project before adding another"],
                    None,
                    None,
                ));
            }

            info!("Registering project: {}", canonical.display());
            let (project, abort_rx) = self.create_project_state(&canonical).await?;
            registry.insert(canonical.clone(), Arc::clone(&project));
            (project, abort_rx)
        };

        self.spawn_project_tasks(Arc::clone(&project), canonical.clone(), abort_rx)
            .await;

        let response = serde_json::json!({
            "status": "registered",
            "project_path": canonical.display().to_string(),
            "index": self.project_index_status(&project).await,
        });
        let content = json_content(response)?;
        Ok(CallToolResult::success(vec![content]))
    }

    pub async fn reindex_project(
        &self,
        project_path_raw: &str,
    ) -> std::result::Result<CallToolResult, McpError> {
        let raw = PathBuf::from(project_path_raw);
        let canonical = resolve_project_path(&raw)?;
        if !canonical.join("Cargo.toml").exists() {
            return Err(invalid_tool_error(
                "MISSING_CARGO_TOML",
                "no Cargo.toml found in project path",
                "reindex_project",
                false,
                &[],
                Some(&canonical),
                None,
            ));
        }

        // Abort old tasks before creating new state to avoid concurrent cargo
        // processes competing for file locks on the same project directory.
        {
            let registry = self.projects.read().await;
            match registry.get(&canonical) {
                None => {
                    return Err(invalid_tool_error(
                        "PROJECT_NOT_REGISTERED",
                        "project is not registered",
                        "reindex_project",
                        false,
                        &["Call register_project first"],
                        Some(&canonical),
                        None,
                    ));
                }
                Some(old) => {
                    let old_guard = old.lock().await;
                    if let Some(tx) = &old_guard.abort {
                        let _ = tx.send(());
                    }
                }
            }
        }

        info!("Reindexing project: {}", canonical.display());
        let (project, abort_rx) = self.create_project_state(&canonical).await?;
        {
            let mut registry = self.projects.write().await;
            registry.insert(canonical.clone(), Arc::clone(&project));
        }

        self.spawn_project_tasks(Arc::clone(&project), canonical.clone(), abort_rx)
            .await;

        let response = serde_json::json!({
            "status": "reindexing",
            "project_path": canonical.display().to_string(),
            "index": self.project_index_status(&project).await,
        });
        let content = json_content(response)?;
        Ok(CallToolResult::success(vec![content]))
    }

    pub async fn list_projects(
        &self,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<CallToolResult, McpError> {
        let projects: Vec<(PathBuf, Arc<Mutex<ProjectState>>)> = {
            let registry = self.projects.read().await;
            registry
                .iter()
                .map(|(path, state)| (path.clone(), Arc::clone(state)))
                .collect()
        };

        let mut entries = Vec::with_capacity(projects.len());
        for (path, state) in projects {
            let progress_snapshot = self.project_index_status(&state).await;
            let mut entry = progress_snapshot;
            let obj = entry
                .as_object_mut()
                .expect("ProjectProgress::to_json always returns an object");
            obj.insert(
                "project_path".to_string(),
                serde_json::Value::String(path.display().to_string()),
            );
            entries.push(entry);
        }
        entries.sort_by(|a, b| {
            a["project_path"]
                .as_str()
                .unwrap_or_default()
                .cmp(b["project_path"].as_str().unwrap_or_default())
        });
        let total = entries.len();
        let page: Vec<_> = entries.into_iter().skip(offset).take(limit).collect();
        let envelope = paginated_response(serde_json::json!(page), total, offset);
        let content = json_content(envelope)?;
        Ok(CallToolResult::success(vec![content]))
    }

    pub async fn get_index_status(
        &self,
        project_path: &Path,
    ) -> std::result::Result<CallToolResult, McpError> {
        let project = self.get_project(project_path).await?;
        let response = serde_json::json!({
            "project_path": resolve_project_path(project_path)?.display().to_string(),
            "index": self.project_index_status(&project).await,
        });
        let content = json_content(response)?;
        Ok(CallToolResult::success(vec![content]))
    }

    pub async fn list_crates(
        &self,
        project_path: &Path,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<CallToolResult, McpError> {
        let project = self.get_project(project_path).await?;
        let project_guard = project.lock().await;
        let crate_names: Vec<_> = project_guard
            .metadata
            .workspace_packages()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        let mut crate_names = crate_names;
        crate_names.sort_unstable();
        let total = crate_names.len();
        let page: Vec<_> = crate_names.into_iter().skip(offset).take(limit).collect();
        let envelope = paginated_response(serde_json::json!(page), total, offset);
        let content = json_content(envelope)?;
        Ok(CallToolResult::success(vec![content]))
    }

    pub async fn get_diagnostics(
        &self,
        project_path: &Path,
    ) -> std::result::Result<CallToolResult, McpError> {
        let project = self.get_project(project_path).await?;
        let (
            raw_diagnostics,
            outdated_dependencies,
            security_advisories,
            cargo_warnings,
            index_status,
        ) = {
            let project_guard = project.lock().await;
            let raw_diagnostics = project_guard.diagnostics.lock().await.clone();
            let outdated_dependencies = project_guard.outdated_dependencies.lock().await.clone();
            let security_advisories = project_guard.security_advisories.lock().await.clone();
            let progress_guard = project_guard.progress.lock().await;
            let warnings: Vec<serde_json::Value> = progress_guard
                .cargo_warnings
                .iter()
                .map(|w| {
                    serde_json::json!({
                        "source": w.source,
                        "message": w.message,
                        "count": w.count,
                    })
                })
                .collect();
            (
                raw_diagnostics,
                outdated_dependencies,
                security_advisories,
                warnings,
                progress_guard.to_json(),
            )
        };
        let build_diagnostics = diagnostics::summarize_diagnostics(&raw_diagnostics);
        let outdated = diagnostics::summarize_outdated(&outdated_dependencies);
        let outdated_actionable = outdated
            .iter()
            .filter(|d| d.get("status").and_then(|s| s.as_str()) != Some("removed"))
            .count();
        let advisories = diagnostics::summarize_audit(&security_advisories);
        let combined_report = serde_json::json!({
            "project_path": resolve_project_path(project_path)?.display().to_string(),
            "index": index_status,
            "build": summarize_build_levels(&build_diagnostics),
            "outdated": {
                "total": outdated_actionable,
            },
            "security": {
                "total": advisories.len(),
            },
            "cargo_warnings": cargo_warnings,
        });
        let content = Content::json(combined_report)?;
        Ok(CallToolResult::success(vec![content]))
    }

    pub async fn get_build_diagnostics(
        &self,
        project_path: &Path,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<CallToolResult, McpError> {
        let project = self.get_project(project_path).await?;
        let project_guard = project.lock().await;
        let raw_diagnostics = project_guard.diagnostics.lock().await.clone();
        let build_diagnostics = diagnostics::summarize_diagnostics(&raw_diagnostics);
        let total = build_diagnostics.len();
        let page: Vec<_> = build_diagnostics
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();

        let mut envelope = paginated_response(serde_json::json!(page), total, offset);
        envelope["summary"] = summarize_build_levels(&build_diagnostics);
        if let Some(message) = raw_diagnostics.iter().find_map(|v| {
            (v.get("reason").and_then(|r| r.as_str()) == Some("cargo-check-error"))
                .then(|| v.get("message").and_then(|m| m.as_str()))
                .flatten()
        }) {
            envelope["error"] = tool_error_payload(
                "CARGO_CHECK_FAILED",
                "cargo check failed",
                "build_diagnostics",
                true,
                &["Run cargo check locally for complete output"],
                Some(project_path),
                Some(message),
            );
        }

        let content = json_content(envelope)?;
        Ok(CallToolResult::success(vec![content]))
    }

    pub async fn get_outdated_diagnostics(
        &self,
        project_path: &Path,
        limit: usize,
        offset: usize,
        include_removed: bool,
    ) -> std::result::Result<CallToolResult, McpError> {
        let project = self.get_project(project_path).await?;
        let project_guard = project.lock().await;
        let raw = project_guard.outdated_dependencies.lock().await.clone();
        let all_items = diagnostics::summarize_outdated(&raw);
        let items: Vec<_> = if include_removed {
            all_items
        } else {
            all_items
                .into_iter()
                .filter(|d| d.get("status").and_then(|s| s.as_str()) != Some("removed"))
                .collect()
        };
        let total = items.len();
        let page: Vec<_> = items.iter().skip(offset).take(limit).cloned().collect();

        let mut envelope = paginated_response(serde_json::json!(page), total, offset);
        envelope["summary"] = serde_json::json!({ "total": total });
        if let Some(err) = normalize_tool_error(&raw, "outdated_diagnostics") {
            envelope["error"] = err;
        }
        let content = json_content(envelope)?;
        Ok(CallToolResult::success(vec![content]))
    }

    pub async fn get_security_diagnostics(
        &self,
        project_path: &Path,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<CallToolResult, McpError> {
        let project = self.get_project(project_path).await?;
        let project_guard = project.lock().await;
        let raw = project_guard.security_advisories.lock().await.clone();
        let items = diagnostics::summarize_audit(&raw);
        let total = items.len();
        let page: Vec<_> = items.iter().skip(offset).take(limit).cloned().collect();

        let mut envelope = paginated_response(serde_json::json!(page), total, offset);
        envelope["summary"] = serde_json::json!({ "total": total });
        if let Some(err) = normalize_tool_error(&raw, "security_diagnostics") {
            envelope["error"] = err;
        }
        let content = json_content(envelope)?;
        Ok(CallToolResult::success(vec![content]))
    }

    pub async fn search_docs(
        &self,
        request: SearchDocsRequest<'_>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let SearchDocsRequest {
            project_path,
            query,
            filter_crates,
            filter_kinds,
            mode,
            max_depth,
            limit,
            offset,
        } = request;
        let fts_query = build_fts_query(&query, mode)?;

        // When project_path is given, scope results to that project's dependency tree
        let mut is_partial = false;
        let mut indexing_status: Option<serde_json::Value> = None;
        let scope_crates: Option<Vec<docs::ProjectCrate>> = if let Some(pp) = project_path {
            let project = self.get_project(pp).await?;
            let project_guard = project.lock().await;

            let progress_guard = project_guard.progress.lock().await;
            match &progress_guard.phase {
                Phase::Metadata | Phase::Check => {
                    let snapshot = progress_guard.to_json();
                    let snapshot_raw = snapshot.to_string();
                    return Err(internal_tool_error(
                        "INDEX_NOT_READY",
                        "documentation index is not ready",
                        "search_docs",
                        true,
                        &["Call get_index_status and wait for status=ready"],
                        Some(pp),
                        Some(&snapshot_raw),
                    ));
                }
                Phase::Failed(msg) => {
                    return Err(internal_tool_error(
                        "INDEX_FAILED",
                        "documentation indexing failed",
                        "search_docs",
                        false,
                        &["Call reindex_project to retry indexing"],
                        Some(pp),
                        Some(msg),
                    ));
                }
                Phase::Indexing => {
                    is_partial = true;
                    indexing_status = Some(progress_guard.to_json());
                }
                Phase::Ready => {}
            }
            drop(progress_guard);

            let metadata = Arc::clone(&project_guard.metadata);
            drop(project_guard);

            let mut crates = docs::project_crate_scopes(&metadata)
                .mcp_internal_err("Failed to compute project crate scopes")?;
            // Filter by max_depth when provided (default: include all).
            if let Some(md) = max_depth {
                crates.retain(|c| c.depth <= md);
            }
            Some(crates)
        } else {
            None
        };

        let span = info_span!(
            "search",
            %query,
            filter_crates = ?filter_crates
        );
        let _enter = span.enter();
        let search_cap = self.config.server.max_search_results.max(1);
        let limit = limit.min(search_cap).max(1);

        // Build the FTS5 query with positional parameters.
        // We use a Vec of boxed rusqlite::types::ToSql for dynamic params.
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql + Send>> = Vec::new();

        // ?1 = query
        param_values.push(Box::new(fts_query));

        let mut extra_where = String::new();

        if let Some(scopes) = scope_crates.as_ref() {
            if scopes.is_empty() {
                let envelope = paginated_response(serde_json::json!([]), 0, offset);
                let content = json_content(envelope)?;
                return Ok(CallToolResult::success(vec![content]));
            }

            let mut placeholders = Vec::with_capacity(scopes.len());
            for i in 0..scopes.len() {
                placeholders.push(format!("?{}", param_values.len() + 1 + i));
            }
            extra_where.push_str(&format!(
                " AND d.package_id_hash IN ({})",
                placeholders.join(", ")
            ));
            for scope in scopes {
                param_values.push(Box::new(scope.package_id_hash.clone()));
            }
        }

        if let Some(filters) = filter_crates.as_ref()
            && !filters.is_empty()
        {
            let mut placeholders = Vec::with_capacity(filters.len());
            for i in 0..filters.len() {
                placeholders.push(format!("?{}", param_values.len() + 1 + i));
            }
            extra_where.push_str(&format!(
                " AND d.crate_name IN ({})",
                placeholders.join(", ")
            ));
            for f in filters {
                param_values.push(Box::new(docs::normalize_crate_name(f)));
            }
        }

        if let Some(filters) = filter_kinds.as_ref()
            && !filters.is_empty()
        {
            let mut placeholders = Vec::with_capacity(filters.len());
            for i in 0..filters.len() {
                placeholders.push(format!("?{}", param_values.len() + 1 + i));
            }
            extra_where.push_str(&format!(" AND d.kind IN ({})", placeholders.join(", ")));
            for kind in filters {
                param_values.push(Box::new(kind.clone()));
            }
        }

        // Fetch a bounded top-N window, then paginate in app code.
        let sql_limit = search_cap;
        let limit_param_idx = param_values.len() + 1;
        param_values.push(Box::new(sql_limit as i64));

        let sql = format!(
            r#"
            SELECT
                d.crate_name,
                d.crate_version,
                d.item_name,
                d.kind,
                snippet(docs_fts, 2, '<mark>', '</mark>', '...', 40) as text,
                bm25(docs_fts, 1.0, 2.0, 1.0) as score
            FROM docs_fts
            JOIN docs d ON d.id = docs_fts.rowid
            WHERE docs_fts MATCH ?1
            {extra_where}
            ORDER BY score ASC, d.crate_name ASC, d.item_name ASC
            LIMIT ?{limit_param_idx}
            "#
        );

        let all_results = match self
            .db
            .call(move |conn| {
                let mut stmt = conn.prepare(&sql)?;
                let param_refs: Vec<&dyn rusqlite::types::ToSql> = param_values
                    .iter()
                    .map(|p| p.as_ref() as &dyn rusqlite::types::ToSql)
                    .collect();
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    let crate_name: String = row.get(0)?;
                    let crate_version: String = row.get(1)?;
                    let item_name: String = row.get(2)?;
                    let kind: String = row.get(3)?;
                    let text: String = row.get(4)?;
                    let score: f64 = row.get(5)?;
                    Ok(serde_json::json!({
                        "crate": crate_name,
                        "crate_version": crate_version,
                        "item": item_name,
                        "kind": kind,
                        "text": text,
                        "score": -score,
                    }))
                })?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                let err_text = e.to_string();
                if err_text.contains("fts5")
                    || err_text.contains("no such column")
                    || err_text.contains("syntax error")
                {
                    return Err(invalid_tool_error(
                        "INVALID_SEARCH_QUERY",
                        "search query could not be parsed",
                        "search_docs",
                        false,
                        &["Use words or symbol paths like tokio::spawn"],
                        project_path,
                        Some(&err_text),
                    ));
                }
                return Err(internal_tool_error(
                    "SEARCH_QUERY_FAILED",
                    "search query failed",
                    "search_docs",
                    true,
                    &["Retry the request"],
                    project_path,
                    Some(&err_text),
                ));
            }
        };

        let total = all_results.len();
        let page: Vec<_> = all_results.into_iter().skip(offset).take(limit).collect();
        let mut envelope = paginated_response(serde_json::json!(page), total, offset);

        if is_partial {
            envelope["partial"] = serde_json::json!(true);
            if let Some(status) = indexing_status {
                envelope["index"] = status;
            }
        }

        if total == 0 && project_path.is_some() {
            let mut notes = Vec::new();
            if is_partial {
                notes.push("index is still building; results may be incomplete".to_string());
            }
            if let Some(pp) = project_path
                && let Ok(project) = self.get_project(pp).await
            {
                let pg = project.lock().await;
                let progress_guard = pg.progress.lock().await;
                let failed = progress_guard.failed_count;
                if failed > 0 {
                    notes.push(format!("{failed} crates failed indexing"));
                }
            }
            if !notes.is_empty() {
                envelope["notes"] = serde_json::json!(notes);
            }
        }

        let content = json_content(envelope)?;
        Ok(CallToolResult::success(vec![content]))
    }
    pub async fn unregister_project(
        &self,
        project_path_raw: &str,
    ) -> std::result::Result<CallToolResult, McpError> {
        let raw = PathBuf::from(project_path_raw);
        let canonical = resolve_project_path(&raw)?;

        let removed = {
            let mut registry = self.projects.write().await;
            registry.remove(&canonical)
        };

        match removed {
            Some(project) => {
                let guard = project.lock().await;
                if let Some(tx) = &guard.abort {
                    let _ = tx.send(());
                }
                drop(guard);

                info!("Unregistered project: {}", canonical.display());
                let content = json_content(serde_json::json!({
                    "status": "unregistered",
                    "project_path": canonical.display().to_string(),
                }))?;
                Ok(CallToolResult::success(vec![content]))
            }
            None => Err(invalid_tool_error(
                "PROJECT_NOT_REGISTERED",
                "project is not registered",
                "unregister_project",
                false,
                &[],
                Some(&canonical),
                None,
            )),
        }
    }
}

// ───── Helper to extract project_path from tool arguments ─────

fn extract_project_path(
    args: &Option<serde_json::Map<String, serde_json::Value>>,
) -> Result<PathBuf, McpError> {
    let path_str = args
        .as_ref()
        .and_then(|a| a.get("project_path"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            invalid_tool_error(
                "MISSING_PROJECT_PATH",
                "missing required project_path parameter",
                "tool_input",
                false,
                &[],
                None,
                None,
            )
        })?;
    Ok(PathBuf::from(path_str))
}

fn try_extract_project_path(
    args: &Option<serde_json::Map<String, serde_json::Value>>,
) -> Option<PathBuf> {
    args.as_ref()
        .and_then(|a| a.get("project_path"))
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
}

fn resolve_project_path(path: &Path) -> Result<PathBuf, McpError> {
    path.canonicalize().map_err(|e| {
        invalid_tool_error(
            "INVALID_PROJECT_PATH",
            "cannot resolve project path",
            "path_resolution",
            false,
            &["Provide an existing absolute project path"],
            Some(path),
            Some(&e.to_string()),
        )
    })
}

// ───── ServerHandler impl ─────

#[allow(clippy::manual_async_fn)]
impl ServerHandler for AppState {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
            server_info: Implementation {
                name: "cratedex".to_string(),
                title: Some("Cratedex".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: Some(env!("CARGO_PKG_DESCRIPTION").to_string()),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "Register projects, monitor index status, query docs, and fetch diagnostics. \
                 Use register_project once, reindex_project only when you want to refresh. \
                 Diagnostics are split by intent for small payloads. \
                 Resources: cratedex://logs. Prompt: coding_modern_rust."
                    .to_string(),
            ),
        }
    }

    fn call_tool(
        &self,
        call: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = std::result::Result<CallToolResult, McpError>> + Send + '_
    {
        async move {
            info!("call_tool: {}", call.name);
            match call.name.as_ref() {
                "register_project" => {
                    let path_str = call
                        .arguments
                        .as_ref()
                        .and_then(|args| args.get("project_path"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            invalid_tool_error(
                                "MISSING_PROJECT_PATH",
                                "missing project_path parameter",
                                "register_project",
                                false,
                                &[],
                                None,
                                None,
                            )
                        })?;
                    self.register_project(path_str).await
                }
                "reindex_project" => {
                    let path_str = call
                        .arguments
                        .as_ref()
                        .and_then(|args| args.get("project_path"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            invalid_tool_error(
                                "MISSING_PROJECT_PATH",
                                "missing project_path parameter",
                                "reindex_project",
                                false,
                                &[],
                                None,
                                None,
                            )
                        })?;
                    self.reindex_project(path_str).await
                }
                "list_projects" => {
                    let (limit, offset) =
                        extract_pagination(&call.arguments, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
                    self.list_projects(limit, offset).await
                }
                "get_index_status" => {
                    let path = extract_project_path(&call.arguments)?;
                    self.get_index_status(&path).await
                }
                "list_crates" => {
                    let path = extract_project_path(&call.arguments)?;
                    let (limit, offset) =
                        extract_pagination(&call.arguments, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
                    self.list_crates(&path, limit, offset).await
                }
                "get_diagnostics" => {
                    let path = extract_project_path(&call.arguments)?;
                    self.get_diagnostics(&path).await
                }
                "get_build_diagnostics" => {
                    let path = extract_project_path(&call.arguments)?;
                    let (limit, offset) =
                        extract_pagination(&call.arguments, DEFAULT_DETAIL_LIMIT, MAX_DETAIL_LIMIT);
                    self.get_build_diagnostics(&path, limit, offset).await
                }
                "get_outdated_diagnostics" => {
                    let path = extract_project_path(&call.arguments)?;
                    let (limit, offset) =
                        extract_pagination(&call.arguments, DEFAULT_DETAIL_LIMIT, MAX_DETAIL_LIMIT);
                    let include_removed = call
                        .arguments
                        .as_ref()
                        .and_then(|a| a.get("include_removed"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    self.get_outdated_diagnostics(&path, limit, offset, include_removed)
                        .await
                }
                "get_security_diagnostics" => {
                    let path = extract_project_path(&call.arguments)?;
                    let (limit, offset) =
                        extract_pagination(&call.arguments, DEFAULT_DETAIL_LIMIT, MAX_DETAIL_LIMIT);
                    self.get_security_diagnostics(&path, limit, offset).await
                }
                "search_docs" => {
                    let project_path = try_extract_project_path(&call.arguments);
                    let query = call
                        .arguments
                        .as_ref()
                        .and_then(|args| args.get("query"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            invalid_tool_error(
                                "MISSING_QUERY",
                                "missing query parameter",
                                "search_docs",
                                false,
                                &[],
                                None,
                                None,
                            )
                        })?
                        .to_string();
                    let filter_crates = call
                        .arguments
                        .as_ref()
                        .and_then(|args| args.get("crates"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<Vec<String>>()
                        });
                    let filter_kinds = call
                        .arguments
                        .as_ref()
                        .and_then(|args| args.get("kinds"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<Vec<String>>()
                        });
                    let mode = QueryMode::parse(
                        call.arguments
                            .as_ref()
                            .and_then(|args| args.get("mode"))
                            .and_then(|v| v.as_str()),
                    )?;
                    // Default max_depth=1 (workspace + direct deps) when a
                    // project_path is set and the caller didn't specify.
                    // Pass null explicitly to search all transitive deps.
                    let max_depth = match call
                        .arguments
                        .as_ref()
                        .and_then(|args| args.get("max_depth"))
                    {
                        Some(v) if v.is_null() => None,
                        Some(v) => v.as_u64().map(|d| d as u32),
                        None if project_path.is_some() => Some(1),
                        None => None,
                    };
                    let search_limit_cap = self.config.server.max_search_results.max(1);
                    let (limit, offset) =
                        extract_pagination(&call.arguments, search_limit_cap, search_limit_cap);
                    self.search_docs(SearchDocsRequest {
                        project_path: project_path.as_deref(),
                        query,
                        filter_crates,
                        filter_kinds,
                        mode,
                        max_depth,
                        limit,
                        offset,
                    })
                    .await
                }
                "unregister_project" => {
                    let path_str = call
                        .arguments
                        .as_ref()
                        .and_then(|args| args.get("project_path"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            invalid_tool_error(
                                "MISSING_PROJECT_PATH",
                                "missing project_path parameter",
                                "unregister_project",
                                false,
                                &[],
                                None,
                                None,
                            )
                        })?;
                    self.unregister_project(path_str).await
                }
                _ => Err(McpError::method_not_found::<CallToolRequestMethod>()),
            }
        }
    }

    fn list_tools(
        &self,
        _pagination: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = std::result::Result<ListToolsResult, McpError>> + Send + '_
    {
        async move {
            info!("list_tools requested");
            let project_path_prop = serde_json::json!({
                "type": "string",
                "description": "Absolute Rust project path"
            });
            let pagination_props = serde_json::json!({
                "limit": {
                    "type": "integer",
                    "description": "Page size"
                },
                "offset": {
                    "type": "integer",
                    "description": "Pagination offset"
                }
            });
            let search_limit_cap = self.config.server.max_search_results.max(1);
            let search_pagination_props = serde_json::json!({
                "limit": {
                    "type": "integer",
                    "description": format!("Page size (max {search_limit_cap})")
                },
                "offset": {
                    "type": "integer",
                    "description": "Pagination offset"
                }
            });
            let paginated_output_schema = |items_schema: serde_json::Value| -> Option<
                Arc<serde_json::Map<String, serde_json::Value>>,
            > {
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "total": { "type": "integer" },
                        "count": { "type": "integer" },
                        "offset": { "type": "integer" },
                        "has_more": { "type": "boolean" },
                        "next_offset": { "type": ["integer", "null"] },
                        "items": items_schema,
                    },
                    "required": ["total", "count", "offset", "has_more", "next_offset", "items"]
                })
                .as_object()
                .cloned()
                .map(Arc::new)
            };
            Ok(ListToolsResult {
                meta: None,
                tools: vec![
                    rmcp::model::Tool {
                        name: "register_project".into(),
                        title: Some("Register Project".into()),
                        description: Some("Register project and start background indexing".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": &project_path_prop
                                },
                                "required": ["project_path"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "status": { "type": "string" },
                                "project_path": { "type": "string" },
                                "index": { "type": "object" }
                            },
                            "required": ["status", "project_path"]
                        })
                        .as_object()
                        .cloned()
                        .map(Arc::new),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(false)
                            .destructive(false)
                            .idempotent(true)
                            .open_world(true)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "reindex_project".into(),
                        title: Some("Reindex Project".into()),
                        description: Some("Restart indexing for an existing project".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": &project_path_prop
                                },
                                "required": ["project_path"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "status": { "type": "string" },
                                "project_path": { "type": "string" },
                                "index": { "type": "object" }
                            },
                            "required": ["status", "project_path"]
                        })
                        .as_object()
                        .cloned()
                        .map(Arc::new),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(false)
                            .destructive(false)
                            .idempotent(false)
                            .open_world(true)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "list_projects".into(),
                        title: Some("List Projects".into()),
                        description: Some("List registered projects".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "limit": pagination_props["limit"],
                                    "offset": pagination_props["offset"],
                                }
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: paginated_output_schema(serde_json::json!({
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "project_path": { "type": "string" },
                                    "status": { "type": "string" },
                                    "indexed": { "type": "integer" },
                                    "total": { "type": "integer" },
                                    "percent": { "type": "integer" }
                                }
                            }
                        })),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(true)
                            .destructive(false)
                            .idempotent(true)
                            .open_world(false)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "get_index_status".into(),
                        title: Some("Get Index Status".into()),
                        description: Some("Get indexing status for one project".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": &project_path_prop
                                },
                                "required": ["project_path"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "project_path": { "type": "string" },
                                "index": { "type": "object" }
                            },
                            "required": ["project_path", "index"]
                        })
                        .as_object()
                        .cloned()
                        .map(Arc::new),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(true)
                            .destructive(false)
                            .idempotent(true)
                            .open_world(false)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "list_crates".into(),
                        title: Some("List Crates".into()),
                        description: Some("List workspace crates".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": &project_path_prop,
                                    "limit": pagination_props["limit"],
                                    "offset": pagination_props["offset"],
                                },
                                "required": ["project_path"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: paginated_output_schema(serde_json::json!({
                            "type": "array",
                            "items": { "type": "string" }
                        })),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(true)
                            .destructive(false)
                            .idempotent(true)
                            .open_world(false)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "get_diagnostics".into(),
                        title: Some("Get Diagnostics Summary".into()),
                        description: Some("Compact diagnostics summary".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": &project_path_prop
                                },
                                "required": ["project_path"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "project_path": { "type": "string" },
                                "index": { "type": "object" },
                                "build": { "type": "object" },
                                "outdated": { "type": "object" },
                                "security": { "type": "object" },
                                "cargo_warnings": { "type": "array" }
                            },
                            "required": ["project_path", "index", "build", "outdated", "security", "cargo_warnings"]
                        })
                        .as_object()
                        .cloned()
                        .map(Arc::new),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(true)
                            .destructive(false)
                            .idempotent(false)
                            .open_world(true)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "get_build_diagnostics".into(),
                        title: Some("Build Diagnostics".into()),
                        description: Some("Paginated build diagnostics".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": &project_path_prop,
                                    "limit": pagination_props["limit"],
                                    "offset": pagination_props["offset"],
                                },
                                "required": ["project_path"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: paginated_output_schema(serde_json::json!({
                            "type": "array",
                            "items": { "type": "object" }
                        })),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(true)
                            .destructive(false)
                            .idempotent(true)
                            .open_world(false)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "get_outdated_diagnostics".into(),
                        title: Some("Outdated Diagnostics".into()),
                        description: Some("Paginated outdated dependencies".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": &project_path_prop,
                                    "include_removed": {
                                        "type": "boolean",
                                        "description": "Include deps where latest is 'Removed' (default: false)"
                                    },
                                    "limit": pagination_props["limit"],
                                    "offset": pagination_props["offset"],
                                },
                                "required": ["project_path"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: paginated_output_schema(serde_json::json!({
                            "type": "array",
                            "items": { "type": "object" }
                        })),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(true)
                            .destructive(false)
                            .idempotent(true)
                            .open_world(false)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "get_security_diagnostics".into(),
                        title: Some("Security Diagnostics".into()),
                        description: Some("Paginated security advisories".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": &project_path_prop,
                                    "limit": pagination_props["limit"],
                                    "offset": pagination_props["offset"],
                                },
                                "required": ["project_path"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: paginated_output_schema(serde_json::json!({
                            "type": "array",
                            "items": { "type": "object" }
                        })),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(true)
                            .destructive(false)
                            .idempotent(true)
                            .open_world(false)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "search_docs".into(),
                        title: Some("Search Docs".into()),
                        description: Some("Search indexed Rust documentation".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": {
                                        "type": "string",
                                        "description": "Optional project scope"
                                    },
                                    "query": {
                                        "type": "string",
                                        "description": "Search query"
                                    },
                                    "crates": {
                                        "type": "array",
                                        "items": {
                                            "type": "string"
                                        },
                                        "description": "Optional crate filters"
                                    },
                                    "kinds": {
                                        "type": "array",
                                        "items": {
                                            "type": "string"
                                        },
                                        "description": "Optional kind filters"
                                    },
                                    "mode": {
                                        "type": "string",
                                        "enum": ["auto", "text", "symbol"],
                                        "description": "Query parser mode"
                                    },
                                    "max_depth": {
                                        "type": ["integer", "null"],
                                        "description": "Max dependency depth (0=workspace, 1=+direct deps). Default 1 when project_path is set. Null=all transitive deps."
                                    },
                                    "limit": search_pagination_props["limit"],
                                    "offset": search_pagination_props["offset"],
                                },
                                "required": ["query"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: paginated_output_schema(serde_json::json!({
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "crate": { "type": "string" },
                                    "crate_version": { "type": "string" },
                                    "item": { "type": "string" },
                                    "kind": { "type": "string" },
                                    "text": { "type": "string" },
                                    "score": { "type": "number" }
                                }
                            }
                        })),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(true)
                            .destructive(false)
                            .idempotent(true)
                            .open_world(false)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                    rmcp::model::Tool {
                        name: "unregister_project".into(),
                        title: Some("Unregister Project".into()),
                        description: Some("Remove a registered project".into()),
                        input_schema: Arc::new(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "project_path": &project_path_prop
                                },
                                "required": ["project_path"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                        output_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "status": { "type": "string" },
                                "project_path": { "type": "string" }
                            },
                            "required": ["status", "project_path"]
                        })
                        .as_object()
                        .cloned()
                        .map(Arc::new),
                        annotations: Some(ToolAnnotations::new()
                            .read_only(false)
                            .destructive(true)
                            .idempotent(true)
                            .open_world(false)),
                        execution: None,
                        icons: None,
                        meta: None,
                    },
                ],
                next_cursor: None,
            })
        }
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = std::result::Result<ListResourcesResult, McpError>> + Send + '_
    {
        async move {
            info!("list_resources requested");
            Ok(resources::list_resources_impl())
        }
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = std::result::Result<ReadResourceResult, McpError>> + Send + '_
    {
        async move {
            info!("read_resource: {}", request.uri);
            resources::read_resource_impl(&request.uri, &self.log_buffer).ok_or_else(|| {
                McpError::invalid_params(format!("Unknown resource URI: {}", request.uri), None)
            })
        }
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = std::result::Result<ListPromptsResult, McpError>> + Send + '_
    {
        async move {
            info!("list_prompts requested");
            Ok(prompts::list_prompts_impl())
        }
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = std::result::Result<GetPromptResult, McpError>> + Send + '_
    {
        async move {
            info!("get_prompt: {}", request.name);
            prompts::get_prompt(&request)
        }
    }
}

fn json_content<T: Serialize>(value: T) -> Result<Content, McpError> {
    let json = serde_json::to_value(value)
        .map_err(|e| McpError::internal_error(format!("Failed to serialize JSON: {}", e), None))?;
    Content::json(json)
}

/// Configures and starts the MCP server.
pub async fn start_server() -> AppResult<()> {
    use resources::{LogCaptureLayer, new_log_buffer};
    use tracing::Level;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // Load configuration
    let config =
        Config::load().map_err(|e| anyhow::anyhow!("Failed to load configuration: {}", e))?;

    // Set up tracing with log capture layer
    let log_buffer = new_log_buffer(resources::LOG_BUFFER_CAPACITY);
    let log_layer = LogCaptureLayer::new(log_buffer.clone(), resources::LOG_BUFFER_CAPACITY);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(log_layer)
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            Level::INFO,
        ))
        .init();

    info!(
        "Connecting to database at {}...",
        config.database.path.display()
    );

    let db_path_str = config.database.path.to_string_lossy().to_string();
    if db_path_str != ":memory:"
        && let Some(parent) = config.database.path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }

    let db = match Db::open_with_retry(&db_path_str, 3, std::time::Duration::from_millis(100)).await
    {
        Ok(db) => db,
        Err(e) => {
            if db_path_str == ":memory:" {
                return Err(anyhow::anyhow!("Failed to connect to database: {}", e).into());
            }
            // Fall back to a per-process temporary database so the MCP handshake
            // can still complete instead of crashing.
            let fallback_dir = config
                .database
                .path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let fallback_path = fallback_dir.join(format!("cratedex-{}.db", std::process::id()));
            warn!(
                original_path = db_path_str,
                fallback_path = %fallback_path.display(),
                original_error = %e,
                "Failed to open configured database after retries, falling back to per-process DB. \
                 Indexed docs will not be shared with other instances. \
                 To avoid this, set CRATEDEX__DATABASE__PATH to a unique path \
                 or use HTTP transport with a single shared daemon."
            );
            Db::open(&fallback_path.to_string_lossy()).map_err(|e2| {
                anyhow::anyhow!(
                    "Failed to open fallback database at {}: {}",
                    fallback_path.display(),
                    e2
                )
            })?
        }
    };

    // Eagerly create the global docs table on startup
    db.call(|conn| {
        docs::ensure_docs_table_and_fts(conn)?;
        Ok(())
    })
    .await?;

    let app_state = AppState::new(config.clone(), db, log_buffer);

    match app_state.config.server.transport {
        Transport::Stdio => {
            info!("Starting Cratedex server with stdio transport...");
            let service = app_state
                .serve(stdio())
                .await
                .map_err(|e| AppError::ServerInit(Box::new(e)))?;
            // Keep the stdio service alive for the full client session.
            let quit_reason = service.waiting().await?;
            info!(?quit_reason, "Cratedex stdio session finished");
        }
        Transport::Http => {
            let host = app_state.config.server.host.clone();
            let port = app_state.config.server.port;

            if !app_state.config.server.allow_remote && !is_loopback_host(&host) {
                return Err(anyhow::anyhow!(
                    "Refusing to bind HTTP server to non-loopback host '{}'. \
Set CRATEDEX__SERVER__ALLOW_REMOTE=true only when fronting cratedex with \
an authenticated TLS reverse proxy.",
                    host
                )
                .into());
            }

            let addr: SocketAddr = format!("{}:{}", host, port)
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid server address: {}", e))?;
            info!(
                "Starting Cratedex server over HTTP (Streamable HTTP) at http://{}",
                addr
            );
            let http_config = StreamableHttpServerConfig::default();
            let cancellation = http_config.cancellation_token.clone();
            let app_state_for_service = app_state.clone();
            let service = StreamableHttpService::new(
                move || Ok(app_state_for_service.clone()),
                LocalSessionManager::default().into(),
                http_config,
            );
            let requests_per_sec = app_state
                .config
                .server
                .rate_limit_per_sec
                .clamp(1, u32::MAX as u64);
            let quota = Quota::per_second(
                NonZeroU32::new(requests_per_sec as u32)
                    .expect("requests_per_sec is clamped to >=1"),
            );
            let rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>> =
                Arc::new(RateLimiter::direct(quota));
            let mut router = Router::new()
                .nest_service("/mcp", service)
                .layer(RequestBodyLimitLayer::new(
                    app_state.config.server.max_request_body_bytes.max(1024),
                ))
                .layer(ConcurrencyLimitLayer::new(
                    app_state.config.server.max_concurrent_requests.max(1),
                ))
                .layer(middleware::from_fn(
                    move |request: axum::extract::Request, next: middleware::Next| {
                        let rate_limiter = Arc::clone(&rate_limiter);
                        async move {
                            if rate_limiter.check().is_err() {
                                return (
                                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                                    "rate limit exceeded",
                                )
                                    .into_response();
                            }
                            next.run(request).await
                        }
                    },
                ));

            if let Some(token) = app_state.config.server.auth_token.clone() {
                let token = token.trim().to_string();
                if token.is_empty() {
                    return Err(anyhow::anyhow!(
                        "CRATEDEX__SERVER__AUTH_TOKEN is set but empty. \
Provide a non-empty bearer token or unset the variable."
                    )
                    .into());
                }
                let expected_header = format!("Bearer {}", token);
                // Pre-compute hash for constant-time comparison (prevents timing side-channel).
                use sha2::Digest;
                let expected_hash = sha2::Sha256::digest(expected_header.as_bytes());
                router = router.layer(ValidateRequestHeaderLayer::custom(
                    move |request: &mut axum::http::Request<_>| {
                        let is_authorized = request
                            .headers()
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .map(|v| sha2::Sha256::digest(v.as_bytes()) == expected_hash)
                            .unwrap_or(false);
                        if is_authorized {
                            return Ok(());
                        }

                        let mut response =
                            axum::response::Response::new(axum::body::Body::from("Unauthorized"));
                        *response.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
                        Err(response)
                    },
                ));
            }

            let tcp_listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(tcp_listener, router)
                .with_graceful_shutdown(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    cancellation.cancel();
                })
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
    }

    Ok(())
}

async fn watch_for_changes(
    diagnostics_cache: Arc<Mutex<Vec<serde_json::Value>>>,
    workspace_root: PathBuf,
    debounce_ms: u64,
    project_path: PathBuf,
    progress: Arc<Mutex<ProjectProgress>>,
    mut abort_rx: tokio::sync::watch::Receiver<()>,
) -> notify::Result<()> {
    use notify::EventKind;

    let (tx, mut rx) = mpsc::channel(100);

    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(event) => {
                if matches!(event.kind, EventKind::Modify(_))
                    && event
                        .paths
                        .iter()
                        .any(|p| p.extension().is_some_and(|e| e == "rs"))
                    && let Err(e) = tx.try_send(())
                {
                    error!("Failed to send file change notification: {}", e);
                }
            }
            Err(e) => error!("File watcher error: {}", e),
        })?;

    watcher.watch(&workspace_root, RecursiveMode::Recursive)?;
    info!(
        "Watching for file changes in '{}'...",
        workspace_root.display()
    );

    let debounce_duration = Duration::from_millis(debounce_ms);

    loop {
        tokio::select! {
            _ = abort_rx.changed() => {
                info!("File watcher aborted for '{}'", project_path.display());
                break;
            }
            event = rx.recv() => {
                if event.is_none() {
                    break;
                }
                // Debounce: wait, then drain any events that arrived during the sleep.
                tokio::time::sleep(debounce_duration).await;
                while rx.try_recv().is_ok() {}

                info!("Running diagnostics after file change...");
                diagnostics::run_check_on_startup(
                    Arc::clone(&diagnostics_cache),
                    &project_path,
                    Arc::clone(&progress),
                )
                .await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::engine::docs;
    use rusqlite::params;

    const INSERT_SQL: &str = r#"INSERT INTO "docs" (crate_name, crate_version, package_id_hash, item_name, kind, text) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#;

    /// Helper: create an in-memory DB with docs table + FTS5.
    fn setup_db() -> Db {
        let db = Db::open(":memory:").unwrap();
        {
            let conn = db.conn.lock().unwrap();
            docs::ensure_docs_table_and_fts(&conn).unwrap();
        }
        db
    }

    fn ready_progress() -> Arc<Mutex<ProjectProgress>> {
        let mut progress = ProjectProgress::new();
        progress.phase = Phase::Ready;
        Arc::new(Mutex::new(progress))
    }

    // ───── merge_cargo_warnings tests ─────

    #[test]
    fn merge_cargo_warnings_deduplicates_and_counts() {
        let mut progress = ProjectProgress::new();

        progress.merge_cargo_warnings(vec![
            ("cargo check".into(), "warning: unused import".into()),
            ("cargo check".into(), "warning: unused import".into()),
            ("cargo check".into(), "error: type mismatch".into()),
            // same message but different source — should NOT collapse
            ("cargo rustdoc".into(), "warning: unused import".into()),
        ]);

        assert_eq!(progress.cargo_warnings.len(), 3);

        let unused = progress
            .cargo_warnings
            .iter()
            .find(|w| w.message == "warning: unused import" && w.source == "cargo check")
            .unwrap();
        assert_eq!(unused.count, 2);
    }

    // ───── to_json tests ─────

    #[test]
    fn to_json_estimated_remaining_only_during_indexing() {
        let mut progress = ProjectProgress::new();
        progress.estimated_total_secs = Some(100.0);
        progress.new_dependencies = 10;

        // During Metadata phase, eta_secs should be absent
        progress.phase = Phase::Metadata;
        let json = progress.to_json();
        assert!(json.get("eta_secs").is_none());
        assert_eq!(json["status"], "queued");

        // During Check phase, eta_secs should be absent
        progress.phase = Phase::Check;
        let json = progress.to_json();
        assert!(json.get("eta_secs").is_none());
        assert_eq!(json["status"], "queued");

        // During Indexing phase with remaining work, eta_secs should be a number
        progress.phase = Phase::Indexing;
        let json = progress.to_json();
        assert!(json["eta_secs"].is_number());
        assert_eq!(json["status"], "indexing");

        // When all crates are done but still in Indexing phase (Phase 2), should be null
        progress.processed_count = 8;
        progress.failed_count = 2;
        let json = progress.to_json();
        assert!(json.get("eta_secs").is_none() || json["eta_secs"].is_null());
        assert_eq!(json["total"], 10);
    }

    /// Helper to extract the JSON text from a CallToolResult's first content item.
    fn extract_json_text(result: &CallToolResult) -> &str {
        result.content[0]
            .as_text()
            .expect("expected text content")
            .text
            .as_str()
    }

    /// Helper to extract the items array from a paginated envelope.
    fn extract_items(result: &CallToolResult) -> Vec<serde_json::Value> {
        let envelope: serde_json::Value = serde_json::from_str(extract_json_text(result)).unwrap();
        envelope["items"]
            .as_array()
            .expect("expected items array in envelope")
            .clone()
    }

    /// Helper to extract the full paginated envelope.
    fn extract_envelope(result: &CallToolResult) -> serde_json::Value {
        serde_json::from_str(extract_json_text(result)).unwrap()
    }

    /// Helper to insert a doc row synchronously.
    fn insert_doc(
        db: &Db,
        crate_name: &str,
        version: &str,
        pkg_hash: &str,
        item_name: &str,
        kind: &str,
        text: &str,
    ) {
        let conn = db.conn.lock().unwrap();
        conn.execute(
            INSERT_SQL,
            params![crate_name, version, pkg_hash, item_name, kind, text],
        )
        .unwrap();
    }

    // ───── search_docs tests ─────

    #[tokio::test]
    async fn search_docs_global_returns_all_results() {
        let db = setup_db();
        insert_doc(
            &db,
            "tokio",
            "1.0.0",
            "tokio_hash",
            "spawn",
            "Function",
            "Spawns a new async task on the runtime.",
        );
        insert_doc(
            &db,
            "serde",
            "1.0.0",
            "serde_hash",
            "Serialize",
            "Trait",
            "Serialization framework for Rust.",
        );

        let app_state = AppState::new(Config::default(), db, resources::new_log_buffer(10));
        let result = app_state
            .search_docs(SearchDocsRequest {
                project_path: None,
                query: "task".to_string(),
                filter_crates: None,
                filter_kinds: None,
                mode: QueryMode::Auto,
                max_depth: None,
                limit: DEFAULT_PAGE_LIMIT,
                offset: 0,
            })
            .await
            .unwrap();

        let items = extract_items(&result);
        assert!(
            !items.is_empty(),
            "Global search should return results for 'task'"
        );
        assert!(
            items.iter().any(|r| r["crate"] == "tokio"),
            "Should find tokio for 'task'"
        );
    }

    #[tokio::test]
    async fn search_docs_with_crate_filter_narrows_results() {
        let db = setup_db();
        insert_doc(
            &db,
            "tokio",
            "1.0.0",
            "tokio_hash",
            "spawn",
            "Function",
            "Spawns a new async task.",
        );
        insert_doc(
            &db,
            "serde",
            "1.0.0",
            "serde_hash",
            "deserialize",
            "Function",
            "Deserialize data from a task format.",
        );

        let app_state = AppState::new(Config::default(), db, resources::new_log_buffer(10));
        let result = app_state
            .search_docs(SearchDocsRequest {
                project_path: None,
                query: "task".to_string(),
                filter_crates: Some(vec!["serde".to_string()]),
                filter_kinds: None,
                mode: QueryMode::Auto,
                max_depth: None,
                limit: DEFAULT_PAGE_LIMIT,
                offset: 0,
            })
            .await
            .unwrap();

        let items = extract_items(&result);
        for r in &items {
            assert_eq!(
                r["crate"], "serde",
                "Crate filter should restrict results to serde only"
            );
        }
    }

    #[tokio::test]
    async fn search_docs_enforces_configured_result_cap() {
        let db = setup_db();
        for i in 0..8 {
            insert_doc(
                &db,
                &format!("crate{}", i),
                "1.0.0",
                &format!("hash{}", i),
                &format!("item{}", i),
                "Function",
                &format!("Does important stuff number {}", i),
            );
        }

        let mut cfg = Config::default();
        cfg.server.max_search_results = 3;
        let app_state = AppState::new(cfg, db, resources::new_log_buffer(10));

        let first_page = app_state
            .search_docs(SearchDocsRequest {
                project_path: None,
                query: "stuff".to_string(),
                filter_crates: None,
                filter_kinds: None,
                mode: QueryMode::Auto,
                max_depth: None,
                limit: 50,
                offset: 0,
            })
            .await
            .unwrap();
        let envelope = extract_envelope(&first_page);
        assert_eq!(envelope["total"], 3);
        assert_eq!(envelope["count"], 3);
        assert_eq!(envelope["has_more"], false);

        let after_cap = app_state
            .search_docs(SearchDocsRequest {
                project_path: None,
                query: "stuff".to_string(),
                filter_crates: None,
                filter_kinds: None,
                mode: QueryMode::Auto,
                max_depth: None,
                limit: 50,
                offset: 3,
            })
            .await
            .unwrap();
        let envelope = extract_envelope(&after_cap);
        assert_eq!(envelope["total"], 3);
        assert_eq!(envelope["count"], 0);
        assert_eq!(envelope["has_more"], false);
    }

    /// Build a minimal cargo metadata with two packages (alpha, beta) where
    /// alpha is the workspace member and depends on beta.
    fn synthetic_metadata() -> cargo_metadata::Metadata {
        serde_json::from_value(serde_json::json!({
            "packages": [
                {
                    "name": "alpha",
                    "version": "0.1.0",
                    "id": "alpha 0.1.0 (path+file:///test/alpha)",
                    "source": null,
                    "dependencies": [],
                    "targets": [{"kind": ["lib"], "crate_types": ["lib"], "name": "alpha", "src_path": "/test/alpha/src/lib.rs", "edition": "2021", "doc": true, "doctest": true, "test": true}],
                    "features": {},
                    "manifest_path": "/test/alpha/Cargo.toml",
                    "metadata": null,
                    "publish": null,
                    "authors": [],
                    "categories": [],
                    "keywords": [],
                    "readme": null,
                    "repository": null,
                    "homepage": null,
                    "documentation": null,
                    "edition": "2021",
                    "links": null,
                    "default_run": null,
                    "rust_version": null,
                    "license": null,
                    "license_file": null,
                    "description": null
                },
                {
                    "name": "beta",
                    "version": "2.0.0",
                    "id": "beta 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "dependencies": [],
                    "targets": [{"kind": ["lib"], "crate_types": ["lib"], "name": "beta", "src_path": "/test/beta/src/lib.rs", "edition": "2021", "doc": true, "doctest": true, "test": true}],
                    "features": {},
                    "manifest_path": "/test/beta/Cargo.toml",
                    "metadata": null,
                    "publish": null,
                    "authors": [],
                    "categories": [],
                    "keywords": [],
                    "readme": null,
                    "repository": null,
                    "homepage": null,
                    "documentation": null,
                    "edition": "2021",
                    "links": null,
                    "default_run": null,
                    "rust_version": null,
                    "license": null,
                    "license_file": null,
                    "description": null
                }
            ],
            "workspace_members": ["alpha 0.1.0 (path+file:///test/alpha)"],
            "workspace_default_members": ["alpha 0.1.0 (path+file:///test/alpha)"],
            "resolve": {
                "nodes": [
                    {
                        "id": "alpha 0.1.0 (path+file:///test/alpha)",
                        "dependencies": ["beta 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
                        "deps": [{"name": "beta", "pkg": "beta 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)", "dep_kinds": [{"kind": null, "target": null}]}],
                        "features": []
                    },
                    {
                        "id": "beta 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
                        "dependencies": [],
                        "deps": [],
                        "features": []
                    }
                ],
                "root": "alpha 0.1.0 (path+file:///test/alpha)"
            },
            "target_directory": "/test/alpha/target",
            "version": 1,
            "workspace_root": "/test/alpha"
        }))
        .expect("synthetic metadata should deserialize")
    }

    /// Build metadata with two workspace members in non-deterministic package order.
    fn synthetic_metadata_multi_workspace_unsorted() -> cargo_metadata::Metadata {
        serde_json::from_value(serde_json::json!({
            "packages": [
                {
                    "name": "beta",
                    "version": "0.1.0",
                    "id": "beta 0.1.0 (path+file:///test/beta)",
                    "source": null,
                    "dependencies": [],
                    "targets": [{"kind": ["lib"], "crate_types": ["lib"], "name": "beta", "src_path": "/test/beta/src/lib.rs", "edition": "2021", "doc": true, "doctest": true, "test": true}],
                    "features": {},
                    "manifest_path": "/test/beta/Cargo.toml",
                    "metadata": null,
                    "publish": null,
                    "authors": [],
                    "categories": [],
                    "keywords": [],
                    "readme": null,
                    "repository": null,
                    "homepage": null,
                    "documentation": null,
                    "edition": "2021",
                    "links": null,
                    "default_run": null,
                    "rust_version": null,
                    "license": null,
                    "license_file": null,
                    "description": null
                },
                {
                    "name": "alpha",
                    "version": "0.1.0",
                    "id": "alpha 0.1.0 (path+file:///test/alpha)",
                    "source": null,
                    "dependencies": [],
                    "targets": [{"kind": ["lib"], "crate_types": ["lib"], "name": "alpha", "src_path": "/test/alpha/src/lib.rs", "edition": "2021", "doc": true, "doctest": true, "test": true}],
                    "features": {},
                    "manifest_path": "/test/alpha/Cargo.toml",
                    "metadata": null,
                    "publish": null,
                    "authors": [],
                    "categories": [],
                    "keywords": [],
                    "readme": null,
                    "repository": null,
                    "homepage": null,
                    "documentation": null,
                    "edition": "2021",
                    "links": null,
                    "default_run": null,
                    "rust_version": null,
                    "license": null,
                    "license_file": null,
                    "description": null
                }
            ],
            "workspace_members": [
                "alpha 0.1.0 (path+file:///test/alpha)",
                "beta 0.1.0 (path+file:///test/beta)"
            ],
            "workspace_default_members": [
                "alpha 0.1.0 (path+file:///test/alpha)",
                "beta 0.1.0 (path+file:///test/beta)"
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "alpha 0.1.0 (path+file:///test/alpha)",
                        "dependencies": [],
                        "deps": [],
                        "features": []
                    },
                    {
                        "id": "beta 0.1.0 (path+file:///test/beta)",
                        "dependencies": [],
                        "deps": [],
                        "features": []
                    }
                ],
                "root": null
            },
            "target_directory": "/test/target",
            "version": 1,
            "workspace_root": "/test"
        }))
        .expect("synthetic unsorted metadata should deserialize")
    }

    fn minimal_metadata() -> cargo_metadata::Metadata {
        serde_json::from_value(serde_json::json!({
            "packages": [],
            "workspace_members": [],
            "workspace_default_members": [],
            "resolve": null,
            "target_directory": "/tmp/target",
            "version": 1,
            "workspace_root": "/tmp"
        }))
        .expect("minimal metadata should deserialize")
    }

    #[tokio::test]
    async fn list_projects_are_sorted_for_stable_pagination() {
        let db = setup_db();
        let app_state = AppState::new(Config::default(), db, resources::new_log_buffer(10));

        let root = tempfile::tempdir().unwrap();
        let alpha_path = root.path().join("alpha_project");
        let zeta_path = root.path().join("zeta_project");
        std::fs::create_dir_all(&alpha_path).unwrap();
        std::fs::create_dir_all(&zeta_path).unwrap();
        let alpha_path = alpha_path.canonicalize().unwrap();
        let zeta_path = zeta_path.canonicalize().unwrap();

        let state_alpha = ProjectState {
            project_path: alpha_path.clone(),
            metadata: Arc::new(minimal_metadata()),
            diagnostics: Arc::new(Mutex::new(Vec::new())),
            outdated_dependencies: Arc::new(Mutex::new(serde_json::Value::Null)),
            security_advisories: Arc::new(Mutex::new(serde_json::Value::Null)),
            progress: ready_progress(),
            abort: None,
        };
        let state_zeta = ProjectState {
            project_path: zeta_path.clone(),
            metadata: Arc::new(minimal_metadata()),
            diagnostics: Arc::new(Mutex::new(Vec::new())),
            outdated_dependencies: Arc::new(Mutex::new(serde_json::Value::Null)),
            security_advisories: Arc::new(Mutex::new(serde_json::Value::Null)),
            progress: ready_progress(),
            abort: None,
        };

        {
            let mut registry = app_state.projects.write().await;
            registry.insert(zeta_path, Arc::new(Mutex::new(state_zeta)));
            registry.insert(alpha_path, Arc::new(Mutex::new(state_alpha)));
        }

        let result = app_state.list_projects(10, 0).await.unwrap();
        let items = extract_items(&result);
        let paths: Vec<String> = items
            .iter()
            .map(|item| item["project_path"].as_str().unwrap().to_string())
            .collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(
            paths, sorted,
            "project list should be sorted for stable pagination"
        );
    }

    #[tokio::test]
    async fn list_crates_are_sorted_for_stable_pagination() {
        let db = setup_db();
        let app_state = AppState::new(Config::default(), db, resources::new_log_buffer(10));
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().canonicalize().unwrap();

        let meta = synthetic_metadata_multi_workspace_unsorted();
        let project_state = ProjectState {
            project_path: canonical.clone(),
            metadata: Arc::new(meta),
            diagnostics: Arc::new(Mutex::new(Vec::new())),
            outdated_dependencies: Arc::new(Mutex::new(serde_json::Value::Null)),
            security_advisories: Arc::new(Mutex::new(serde_json::Value::Null)),
            progress: ready_progress(),
            abort: None,
        };
        {
            let mut registry = app_state.projects.write().await;
            registry.insert(canonical.clone(), Arc::new(Mutex::new(project_state)));
        }

        let result = app_state.list_crates(&canonical, 10, 0).await.unwrap();
        let items = extract_items(&result);
        let names: Vec<String> = items
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[tokio::test]
    async fn search_docs_scoped_filters_by_project_deps() {
        let meta = synthetic_metadata();
        let project_crates = docs::project_crate_scopes(&meta).unwrap();

        // Verify the synthetic metadata produces the expected crate list
        let names: Vec<&str> = project_crates.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"alpha"),
            "alpha should be in project crates"
        );
        assert!(names.contains(&"beta"), "beta should be in project crates");

        let alpha_hash = project_crates
            .iter()
            .find(|c| c.name == "alpha")
            .map(|c| c.package_id_hash.clone())
            .expect("alpha should have a package hash");
        let beta_hash = project_crates
            .iter()
            .find(|c| c.name == "beta")
            .map(|c| c.package_id_hash.clone())
            .expect("beta should have a package hash");

        let db = setup_db();
        // In-tree: alpha and beta
        insert_doc(
            &db,
            "alpha",
            "0.1.0",
            &alpha_hash,
            "do_stuff",
            "Function",
            "Does important stuff for the project.",
        );
        insert_doc(
            &db,
            "beta",
            "2.0.0",
            &beta_hash,
            "BetaTrait",
            "Trait",
            "A trait that does important stuff.",
        );
        // Out-of-tree: gamma (NOT in the metadata resolve graph)
        insert_doc(
            &db,
            "gamma",
            "3.0.0",
            "gamma_hash",
            "GammaTrait",
            "Trait",
            "A trait that does important stuff too.",
        );

        let app_state = AppState::new(Config::default(), db, resources::new_log_buffer(10));

        // Use a temp dir as the project path (must exist for canonicalize)
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().canonicalize().unwrap();

        let project_state = ProjectState {
            project_path: canonical.clone(),
            metadata: Arc::new(meta),
            diagnostics: Arc::new(Mutex::new(Vec::new())),
            outdated_dependencies: Arc::new(Mutex::new(serde_json::Value::Null)),
            security_advisories: Arc::new(Mutex::new(serde_json::Value::Null)),
            progress: ready_progress(),
            abort: None,
        };
        {
            let mut registry = app_state.projects.write().await;
            registry.insert(canonical.clone(), Arc::new(Mutex::new(project_state)));
        }

        // Scoped search — should only include alpha and beta, NOT gamma
        let result = app_state
            .search_docs(SearchDocsRequest {
                project_path: Some(&canonical),
                query: "stuff".to_string(),
                filter_crates: None,
                filter_kinds: None,
                mode: QueryMode::Auto,
                max_depth: None,
                limit: DEFAULT_PAGE_LIMIT,
                offset: 0,
            })
            .await
            .unwrap();

        let items = extract_items(&result);
        assert!(
            !items.is_empty(),
            "Scoped search should find results for 'stuff'"
        );

        let result_crates: Vec<&str> = items.iter().map(|r| r["crate"].as_str().unwrap()).collect();
        assert!(
            result_crates.contains(&"alpha") || result_crates.contains(&"beta"),
            "Should find in-tree crates"
        );
        assert!(
            !result_crates.contains(&"gamma"),
            "Scoped search must not include crates outside the dependency tree"
        );
    }

    #[tokio::test]
    async fn get_diagnostics_per_project_isolation() {
        let db = setup_db();
        let app_state = AppState::new(Config::default(), db, resources::new_log_buffer(10));

        // Create two temp dirs as "projects"
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let path_a = dir_a.path().canonicalize().unwrap();
        let path_b = dir_b.path().canonicalize().unwrap();

        let state_a = ProjectState {
            project_path: path_a.clone(),
            metadata: Arc::new(minimal_metadata()),
            diagnostics: Arc::new(Mutex::new(vec![serde_json::json!({
                "reason": "compiler-message",
                "message": {
                    "level": "error",
                    "message": "error in project A",
                    "spans": [{"file_name": "src/lib.rs", "line_start": 10, "is_primary": true}],
                    "children": [],
                    "code": null,
                    "rendered": "error: error in project A\n"
                }
            })])),
            outdated_dependencies: Arc::new(Mutex::new(serde_json::json!({"dep_a": "outdated"}))),
            security_advisories: Arc::new(Mutex::new(serde_json::Value::Null)),
            progress: ready_progress(),
            abort: None,
        };
        let state_b = ProjectState {
            project_path: path_b.clone(),
            metadata: Arc::new(minimal_metadata()),
            diagnostics: Arc::new(Mutex::new(vec![serde_json::json!({
                "reason": "compiler-message",
                "message": {
                    "level": "warning",
                    "message": "warning in project B",
                    "spans": [{"file_name": "src/main.rs", "line_start": 5, "is_primary": true}],
                    "children": [],
                    "code": {"code": "unused_variables", "explanation": null},
                    "rendered": "warning: warning in project B\n"
                }
            })])),
            outdated_dependencies: Arc::new(Mutex::new(serde_json::Value::Null)),
            security_advisories: Arc::new(Mutex::new(serde_json::json!({"vuln": "found"}))),
            progress: ready_progress(),
            abort: None,
        };

        {
            let mut registry = app_state.projects.write().await;
            registry.insert(path_a.clone(), Arc::new(Mutex::new(state_a)));
            registry.insert(path_b.clone(), Arc::new(Mutex::new(state_b)));
        }

        // Verify project A diagnostics
        let result_a = app_state.get_diagnostics(&path_a).await.unwrap();
        let report_a: serde_json::Value =
            serde_json::from_str(extract_json_text(&result_a)).unwrap();
        assert_eq!(report_a["build"]["errors"], 1);
        assert_eq!(report_a["build"]["warnings"], 0);
        assert!(report_a["index"]["status"].is_string());

        // Verify project B diagnostics (different from A)
        let result_b = app_state.get_diagnostics(&path_b).await.unwrap();
        let report_b: serde_json::Value =
            serde_json::from_str(extract_json_text(&result_b)).unwrap();
        assert_eq!(report_b["build"]["errors"], 0);
        assert_eq!(report_b["build"]["warnings"], 1);
        assert!(report_b["index"]["status"].is_string());
    }

    // ───── FTS query building tests ─────

    #[test]
    fn search_tokens_splits_rust_symbols_and_preserves_underscores() {
        assert_eq!(search_tokens("tokio::spawn"), vec!["tokio", "spawn"]);
        assert_eq!(search_tokens("my_func"), vec!["my_func"]);
        assert_eq!(search_tokens("a<T, U>"), vec!["a", "t", "u"]);
    }

    #[test]
    fn build_fts_query_auto_mode_switches_on_colons() {
        // `::` triggers symbol tokenization — the key heuristic
        let q = build_fts_query("tokio::spawn", QueryMode::Auto).unwrap();
        assert_eq!(q, "tokio* AND spawn*");

        // no `::` stays as text — same tokenization, different detection path
        let q = build_fts_query("async runtime", QueryMode::Auto).unwrap();
        assert_eq!(q, "async* AND runtime*");
    }

    #[test]
    fn build_fts_query_rejects_unsearchable_input() {
        assert!(build_fts_query("", QueryMode::Auto).is_err());
        assert!(build_fts_query(":: ::", QueryMode::Auto).is_err());
    }
}
