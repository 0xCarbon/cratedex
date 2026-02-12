//! The documentation engine is responsible for generating and indexing docs.

use crate::db::Db;
use crate::engine::command::{
    extract_cargo_warnings, new_nightly_cargo_command, run_with_timeout, stderr_preview,
};
use crate::engine::server::ProjectProgress;
use crate::error::{AppError, AppResult};
use cargo_metadata::{Metadata, Node, Package, PackageId, camino::Utf8Path};
use rusqlite::{Connection, params};
use rustdoc_types::{Crate, ItemEnum};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, info_span, warn};

const RUSTDOC_WORKSPACE_TIMEOUT: Duration = Duration::from_mins(10);

struct DocItem {
    crate_name: String,
    crate_version: String,
    package_id_hash: String,
    item_name: String,
    kind: String,
    text: String,
}

pub fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

/// Ensure the shared docs table, FTS5 virtual table, and sync triggers exist.
pub fn ensure_docs_table_and_fts(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS "docs" (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            crate_name TEXT NOT NULL,
            crate_version TEXT NOT NULL,
            package_id_hash TEXT NOT NULL,
            item_name TEXT NOT NULL,
            kind TEXT NOT NULL,
            text TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS "idx_docs_crate_version"
        ON "docs" (crate_name, crate_version);

        CREATE INDEX IF NOT EXISTS "idx_docs_pkg_hash"
        ON "docs" (package_id_hash);

        CREATE VIRTUAL TABLE IF NOT EXISTS "docs_fts" USING fts5(
            crate_name, item_name, text,
            content='docs', content_rowid='id',
            tokenize='porter unicode61'
        );

        -- Auto-sync triggers
        CREATE TRIGGER IF NOT EXISTS docs_ai AFTER INSERT ON docs BEGIN
            INSERT INTO docs_fts(rowid, crate_name, item_name, text)
            VALUES (new.id, new.crate_name, new.item_name, new.text);
        END;

        CREATE TRIGGER IF NOT EXISTS docs_ad AFTER DELETE ON docs BEGIN
            INSERT INTO docs_fts(docs_fts, rowid, crate_name, item_name, text)
            VALUES ('delete', old.id, old.crate_name, old.item_name, old.text);
        END;

        CREATE TRIGGER IF NOT EXISTS docs_au AFTER UPDATE ON docs BEGIN
            INSERT INTO docs_fts(docs_fts, rowid, crate_name, item_name, text)
            VALUES ('delete', old.id, old.crate_name, old.item_name, old.text);
            INSERT INTO docs_fts(rowid, crate_name, item_name, text)
            VALUES (new.id, new.crate_name, new.item_name, new.text);
        END;
        "#,
    )?;
    Ok(())
}

pub fn is_crate_indexed(conn: &Connection, package_id_hash: &str) -> AppResult<bool> {
    let mut stmt =
        conn.prepare_cached(r#"SELECT 1 FROM "docs" WHERE package_id_hash = ?1 LIMIT 1"#)?;
    let exists = stmt.exists(params![package_id_hash])?;
    Ok(exists)
}

/// For each package in the workspace, ensures that a rustdoc JSON file
/// is generated, cached, and indexed.
///
/// Phase 1a generates docs only for workspace crates (with a longer timeout).
/// Phase 1b checks the cache for dependency crates (no `cargo rustdoc` invocation).
/// Phase 2 runs concurrently via an mpsc channel, indexing packages into the DB
/// as soon as their cached JSON becomes available.
pub async fn ensure_docs_are_cached_and_indexed(
    metadata: Arc<Metadata>,
    db: Arc<Db>,
    project_path: PathBuf,
    progress: Arc<Mutex<ProjectProgress>>,
) -> AppResult<()> {
    let IndexPackages {
        packages: index_packages,
        ..
    } = collect_index_packages(&metadata)?;
    let span = info_span!("index_docs", packages = %index_packages.len());
    let _enter = span.enter();

    let cache_dir = get_doc_cache_dir()?;

    // Ensure schema on startup
    db.call(|conn| {
        ensure_docs_table_and_fts(conn)?;
        Ok(())
    })
    .await?;
    info!("Docs table ready.");

    let workspace_members: HashSet<PackageId> =
        metadata.workspace_members.iter().cloned().collect();
    let (workspace_packages, dep_packages): (Vec<_>, Vec<_>) = index_packages
        .into_iter()
        .partition(|pkg| workspace_members.contains(&pkg.id));

    info!(
        "Phase 1: {} workspace crates, {} dependency crates",
        workspace_packages.len(),
        dep_packages.len()
    );

    let target_dir = metadata.target_directory.clone();

    // Pipeline: Phase 1 produces (Package, PathBuf), Phase 2 consumes and indexes.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(Package, PathBuf)>(32);

    // Phase 2 consumer — indexes packages into the DB as they arrive.
    let db_p2 = Arc::clone(&db);
    let progress_p2 = Arc::clone(&progress);
    let phase2 = tokio::spawn(async move {
        let mut indexed_count = 0usize;
        while let Some((package, json_path)) = rx.recv().await {
            {
                let mut pg = progress_p2.lock().await;
                pg.current_crate = Some(format!("{} {}", package.name, package.version));
            }
            let pkg_hash = package_id_hash(&package);

            let already_indexed = {
                let hash = pkg_hash.clone();
                match db_p2.call(move |conn| is_crate_indexed(conn, &hash)).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            "Failed to check index for {} {}: {}",
                            package.name, package.version, e
                        );
                        false
                    }
                }
            };

            if already_indexed {
                debug!(
                    "docs: {} {} (already in global index)",
                    package.name, package.version
                );
                indexed_count += 1;
                continue;
            }

            let should_idx = match should_index_package(&json_path, &pkg_hash) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Failed to check meta for {} {}: {}",
                        package.name, package.version, e
                    );
                    true
                }
            };

            if should_idx {
                let version = package.version.to_string();
                if let Err(e) = index_rustdoc_json(&json_path, &db_p2, &version, &pkg_hash).await {
                    warn!(
                        "Failed to index {} {}: {}",
                        package.name, package.version, e
                    );
                    continue;
                }
                if let Err(e) = write_doc_meta(&json_path, &package, &pkg_hash) {
                    warn!(
                        "Failed to write doc meta for {} {}: {}",
                        package.name, package.version, e
                    );
                }
                info!("docs: {} {} (indexed)", package.name, package.version);
                indexed_count += 1;
            } else {
                debug!("docs: {} {} (up-to-date)", package.name, package.version);
                indexed_count += 1;
            }
        }
        indexed_count
    });

    // Phase 1a: Generate docs for workspace crates (longer timeout).
    info!(
        "Phase 1a: Generating docs for {} workspace crates...",
        workspace_packages.len()
    );
    for package in &workspace_packages {
        {
            let mut pg = progress.lock().await;
            pg.current_crate = Some(format!("{} {}", package.name, package.version));
        }
        let cached_path = cache_dir.join(doc_cache_filename(package));

        if !cached_path.exists()
            && let Err(e) = generate_docs_for_package(
                package,
                target_dir.as_path(),
                &project_path,
                Arc::clone(&progress),
                RUSTDOC_WORKSPACE_TIMEOUT,
            )
            .await
        {
            let message = e.to_string();
            let tail = message
                .split_once(": ")
                .map(|(_, t)| t)
                .unwrap_or(message.as_str());
            let reason = tail
                .lines()
                .find(|l| l.trim().starts_with("error:"))
                .or_else(|| tail.lines().next())
                .unwrap_or("unknown generation failure")
                .trim()
                .to_string();
            warn!(
                "Workspace crate {} {} failed: {}",
                package.name, package.version, reason
            );
            let mut pg = progress.lock().await;
            *pg.failure_categories.entry(reason).or_insert(0) += 1;
            pg.failed_count += 1;
            continue;
        }

        if cached_path.exists() {
            if tx.send((package.clone(), cached_path)).await.is_err() {
                warn!("Phase 2 consumer dropped; aborting Phase 1a");
                break;
            }
            let mut pg = progress.lock().await;
            pg.processed_count += 1;
        } else {
            let mut pg = progress.lock().await;
            *pg.failure_categories
                .entry("json not found after generation".to_string())
                .or_insert(0) += 1;
            pg.failed_count += 1;
        }
    }

    // Phase 1b: Check cache for dependency crates (no doc generation).
    info!(
        "Phase 1b: Checking cache for {} dependency crates...",
        dep_packages.len()
    );
    let mut dep_skipped = 0usize;
    for package in &dep_packages {
        let cached_path = cache_dir.join(doc_cache_filename(package));
        if cached_path.exists() {
            if tx.send((package.clone(), cached_path)).await.is_err() {
                warn!("Phase 2 consumer dropped; aborting Phase 1b");
                break;
            }
            let mut pg = progress.lock().await;
            pg.processed_count += 1;
        } else {
            dep_skipped += 1;
        }
    }
    if dep_skipped > 0 {
        debug!(
            "Skipped {} dependency crates without cached docs",
            dep_skipped
        );
    }

    // Close the channel so Phase 2 can finish.
    drop(tx);

    // Wait for Phase 2 to complete.
    let indexed_count = match phase2.await {
        Ok(count) => count,
        Err(e) => {
            warn!("Phase 2 indexing task failed: {e}");
            0
        }
    };

    {
        let mut pg = progress.lock().await;
        pg.indexed_count = indexed_count;
        for (reason, count) in &pg.failure_categories {
            warn!("{count} crates failed doc generation: {reason}");
        }
        pg.current_crate = None;
    }
    info!(
        "All documentation is now cached and indexed ({} packages).",
        indexed_count
    );
    Ok(())
}

async fn index_rustdoc_json(
    path: &Path,
    db: &Db,
    crate_version: &str,
    package_id_hash: &str,
) -> AppResult<()> {
    let span = info_span!("index_rustdoc", path = %path.display());
    let _enter = span.enter();
    info!("Parsing and indexing rustdoc JSON at: {}", path.display());

    let json_path = path.to_path_buf();
    let version = crate_version.to_string();
    let pkg_hash = package_id_hash.to_string();

    let items = tokio::task::spawn_blocking(move || {
        let contents = std::fs::read_to_string(&json_path)?;
        let mut deserializer = serde_json::Deserializer::from_str(&contents);
        deserializer.disable_recursion_limit();
        let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
        let krate: Crate = serde::Deserialize::deserialize(deserializer)?;
        let crate_name = krate
            .paths
            .get(&krate.root)
            .and_then(|p| p.path.first().cloned())
            .unwrap_or_default();

        let items: Vec<DocItem> = krate
            .index
            .values()
            .filter_map(|item| extract_doc_item(&crate_name, &version, &pkg_hash, item))
            .collect();
        Ok::<_, AppError>(items)
    })
    .await??;

    if items.is_empty() {
        info!("No documentable items found in {}.", path.display());
        return Ok(());
    }

    let item_count = items.len();
    let pkg_hash_for_tx = package_id_hash.to_string();
    db.call_mut(move |conn| {
        let tx = conn.transaction()?;
        tx.execute(
            r#"DELETE FROM "docs" WHERE package_id_hash = ?1"#,
            params![pkg_hash_for_tx],
        )?;

        {
            let mut insert_stmt = tx.prepare_cached(
                r#"INSERT INTO "docs" (crate_name, crate_version, package_id_hash, item_name, kind, text) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            )?;
            for item in &items {
                insert_stmt.execute(params![
                    item.crate_name,
                    item.crate_version,
                    item.package_id_hash,
                    item.item_name,
                    item.kind,
                    item.text,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    })
    .await?;

    info!(
        "Successfully indexed {} documents from {}.",
        item_count,
        path.display()
    );
    Ok(())
}

fn extract_doc_item(
    crate_name: &str,
    crate_version: &str,
    package_id_hash: &str,
    item: &rustdoc_types::Item,
) -> Option<DocItem> {
    let kind = match &item.inner {
        ItemEnum::Module(_) => "Module",
        ItemEnum::Function(_) => "Function",
        ItemEnum::Struct(_) => "Struct",
        ItemEnum::Enum(_) => "Enum",
        ItemEnum::Trait(_) => "Trait",
        ItemEnum::Macro(_) => "Macro",
        _ => return None,
    };

    let docs = item.docs.as_deref().unwrap_or("");
    let item_name = item.name.clone()?;

    Some(DocItem {
        crate_name: crate_name.to_string(),
        crate_version: crate_version.to_string(),
        package_id_hash: package_id_hash.to_string(),
        item_name,
        kind: kind.to_string(),
        text: docs.to_string(),
    })
}

/// Crate identity plus dependency depth (0 = workspace member, 1 = direct dep, …).
pub struct ProjectCrate {
    pub name: String,
    pub version: String,
    pub package_id_hash: String,
    pub depth: u32,
}

/// Returns package identity info for the project's dependency tree.
pub fn project_crate_scopes(metadata: &Metadata) -> AppResult<Vec<ProjectCrate>> {
    let IndexPackages { packages, depths } = collect_index_packages(metadata)?;
    Ok(packages
        .iter()
        .map(|pkg| {
            let depth = depths.get(&pkg.id).copied().unwrap_or(u32::MAX);
            ProjectCrate {
                name: normalize_crate_name(&pkg.name),
                version: pkg.version.to_string(),
                package_id_hash: package_id_hash(pkg),
                depth,
            }
        })
        .collect())
}

async fn generate_docs_for_package(
    package: &Package,
    target_dir: &Utf8Path,
    project_path: &Path,
    progress: Arc<Mutex<ProjectProgress>>,
    timeout: Duration,
) -> AppResult<()> {
    let package_spec = if package.source.is_some() {
        format!("{}@{}", package.name, package.version)
    } else {
        package.name.to_string()
    };
    let mut cmd = new_nightly_cargo_command(project_path);
    cmd.arg("rustdoc")
        .arg("--package")
        .arg(package_spec)
        .arg("--")
        .arg("-Z")
        .arg("unstable-options")
        .arg("--output-format")
        .arg("json");

    let output = run_with_timeout(&mut cmd, timeout, "`cargo rustdoc`").await?;
    let cargo_warnings = extract_cargo_warnings(&output.stderr, "cargo rustdoc");
    if !cargo_warnings.is_empty() {
        progress.lock().await.merge_cargo_warnings(cargo_warnings);
    }

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "`cargo rustdoc` failed for {} {}: {}",
            package.name,
            package.version,
            stderr_preview(&output.stderr, 5)
        )
        .into());
    }

    let source_path = target_dir
        .join("doc")
        .join(format!("{}.json", normalize_crate_name(&package.name)));
    let dest_path = get_doc_cache_dir()?.join(doc_cache_filename(package));

    if !source_path.exists() {
        return Err(anyhow::anyhow!(
            "`cargo rustdoc` succeeded for {} {}, but JSON was not found at {}",
            package.name,
            package.version,
            source_path
        )
        .into());
    }

    // rename can fail across filesystem boundaries, fall back to copy+remove.
    if fs::rename(&source_path, &dest_path).is_err() {
        fs::copy(&source_path, &dest_path)?;
        let _ = fs::remove_file(&source_path);
    }
    info!(
        "Successfully cached docs for {} {}",
        package.name, package.version
    );
    Ok(())
}

/// Gets the path to the main cache directory.
pub fn get_cache_dir() -> AppResult<PathBuf> {
    let cache_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?
        .join(".cratedex");

    if !cache_dir.exists() {
        fs::create_dir_all(&cache_dir)?;
    }

    Ok(cache_dir)
}

fn get_doc_cache_dir() -> AppResult<PathBuf> {
    let cache_dir = get_cache_dir()?.join("cache").join("doc-json");

    if !cache_dir.exists() {
        fs::create_dir_all(&cache_dir)?;
    }

    Ok(cache_dir)
}

fn get_doc_meta_path(json_path: &Path) -> PathBuf {
    json_path.with_extension("json.meta")
}

fn doc_cache_filename(package: &Package) -> String {
    format!(
        "{}-{}-{}.json",
        package.name,
        package.version,
        package_id_hash(package)
    )
}

pub fn package_id_hash(package: &Package) -> String {
    let mut hasher = Sha256::new();
    hasher.update(package.id.repr.as_bytes());
    let bytes = hasher.finalize();
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for b in bytes {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

fn should_index_package(cached_json: &Path, pkg_hash: &str) -> AppResult<bool> {
    let meta_path = get_doc_meta_path(cached_json);
    if !meta_path.exists() {
        return Ok(true);
    }
    let buf = std::fs::read_to_string(&meta_path)?;
    let val: serde_json::Value = match serde_json::from_str(&buf) {
        Ok(val) => val,
        Err(err) => {
            warn!(
                "Failed to parse doc meta at {}: {}. Reindexing.",
                meta_path.display(),
                err
            );
            return Ok(true);
        }
    };
    let recorded_pkg_hash = val
        .get("package_id_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Ok(recorded_pkg_hash != pkg_hash)
}

fn write_doc_meta(cached_json: &Path, package: &Package, pkg_hash: &str) -> AppResult<()> {
    let meta_path = get_doc_meta_path(cached_json);
    let data = serde_json::json!({
        "crate_name": package.name,
        "crate_version": package.version.to_string(),
        "package_id": package.id.repr.as_str(),
        "package_id_hash": pkg_hash,
    });
    std::fs::write(meta_path, serde_json::to_vec_pretty(&data)?)?;
    Ok(())
}

/// Packages reachable from workspace members, together with their BFS depth.
pub struct IndexPackages {
    pub packages: Vec<Package>,
    /// Depth 0 = workspace member, 1 = direct dependency, 2+ = transitive.
    pub depths: HashMap<PackageId, u32>,
}

/// Collect all packages reachable from workspace members (workspace + transitive deps).
/// Also computes the minimum BFS depth for each package.
pub fn collect_index_packages(metadata: &Metadata) -> AppResult<IndexPackages> {
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Cargo metadata resolve graph is missing"))?;

    let mut node_by_id: HashMap<PackageId, &Node> = HashMap::new();
    for node in &resolve.nodes {
        node_by_id.insert(node.id.clone(), node);
    }

    let mut queue: VecDeque<(PackageId, u32)> = metadata
        .workspace_members
        .iter()
        .map(|id| (id.clone(), 0))
        .collect();
    let mut depths: HashMap<PackageId, u32> = HashMap::new();

    while let Some((id, depth)) = queue.pop_front() {
        if depths.contains_key(&id) {
            continue; // Already visited at same or shorter depth (BFS guarantee).
        }
        depths.insert(id.clone(), depth);

        let node = node_by_id
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("Missing resolve node for package {}", id))?;
        let deps: Vec<PackageId> = if !node.deps.is_empty() {
            node.deps.iter().map(|dep| dep.pkg.clone()).collect()
        } else {
            node.dependencies.to_vec()
        };
        for dep_id in deps {
            if !depths.contains_key(&dep_id) {
                queue.push_back((dep_id, depth + 1));
            }
        }
    }

    let packages = metadata
        .packages
        .iter()
        .filter(|pkg| depths.contains_key(&pkg.id))
        .cloned()
        .collect::<Vec<_>>();

    Ok(IndexPackages { packages, depths })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSERT_SQL: &str = r#"INSERT INTO "docs" (crate_name, crate_version, package_id_hash, item_name, kind, text) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#;

    /// Helper: create an in-memory DB with docs table + FTS5.
    fn setup_db() -> Db {
        let db = Db::open(":memory:").unwrap();
        // Use blocking_lock since we're setting up synchronously in tests
        {
            let conn = db.conn.lock().unwrap();
            ensure_docs_table_and_fts(&conn).unwrap();
        }
        db
    }

    #[test]
    fn normalize_crate_name_replaces_hyphens() {
        assert_eq!(normalize_crate_name("my-crate"), "my_crate");
        assert_eq!(
            normalize_crate_name("already_underscore"),
            "already_underscore"
        );
        assert_eq!(normalize_crate_name("a-b-c"), "a_b_c");
        assert_eq!(normalize_crate_name("simple"), "simple");
    }

    #[tokio::test]
    async fn fts_index_works_end_to_end() -> AppResult<()> {
        let db = setup_db();

        db.call(|conn| {
            conn.execute(
                INSERT_SQL,
                params![
                    "tokio",
                    "1.0.0",
                    "tokio_hash",
                    "spawn",
                    "Function",
                    "Spawns a task on the runtime.",
                ],
            )?;
            conn.execute(
                INSERT_SQL,
                params![
                    "serde",
                    "1.0.0",
                    "serde_hash",
                    "Serialize",
                    "Trait",
                    "Serialization framework for Rust.",
                ],
            )?;
            Ok(())
        })
        .await?;

        let (crate_name, item_name, score) = db
            .call(|conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT d.crate_name, d.item_name,
                           bm25(docs_fts, 1.0, 2.0, 1.0) as score
                    FROM docs_fts
                    JOIN docs d ON d.id = docs_fts.rowid
                    WHERE docs_fts MATCH ?1
                    ORDER BY score ASC
                    LIMIT 10
                    "#,
                )?;
                let result = stmt.query_row(params!["task"], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, f64>(2)?,
                    ))
                })?;
                Ok(result)
            })
            .await?;

        assert_eq!(crate_name, "tokio");
        assert_eq!(item_name, "spawn");
        // bm25 returns negative scores (lower = better match)
        assert!(score < 0.0);
        Ok(())
    }

    #[tokio::test]
    async fn is_crate_indexed_returns_false_for_new_crate() {
        let db = setup_db();
        let result = db
            .call(|conn| is_crate_indexed(conn, "nonexistent"))
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn is_crate_indexed_returns_true_after_insert() {
        let db = setup_db();
        db.call(|conn| {
            conn.execute(
                INSERT_SQL,
                params![
                    "tokio",
                    "1.0.0",
                    "tokio_hash",
                    "spawn",
                    "Function",
                    "Spawns a task.",
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let result = db
            .call(|conn| is_crate_indexed(conn, "tokio_hash"))
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn dedup_is_package_specific() {
        let db = setup_db();
        db.call(|conn| {
            conn.execute(
                INSERT_SQL,
                params![
                    "tokio",
                    "1.0.0",
                    "tokio_hash",
                    "spawn",
                    "Function",
                    "Spawns a task.",
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        // Different hash → not indexed
        let r1 = db
            .call(|conn| is_crate_indexed(conn, "tokio_hash_v2"))
            .await
            .unwrap();
        assert!(!r1);
        // Same hash → indexed
        let r2 = db
            .call(|conn| is_crate_indexed(conn, "tokio_hash"))
            .await
            .unwrap();
        assert!(r2);
    }

    #[tokio::test]
    async fn project_crate_scopes_includes_workspace_and_deps() {
        // Dogfood: use cratedex's own metadata
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let meta = cargo_metadata::MetadataCommand::new()
            .manifest_path(manifest)
            .exec()
            .expect("cargo metadata should succeed on cratedex itself");

        let crates = project_crate_scopes(&meta).unwrap();
        assert!(!crates.is_empty(), "Should have at least one crate");

        let names: Vec<&str> = crates.iter().map(|c| c.name.as_str()).collect();
        // cratedex itself should be present
        assert!(
            names.contains(&"cratedex"),
            "Should include cratedex itself"
        );
        // Well-known direct dependencies should be present
        assert!(names.contains(&"serde"), "serde should be a transitive dep");
        assert!(names.contains(&"tokio"), "tokio should be a direct dep");
    }
}
