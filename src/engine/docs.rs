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
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, info_span, warn};

const RUSTDOC_TIMEOUT: Duration = Duration::from_mins(3);

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

    // Drop legacy Turso FTS index if it exists (migration)
    conn.execute_batch(r#"DROP INDEX IF EXISTS "idx_docs_fts";"#)?;

    ensure_docs_schema(conn)?;
    Ok(())
}

fn ensure_docs_schema(conn: &Connection) -> AppResult<()> {
    let has_pkg_hash = {
        let mut stmt = conn.prepare(r#"PRAGMA table_info("docs")"#)?;
        stmt.query_map([], |row| {
            let name: String = row.get(1)?;
            Ok(name)
        })?
        .any(|r| r.map(|n| n == "package_id_hash").unwrap_or(false))
    };

    if !has_pkg_hash {
        conn.execute_batch(
            r#"
            ALTER TABLE "docs" ADD COLUMN package_id_hash TEXT NOT NULL DEFAULT '';
            CREATE INDEX IF NOT EXISTS "idx_docs_pkg_hash" ON "docs" (package_id_hash);
            DELETE FROM "docs";
            "#,
        )?;
    }

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
pub async fn ensure_docs_are_cached_and_indexed(
    metadata: Arc<Metadata>,
    db: Arc<Db>,
    project_path: PathBuf,
    progress: Arc<Mutex<ProjectProgress>>,
) -> AppResult<()> {
    let index_packages = collect_index_packages(&metadata)?;
    let span = info_span!("index_docs", packages = %index_packages.len());
    let _enter = span.enter();
    info!("Checking for cached rustdoc JSON for all dependencies...");

    let cache_dir = get_doc_cache_dir()?;

    // Ensure schema on startup
    db.call(|conn| {
        ensure_docs_table_and_fts(conn)?;
        Ok(())
    })
    .await?;
    info!("Docs table ready.");

    let mut json_paths: Vec<(Package, PathBuf)> = Vec::new();
    let target_dir = metadata.target_directory.clone();

    for package in &index_packages {
        {
            let mut progress_guard = progress.lock().await;
            progress_guard.current_crate = Some(format!("{} {}", package.name, package.version));
        }
        let cached_path = cache_dir.join(doc_cache_filename(package));

        if !cached_path.exists()
            && let Err(e) = generate_docs_for_package(
                package,
                target_dir.as_path(),
                &project_path,
                Arc::clone(&progress),
            )
            .await
        {
            let message = e.to_string();
            let reason = message
                .split_once(": ")
                .map(|(_, tail)| tail)
                .unwrap_or(message.as_str())
                .lines()
                .next()
                .unwrap_or("unknown generation failure")
                .to_string();
            let mut progress_guard = progress.lock().await;
            *progress_guard
                .failure_categories
                .entry(reason)
                .or_insert(0) += 1;
            progress_guard.failed_count += 1;
            continue;
        }

        if cached_path.exists() {
            json_paths.push((package.clone(), cached_path));
            let mut progress_guard = progress.lock().await;
            progress_guard.processed_count += 1;
        } else {
            let mut progress_guard = progress.lock().await;
            *progress_guard
                .failure_categories
                .entry("json not found after generation".to_string())
                .or_insert(0) += 1;
            progress_guard.failed_count += 1;
        }
    }

    {
        let progress_guard = progress.lock().await;
        for (reason, count) in &progress_guard.failure_categories {
            warn!("{count} crates failed doc generation: {reason}");
        }
    }

    info!(
        "Phase 1 done: {} cached JSON files. Starting Phase 2 (DB indexing)...",
        json_paths.len()
    );

    for (i, (package, json_path)) in json_paths.iter().enumerate() {
        {
            let mut progress_guard = progress.lock().await;
            progress_guard.current_crate = Some(format!("{} {}", package.name, package.version));
        }
        let pkg_hash = package_id_hash(package);

        info!(
            "Phase 2 [{}/{}]: checking {} {}...",
            i + 1,
            json_paths.len(),
            package.name,
            package.version
        );

        let already_indexed = {
            let hash = pkg_hash.clone();
            db.call(move |conn| is_crate_indexed(conn, &hash)).await?
        };

        if already_indexed {
            info!(
                "docs: {} {} (already in global index)",
                package.name, package.version
            );
            continue;
        }

        let should_idx = should_index_package(json_path, &pkg_hash)?;
        if should_idx {
            let version = package.version.to_string();
            index_rustdoc_json(json_path, &db, &version, &pkg_hash).await?;
            if let Err(e) = write_doc_meta(json_path, package, &pkg_hash) {
                warn!(
                    "Failed to write doc meta for {} {}: {}",
                    package.name, package.version, e
                );
            }
            info!("docs: {} {} (indexed)", package.name, package.version);
        } else {
            info!("docs: {} {} (up-to-date)", package.name, package.version);
        }
    }

    {
        let mut progress_guard = progress.lock().await;
        progress_guard.current_crate = None;
    }
    info!("All documentation is now cached and indexed.");
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

    let docs = item.docs.as_ref().filter(|d| !d.is_empty())?;
    let item_name = item.name.clone()?;

    Some(DocItem {
        crate_name: crate_name.to_string(),
        crate_version: crate_version.to_string(),
        package_id_hash: package_id_hash.to_string(),
        item_name,
        kind: kind.to_string(),
        text: docs.clone(),
    })
}

/// Returns the crate names and versions for packages reachable
/// from a project's workspace members.
pub struct ProjectCrate {
    pub name: String,
    pub version: String,
    pub package_id_hash: String,
}

/// Returns package identity info for the project's dependency tree.
pub fn project_crate_scopes(metadata: &Metadata) -> AppResult<Vec<ProjectCrate>> {
    let packages = collect_index_packages(metadata)?;
    Ok(packages
        .iter()
        .map(|pkg| ProjectCrate {
            name: normalize_crate_name(&pkg.name),
            version: pkg.version.to_string(),
            package_id_hash: package_id_hash(pkg),
        })
        .collect())
}

async fn generate_docs_for_package(
    package: &Package,
    target_dir: &Utf8Path,
    project_path: &Path,
    progress: Arc<Mutex<ProjectProgress>>,
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

    let output = run_with_timeout(&mut cmd, RUSTDOC_TIMEOUT, "`cargo rustdoc`").await?;
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
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
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

/// Collect all packages reachable from workspace members (workspace + transitive deps).
pub fn collect_index_packages(metadata: &Metadata) -> AppResult<Vec<Package>> {
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Cargo metadata resolve graph is missing"))?;

    let mut node_by_id: HashMap<PackageId, &Node> = HashMap::new();
    for node in &resolve.nodes {
        node_by_id.insert(node.id.clone(), node);
    }

    let mut queue: std::collections::VecDeque<PackageId> =
        metadata.workspace_members.iter().cloned().collect();
    let mut reachable: HashSet<PackageId> = HashSet::new();

    while let Some(id) = queue.pop_front() {
        if !reachable.insert(id.clone()) {
            continue;
        }
        let node = node_by_id
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("Missing resolve node for package {}", id))?;
        let deps: Vec<PackageId> = if !node.deps.is_empty() {
            node.deps.iter().map(|dep| dep.pkg.clone()).collect()
        } else {
            node.dependencies.to_vec()
        };
        for dep_id in deps {
            if !reachable.contains(&dep_id) {
                queue.push_back(dep_id);
            }
        }
    }

    let packages = metadata
        .packages
        .iter()
        .filter(|pkg| reachable.contains(&pkg.id))
        .cloned()
        .collect::<Vec<_>>();

    Ok(packages)
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
