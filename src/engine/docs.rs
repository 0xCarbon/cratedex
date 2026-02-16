//! The documentation engine is responsible for generating and indexing docs.

use crate::db::Db;
use crate::engine::command::{
    extract_cargo_warnings, new_nightly_cargo_command, run_with_timeout, stderr_preview,
};
use crate::engine::server::ProjectProgress;
use crate::error::{AppError, AppResult};
use cargo_metadata::{Metadata, Node, Package, PackageId, camino::Utf8Path};
use rusqlite::{Connection, params};
use rustdoc_types::{
    Abi, AssocItemConstraint, AssocItemConstraintKind, Crate, DynTrait, FunctionPointer,
    GenericArg, GenericArgs, GenericBound, GenericParamDef, GenericParamDefKind, ItemEnum,
    Path as RustdocPath, PolyTrait, Term, TraitBoundModifier, Type, WherePredicate,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, info_span, warn};

const RUSTDOC_WORKSPACE_TIMEOUT: Duration = Duration::from_mins(10);
const TYPE_RENDER_MAX_DEPTH: usize = 20;

struct DocItem {
    crate_name: String,
    crate_version: String,
    package_id_hash: String,
    item_name: String,
    kind: String,
    parent_name: Option<String>,
    parent_kind: Option<String>,
    trait_name: Option<String>,
    signature: String,
    text: String,
}

pub fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

/// Ensure the shared docs table, FTS5 virtual table, and sync triggers exist.
/// Detects old schema (missing `signature` column) and recreates tables.
pub fn ensure_docs_table_and_fts(conn: &Connection) -> AppResult<()> {
    // Schema version detection: if the docs table exists but lacks `signature`, drop everything.
    let needs_recreate = {
        let mut stmt = conn
            .prepare("SELECT count(*) FROM pragma_table_info('docs') WHERE name = 'signature'")?;
        let has_signature: i64 = stmt.query_row([], |row| row.get(0))?;
        // Table exists (has rows in pragma) but no signature column → old schema.
        let mut stmt2 = conn.prepare("SELECT count(*) FROM pragma_table_info('docs')")?;
        let col_count: i64 = stmt2.query_row([], |row| row.get(0))?;
        col_count > 0 && has_signature == 0
    };

    if needs_recreate {
        info!("Detected old docs schema, recreating tables...");
        conn.execute_batch(
            r"
            DROP TRIGGER IF EXISTS docs_ai;
            DROP TRIGGER IF EXISTS docs_ad;
            DROP TRIGGER IF EXISTS docs_au;
            DROP TABLE IF EXISTS docs_fts;
            DROP TABLE IF EXISTS docs;
            ",
        )?;
    }

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS "docs" (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            crate_name TEXT NOT NULL,
            crate_version TEXT NOT NULL,
            package_id_hash TEXT NOT NULL,
            item_name TEXT NOT NULL,
            kind TEXT NOT NULL,
            parent_name TEXT,
            parent_kind TEXT,
            trait_name TEXT,
            signature TEXT NOT NULL DEFAULT '',
            text TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS "idx_docs_crate_version"
        ON "docs" (crate_name, crate_version);

        CREATE INDEX IF NOT EXISTS "idx_docs_pkg_hash"
        ON "docs" (package_id_hash);

        CREATE INDEX IF NOT EXISTS "idx_docs_parent"
        ON "docs" (parent_name);

        CREATE VIRTUAL TABLE IF NOT EXISTS "docs_fts" USING fts5(
            crate_name, item_name, parent_name, signature, text,
            content='docs', content_rowid='id',
            tokenize='porter unicode61'
        );

        -- Auto-sync triggers (COALESCE for NULLable FTS5 columns)
        CREATE TRIGGER IF NOT EXISTS docs_ai AFTER INSERT ON docs BEGIN
            INSERT INTO docs_fts(rowid, crate_name, item_name, parent_name, signature, text)
            VALUES (new.id, new.crate_name, new.item_name,
                    COALESCE(new.parent_name, ''), new.signature, new.text);
        END;

        CREATE TRIGGER IF NOT EXISTS docs_ad AFTER DELETE ON docs BEGIN
            INSERT INTO docs_fts(docs_fts, rowid, crate_name, item_name, parent_name, signature, text)
            VALUES ('delete', old.id, old.crate_name, old.item_name,
                    COALESCE(old.parent_name, ''), old.signature, old.text);
        END;

        CREATE TRIGGER IF NOT EXISTS docs_au AFTER UPDATE ON docs BEGIN
            INSERT INTO docs_fts(docs_fts, rowid, crate_name, item_name, parent_name, signature, text)
            VALUES ('delete', old.id, old.crate_name, old.item_name,
                    COALESCE(old.parent_name, ''), old.signature, old.text);
            INSERT INTO docs_fts(rowid, crate_name, item_name, parent_name, signature, text)
            VALUES (new.id, new.crate_name, new.item_name,
                    COALESCE(new.parent_name, ''), new.signature, new.text);
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

        let items = extract_all_items(&crate_name, &version, &pkg_hash, &krate);
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
                r#"INSERT INTO "docs" (crate_name, crate_version, package_id_hash, item_name, kind, parent_name, parent_kind, trait_name, signature, text) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            )?;
            for item in &items {
                insert_stmt.execute(params![
                    item.crate_name,
                    item.crate_version,
                    item.package_id_hash,
                    item.item_name,
                    item.kind,
                    item.parent_name,
                    item.parent_kind,
                    item.trait_name,
                    item.signature,
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

// ───── Type renderer ─────

fn render_type(ty: &Type, depth: usize) -> String {
    if depth > TYPE_RENDER_MAX_DEPTH {
        return "...".to_string();
    }
    let d = depth + 1;
    match ty {
        Type::ResolvedPath(path) => render_path(path, d),
        Type::Generic(name) => name.clone(),
        Type::Primitive(name) => name.clone(),
        Type::BorrowedRef {
            lifetime,
            is_mutable,
            type_,
        } => {
            let mut s = String::from("&");
            if let Some(lt) = lifetime {
                write!(s, "{lt} ").unwrap();
            }
            if *is_mutable {
                s.push_str("mut ");
            }
            s.push_str(&render_type(type_, d));
            s
        }
        Type::Tuple(types) => {
            if types.is_empty() {
                "()".to_string()
            } else {
                let inner: Vec<_> = types.iter().map(|t| render_type(t, d)).collect();
                format!("({})", inner.join(", "))
            }
        }
        Type::Slice(inner) => format!("[{}]", render_type(inner, d)),
        Type::Array { type_, len } => format!("[{}; {len}]", render_type(type_, d)),
        Type::RawPointer { is_mutable, type_ } => {
            if *is_mutable {
                format!("*mut {}", render_type(type_, d))
            } else {
                format!("*const {}", render_type(type_, d))
            }
        }
        Type::DynTrait(dyn_trait) => render_dyn_trait(dyn_trait, d),
        Type::ImplTrait(bounds) => {
            let rendered = render_generic_bounds(bounds, d);
            format!("impl {rendered}")
        }
        Type::FunctionPointer(fp) => render_fn_pointer(fp, d),
        Type::QualifiedPath {
            name,
            args,
            self_type,
            trait_,
        } => {
            let self_rendered = render_type(self_type, d);
            let mut s = if let Some(trait_path) = trait_ {
                format!(
                    "<{self_rendered} as {}>::{name}",
                    render_path(trait_path, d)
                )
            } else {
                format!("{self_rendered}::{name}")
            };
            if let Some(ga) = args {
                s.push_str(&render_generic_args(ga, d));
            }
            s
        }
        Type::Infer => "_".to_string(),
        Type::Pat {
            type_,
            __pat_unstable_do_not_use,
        } => {
            format!("{} is {}", render_type(type_, d), __pat_unstable_do_not_use)
        }
    }
}

fn render_path(path: &RustdocPath, depth: usize) -> String {
    let name = path.path.rsplit("::").next().unwrap_or(&path.path);
    let mut s = name.to_string();
    if let Some(args) = &path.args {
        s.push_str(&render_generic_args(args, depth));
    }
    s
}

fn render_generic_args(args: &GenericArgs, depth: usize) -> String {
    match args {
        GenericArgs::AngleBracketed { args, constraints } => {
            let mut parts: Vec<String> = Vec::new();
            for arg in args {
                parts.push(render_generic_arg(arg, depth));
            }
            for constraint in constraints {
                parts.push(render_assoc_item_constraint(constraint, depth));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!("<{}>", parts.join(", "))
            }
        }
        GenericArgs::Parenthesized { inputs, output } => {
            let inputs_str: Vec<_> = inputs.iter().map(|t| render_type(t, depth)).collect();
            let mut s = format!("({})", inputs_str.join(", "));
            if let Some(out) = output {
                write!(s, " -> {}", render_type(out, depth)).unwrap();
            }
            s
        }
        GenericArgs::ReturnTypeNotation => "(..)".to_string(),
    }
}

fn render_generic_arg(arg: &GenericArg, depth: usize) -> String {
    match arg {
        GenericArg::Lifetime(lt) => lt.clone(),
        GenericArg::Type(ty) => render_type(ty, depth),
        GenericArg::Const(c) => c.expr.clone(),
        GenericArg::Infer => "_".to_string(),
    }
}

fn render_assoc_item_constraint(c: &AssocItemConstraint, depth: usize) -> String {
    let mut s = c.name.clone();
    if let Some(args) = &c.args {
        s.push_str(&render_generic_args(args, depth));
    }
    match &c.binding {
        AssocItemConstraintKind::Equality(term) => {
            write!(s, " = {}", render_term(term, depth)).unwrap();
        }
        AssocItemConstraintKind::Constraint(bounds) => {
            write!(s, ": {}", render_generic_bounds(bounds, depth)).unwrap();
        }
    }
    s
}

fn render_term(term: &Term, depth: usize) -> String {
    match term {
        Term::Type(ty) => render_type(ty, depth),
        Term::Constant(c) => c.expr.clone(),
    }
}

fn render_generic_bounds(bounds: &[GenericBound], depth: usize) -> String {
    bounds
        .iter()
        .map(|b| render_generic_bound(b, depth))
        .collect::<Vec<_>>()
        .join(" + ")
}

fn render_generic_bound(bound: &GenericBound, depth: usize) -> String {
    match bound {
        GenericBound::TraitBound {
            trait_,
            generic_params,
            modifier,
        } => {
            let mut s = String::new();
            if !generic_params.is_empty() {
                write!(
                    s,
                    "for<{}> ",
                    render_generic_param_defs(generic_params, depth)
                )
                .unwrap();
            }
            match modifier {
                TraitBoundModifier::Maybe => s.push('?'),
                TraitBoundModifier::MaybeConst => s.push_str("~const "),
                TraitBoundModifier::None => {}
            }
            s.push_str(&render_path(trait_, depth));
            s
        }
        GenericBound::Outlives(lt) => lt.clone(),
        GenericBound::Use(args) => {
            let parts: Vec<_> = args
                .iter()
                .map(|a| match a {
                    rustdoc_types::PreciseCapturingArg::Lifetime(lt) => lt.clone(),
                    rustdoc_types::PreciseCapturingArg::Param(p) => p.clone(),
                })
                .collect();
            format!("use<{}>", parts.join(", "))
        }
    }
}

fn render_generic_param_defs(params: &[GenericParamDef], depth: usize) -> String {
    params
        .iter()
        .map(|p| render_generic_param_def(p, depth))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_generic_param_def(param: &GenericParamDef, depth: usize) -> String {
    match &param.kind {
        GenericParamDefKind::Lifetime { outlives } => {
            let mut s = param.name.clone();
            if !outlives.is_empty() {
                write!(s, ": {}", outlives.join(" + ")).unwrap();
            }
            s
        }
        GenericParamDefKind::Type {
            bounds,
            default,
            is_synthetic: _,
        } => {
            let mut s = param.name.clone();
            if !bounds.is_empty() {
                write!(s, ": {}", render_generic_bounds(bounds, depth)).unwrap();
            }
            if let Some(def) = default {
                write!(s, " = {}", render_type(def, depth)).unwrap();
            }
            s
        }
        GenericParamDefKind::Const { type_, default } => {
            let mut s = format!("const {}: {}", param.name, render_type(type_, depth));
            if let Some(def) = default {
                write!(s, " = {def}").unwrap();
            }
            s
        }
    }
}

fn render_where_predicates(predicates: &[WherePredicate], depth: usize) -> String {
    if predicates.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = predicates
        .iter()
        .map(|p| match p {
            WherePredicate::BoundPredicate {
                type_,
                bounds,
                generic_params,
            } => {
                let mut s = String::new();
                if !generic_params.is_empty() {
                    write!(
                        s,
                        "for<{}> ",
                        render_generic_param_defs(generic_params, depth)
                    )
                    .unwrap();
                }
                write!(
                    s,
                    "{}: {}",
                    render_type(type_, depth),
                    render_generic_bounds(bounds, depth)
                )
                .unwrap();
                s
            }
            WherePredicate::LifetimePredicate { lifetime, outlives } => {
                if outlives.is_empty() {
                    lifetime.clone()
                } else {
                    format!("{lifetime}: {}", outlives.join(" + "))
                }
            }
            WherePredicate::EqPredicate { lhs, rhs } => {
                format!("{} = {}", render_type(lhs, depth), render_term(rhs, depth))
            }
        })
        .collect();
    format!(" where {}", parts.join(", "))
}

fn render_dyn_trait(dyn_trait: &DynTrait, depth: usize) -> String {
    let mut parts: Vec<String> = dyn_trait
        .traits
        .iter()
        .map(|pt| render_poly_trait(pt, depth))
        .collect();
    if let Some(lt) = &dyn_trait.lifetime {
        parts.push(lt.clone());
    }
    format!("dyn {}", parts.join(" + "))
}

fn render_poly_trait(pt: &PolyTrait, depth: usize) -> String {
    let mut s = String::new();
    if !pt.generic_params.is_empty() {
        write!(
            s,
            "for<{}> ",
            render_generic_param_defs(&pt.generic_params, depth)
        )
        .unwrap();
    }
    s.push_str(&render_path(&pt.trait_, depth));
    s
}

fn render_fn_pointer(fp: &FunctionPointer, depth: usize) -> String {
    let mut s = String::new();
    if !fp.generic_params.is_empty() {
        write!(
            s,
            "for<{}> ",
            render_generic_param_defs(&fp.generic_params, depth)
        )
        .unwrap();
    }
    s.push_str(&render_abi(&fp.header.abi));
    if fp.header.is_unsafe {
        s.push_str("unsafe ");
    }
    s.push_str("fn(");
    let params: Vec<_> = fp
        .sig
        .inputs
        .iter()
        .map(|(name, ty)| {
            if name.is_empty() || name == "_" {
                render_type(ty, depth)
            } else {
                format!("{name}: {}", render_type(ty, depth))
            }
        })
        .collect();
    s.push_str(&params.join(", "));
    if fp.sig.is_c_variadic {
        if !params.is_empty() {
            s.push_str(", ");
        }
        s.push_str("...");
    }
    s.push(')');
    if let Some(out) = &fp.sig.output {
        write!(s, " -> {}", render_type(out, depth)).unwrap();
    }
    s
}

fn render_abi(abi: &Abi) -> String {
    match abi {
        Abi::Rust => String::new(),
        Abi::C { unwind } => {
            if *unwind {
                "extern \"C-unwind\" ".into()
            } else {
                "extern \"C\" ".into()
            }
        }
        Abi::System { unwind } => {
            if *unwind {
                "extern \"system-unwind\" ".into()
            } else {
                "extern \"system\" ".into()
            }
        }
        Abi::Cdecl { .. } => "extern \"cdecl\" ".into(),
        Abi::Stdcall { .. } => "extern \"stdcall\" ".into(),
        Abi::Fastcall { .. } => "extern \"fastcall\" ".into(),
        Abi::Aapcs { .. } => "extern \"aapcs\" ".into(),
        Abi::Win64 { .. } => "extern \"win64\" ".into(),
        Abi::SysV64 { .. } => "extern \"sysv64\" ".into(),
        Abi::Other(name) => format!("extern \"{name}\" "),
    }
}

// ───── Signature renderers ─────

fn render_function_signature(func: &rustdoc_types::Function, name: &str) -> String {
    let mut s = String::new();
    if func.header.is_const {
        s.push_str("const ");
    }
    if func.header.is_async {
        s.push_str("async ");
    }
    if func.header.is_unsafe {
        s.push_str("unsafe ");
    }
    s.push_str(&render_abi(&func.header.abi));
    s.push_str("fn ");
    s.push_str(name);

    // Generic params (filter out synthetic ones like impl Trait desugaring)
    let real_params: Vec<_> = func
        .generics
        .params
        .iter()
        .filter(|p| {
            !matches!(
                &p.kind,
                GenericParamDefKind::Type {
                    is_synthetic: true,
                    ..
                }
            )
        })
        .collect();
    if !real_params.is_empty() {
        write!(
            s,
            "<{}>",
            real_params
                .iter()
                .map(|p| render_generic_param_def(p, 0))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
    }

    // Parameters
    s.push('(');
    let params: Vec<_> = func
        .sig
        .inputs
        .iter()
        .map(|(name, ty)| {
            let ty_str = render_type(ty, 0);
            if name == "self" {
                // Render self params naturally
                match ty {
                    Type::BorrowedRef {
                        lifetime,
                        is_mutable,
                        ..
                    } => {
                        let mut self_str = String::from("&");
                        if let Some(lt) = lifetime {
                            write!(self_str, "{lt} ").unwrap();
                        }
                        if *is_mutable {
                            self_str.push_str("mut ");
                        }
                        self_str.push_str("self");
                        self_str
                    }
                    _ => {
                        if ty_str == "Self" {
                            "self".to_string()
                        } else {
                            format!("self: {ty_str}")
                        }
                    }
                }
            } else if name.is_empty() || name == "_" {
                format!("_: {ty_str}")
            } else {
                format!("{name}: {ty_str}")
            }
        })
        .collect();
    s.push_str(&params.join(", "));
    if func.sig.is_c_variadic {
        if !params.is_empty() {
            s.push_str(", ");
        }
        s.push_str("...");
    }
    s.push(')');

    // Return type
    if let Some(output) = &func.sig.output {
        write!(s, " -> {}", render_type(output, 0)).unwrap();
    }

    // Where clause
    s.push_str(&render_where_predicates(&func.generics.where_predicates, 0));

    s
}

fn render_struct_signature(strct: &rustdoc_types::Struct, name: &str) -> String {
    let mut s = String::from("struct ");
    s.push_str(name);
    let real_params: Vec<_> = strct
        .generics
        .params
        .iter()
        .filter(|p| {
            !matches!(
                &p.kind,
                GenericParamDefKind::Type {
                    is_synthetic: true,
                    ..
                }
            )
        })
        .collect();
    if !real_params.is_empty() {
        write!(
            s,
            "<{}>",
            real_params
                .iter()
                .map(|p| render_generic_param_def(p, 0))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
    }
    s.push_str(&render_where_predicates(
        &strct.generics.where_predicates,
        0,
    ));
    s
}

fn render_enum_signature(enm: &rustdoc_types::Enum, name: &str) -> String {
    let mut s = String::from("enum ");
    s.push_str(name);
    let real_params: Vec<_> = enm
        .generics
        .params
        .iter()
        .filter(|p| {
            !matches!(
                &p.kind,
                GenericParamDefKind::Type {
                    is_synthetic: true,
                    ..
                }
            )
        })
        .collect();
    if !real_params.is_empty() {
        write!(
            s,
            "<{}>",
            real_params
                .iter()
                .map(|p| render_generic_param_def(p, 0))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
    }
    s.push_str(&render_where_predicates(&enm.generics.where_predicates, 0));
    s
}

fn render_trait_signature(trt: &rustdoc_types::Trait, name: &str) -> String {
    let mut s = String::new();
    if trt.is_unsafe {
        s.push_str("unsafe ");
    }
    if trt.is_auto {
        s.push_str("auto ");
    }
    s.push_str("trait ");
    s.push_str(name);
    let real_params: Vec<_> = trt
        .generics
        .params
        .iter()
        .filter(|p| {
            !matches!(
                &p.kind,
                GenericParamDefKind::Type {
                    is_synthetic: true,
                    ..
                }
            )
        })
        .collect();
    if !real_params.is_empty() {
        write!(
            s,
            "<{}>",
            real_params
                .iter()
                .map(|p| render_generic_param_def(p, 0))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
    }
    if !trt.bounds.is_empty() {
        write!(s, ": {}", render_generic_bounds(&trt.bounds, 0)).unwrap();
    }
    s.push_str(&render_where_predicates(&trt.generics.where_predicates, 0));
    s
}

fn render_type_alias_signature(ta: &rustdoc_types::TypeAlias, name: &str) -> String {
    let mut s = String::from("type ");
    s.push_str(name);
    let real_params: Vec<_> = ta
        .generics
        .params
        .iter()
        .filter(|p| {
            !matches!(
                &p.kind,
                GenericParamDefKind::Type {
                    is_synthetic: true,
                    ..
                }
            )
        })
        .collect();
    if !real_params.is_empty() {
        write!(
            s,
            "<{}>",
            real_params
                .iter()
                .map(|p| render_generic_param_def(p, 0))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
    }
    write!(s, " = {}", render_type(&ta.type_, 0)).unwrap();
    s.push_str(&render_where_predicates(&ta.generics.where_predicates, 0));
    s
}

fn render_constant_signature(type_: &Type, const_: &rustdoc_types::Constant, name: &str) -> String {
    let mut s = format!("const {name}: {}", render_type(type_, 0));
    if let Some(val) = &const_.value {
        write!(s, " = {val}").unwrap();
    }
    s
}

fn render_static_signature(stat: &rustdoc_types::Static, name: &str) -> String {
    let mut_kw = if stat.is_mutable { "mut " } else { "" };
    format!("static {mut_kw}{name}: {}", render_type(&stat.type_, 0))
}

fn render_variant_signature(variant: &rustdoc_types::Variant, name: &str, krate: &Crate) -> String {
    match &variant.kind {
        rustdoc_types::VariantKind::Plain => name.to_string(),
        rustdoc_types::VariantKind::Tuple(fields) => {
            let field_types: Vec<_> = fields
                .iter()
                .map(|field_id| {
                    field_id
                        .as_ref()
                        .and_then(|id| krate.index.get(id))
                        .and_then(|item| match &item.inner {
                            ItemEnum::StructField(ty) => Some(render_type(ty, 0)),
                            _ => None,
                        })
                        .unwrap_or_else(|| "_".to_string())
                })
                .collect();
            format!("{name}({})", field_types.join(", "))
        }
        rustdoc_types::VariantKind::Struct { fields, .. } => {
            let field_strs: Vec<_> = fields
                .iter()
                .filter_map(|id| {
                    let item = krate.index.get(id)?;
                    let field_name = item.name.as_deref()?;
                    match &item.inner {
                        ItemEnum::StructField(ty) => {
                            Some(format!("{field_name}: {}", render_type(ty, 0)))
                        }
                        _ => None,
                    }
                })
                .collect();
            format!("{name} {{ {} }}", field_strs.join(", "))
        }
    }
}

// ───── Three-pass extraction ─────

/// Resolve the Self type of an impl block to (name, kind).
fn resolve_self_type(ty: &Type, krate: &Crate) -> (Option<String>, Option<String>) {
    match ty {
        Type::ResolvedPath(path) => {
            let name = path
                .path
                .rsplit("::")
                .next()
                .unwrap_or(&path.path)
                .to_string();
            let kind = krate
                .paths
                .get(&path.id)
                .map(|summary| format!("{:?}", summary.kind));
            (Some(name), kind)
        }
        Type::Generic(name) => (Some(name.clone()), None),
        Type::Primitive(name) => (Some(name.clone()), Some("Primitive".to_string())),
        Type::BorrowedRef { type_, .. } => resolve_self_type(type_, krate),
        _ => (None, None),
    }
}

fn extract_all_items(
    crate_name: &str,
    crate_version: &str,
    package_id_hash: &str,
    krate: &Crate,
) -> Vec<DocItem> {
    let mut items = Vec::new();

    // Pass 0: Collect all item IDs that are referenced by impl blocks.
    // These are methods/assoc types/consts that we'll handle in Pass 2 with parent context.
    let mut impl_item_ids: HashSet<&rustdoc_types::Id> = HashSet::new();
    for item in krate.index.values() {
        if let ItemEnum::Impl(impl_) = &item.inner {
            for id in &impl_.items {
                impl_item_ids.insert(id);
            }
        }
    }

    // Pass 1: Non-impl items (top-level functions, structs, enums, traits, etc.)
    for item in krate.index.values() {
        let item_name = match &item.name {
            Some(n) => n.clone(),
            None => continue,
        };
        let docs = item.docs.as_deref().unwrap_or("");

        // Skip items that belong to impl blocks — we'll extract them in Pass 2
        if impl_item_ids.contains(&item.id) {
            continue;
        }

        match &item.inner {
            ItemEnum::Module(_) => {
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name,
                    kind: "Module".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    signature: String::new(),
                    text: docs.to_string(),
                });
            }
            ItemEnum::Function(func) => {
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name: item_name.clone(),
                    kind: "Function".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    signature: render_function_signature(func, &item_name),
                    text: docs.to_string(),
                });
            }
            ItemEnum::Struct(strct) => {
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name: item_name.clone(),
                    kind: "Struct".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    signature: render_struct_signature(strct, &item_name),
                    text: docs.to_string(),
                });
            }
            ItemEnum::Enum(enm) => {
                let enum_sig = render_enum_signature(enm, &item_name);
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name: item_name.clone(),
                    kind: "Enum".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    signature: enum_sig,
                    text: docs.to_string(),
                });
                // Also extract variants
                for variant_id in &enm.variants {
                    if let Some(variant_item) = krate.index.get(variant_id)
                        && let Some(vname) = &variant_item.name
                        && let ItemEnum::Variant(variant) = &variant_item.inner
                    {
                        items.push(DocItem {
                            crate_name: crate_name.to_string(),
                            crate_version: crate_version.to_string(),
                            package_id_hash: package_id_hash.to_string(),
                            item_name: vname.clone(),
                            kind: "Variant".to_string(),
                            parent_name: Some(item_name.clone()),
                            parent_kind: Some("Enum".to_string()),
                            trait_name: None,
                            signature: render_variant_signature(variant, vname, krate),
                            text: variant_item.docs.as_deref().unwrap_or("").to_string(),
                        });
                    }
                }
            }
            ItemEnum::Trait(trt) => {
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name: item_name.clone(),
                    kind: "Trait".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    signature: render_trait_signature(trt, &item_name),
                    text: docs.to_string(),
                });
            }
            ItemEnum::Macro(body) => {
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name: item_name.clone(),
                    kind: "Macro".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    // For macros, the "body" is the source definition
                    signature: format!("{}!", item_name),
                    text: format!("{}\n{body}", docs),
                });
            }
            ItemEnum::ProcMacro(_) => {
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name: item_name.clone(),
                    kind: "Macro".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    signature: format!("{}!", item_name),
                    text: docs.to_string(),
                });
            }
            ItemEnum::TypeAlias(ta) => {
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name: item_name.clone(),
                    kind: "TypeAlias".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    signature: render_type_alias_signature(ta, &item_name),
                    text: docs.to_string(),
                });
            }
            ItemEnum::Constant { type_, const_ } => {
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name: item_name.clone(),
                    kind: "Constant".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    signature: render_constant_signature(type_, const_, &item_name),
                    text: docs.to_string(),
                });
            }
            ItemEnum::Static(stat) => {
                items.push(DocItem {
                    crate_name: crate_name.to_string(),
                    crate_version: crate_version.to_string(),
                    package_id_hash: package_id_hash.to_string(),
                    item_name: item_name.clone(),
                    kind: "Static".to_string(),
                    parent_name: None,
                    parent_kind: None,
                    trait_name: None,
                    signature: render_static_signature(stat, &item_name),
                    text: docs.to_string(),
                });
            }
            // ItemEnum has many variants we don't index (ExternCrate, Import, etc.)
            _ => {}
        }
    }

    // Pass 2: Walk impl blocks → extract methods, assoc types, assoc consts with parent context
    for item in krate.index.values() {
        let ItemEnum::Impl(impl_) = &item.inner else {
            continue;
        };

        // Skip synthetic/negative/blanket impls
        if impl_.is_synthetic || impl_.is_negative || impl_.blanket_impl.is_some() {
            continue;
        }

        let (parent_name, parent_kind) = resolve_self_type(&impl_.for_, krate);
        let trait_name = impl_
            .trait_
            .as_ref()
            .map(|p| p.path.rsplit("::").next().unwrap_or(&p.path).to_string());

        for member_id in &impl_.items {
            let Some(member) = krate.index.get(member_id) else {
                continue;
            };
            let Some(member_name) = &member.name else {
                continue;
            };
            let member_docs = member.docs.as_deref().unwrap_or("");

            match &member.inner {
                ItemEnum::Function(func) => {
                    items.push(DocItem {
                        crate_name: crate_name.to_string(),
                        crate_version: crate_version.to_string(),
                        package_id_hash: package_id_hash.to_string(),
                        item_name: member_name.clone(),
                        kind: "Method".to_string(),
                        parent_name: parent_name.clone(),
                        parent_kind: parent_kind.clone(),
                        trait_name: trait_name.clone(),
                        signature: render_function_signature(func, member_name),
                        text: member_docs.to_string(),
                    });
                }
                ItemEnum::AssocType {
                    generics,
                    bounds,
                    type_,
                } => {
                    let mut sig = format!("type {member_name}");
                    let real_params: Vec<_> = generics
                        .params
                        .iter()
                        .filter(|p| {
                            !matches!(
                                &p.kind,
                                GenericParamDefKind::Type {
                                    is_synthetic: true,
                                    ..
                                }
                            )
                        })
                        .collect();
                    if !real_params.is_empty() {
                        write!(
                            sig,
                            "<{}>",
                            real_params
                                .iter()
                                .map(|p| render_generic_param_def(p, 0))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                        .unwrap();
                    }
                    if !bounds.is_empty() {
                        write!(sig, ": {}", render_generic_bounds(bounds, 0)).unwrap();
                    }
                    if let Some(ty) = type_ {
                        write!(sig, " = {}", render_type(ty, 0)).unwrap();
                    }
                    items.push(DocItem {
                        crate_name: crate_name.to_string(),
                        crate_version: crate_version.to_string(),
                        package_id_hash: package_id_hash.to_string(),
                        item_name: member_name.clone(),
                        kind: "AssocType".to_string(),
                        parent_name: parent_name.clone(),
                        parent_kind: parent_kind.clone(),
                        trait_name: trait_name.clone(),
                        signature: sig,
                        text: member_docs.to_string(),
                    });
                }
                ItemEnum::AssocConst { type_, value } => {
                    let mut sig = format!("const {member_name}: {}", render_type(type_, 0));
                    if let Some(val) = value {
                        write!(sig, " = {val}").unwrap();
                    }
                    items.push(DocItem {
                        crate_name: crate_name.to_string(),
                        crate_version: crate_version.to_string(),
                        package_id_hash: package_id_hash.to_string(),
                        item_name: member_name.clone(),
                        kind: "AssocConst".to_string(),
                        parent_name: parent_name.clone(),
                        parent_kind: parent_kind.clone(),
                        trait_name: trait_name.clone(),
                        signature: sig,
                        text: member_docs.to_string(),
                    });
                }
                // Only methods, assoc types, and assoc consts are relevant in impl blocks
                _ => {}
            }
        }
    }

    items
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

    const INSERT_SQL: &str = r#"INSERT INTO "docs" (crate_name, crate_version, package_id_hash, item_name, kind, parent_name, parent_kind, trait_name, signature, text) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#;

    /// Helper: create an in-memory DB with docs table + FTS5.
    fn setup_db() -> Db {
        let db = Db::open(":memory:").unwrap();
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
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    "async fn spawn<F>(future: F) -> JoinHandle<F::Output>",
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
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    "trait Serialize",
                    "Serialization framework for Rust.",
                ],
            )?;
            Ok(())
        })
        .await?;

        let (crate_name, item_name, score) = db
            .call(|conn| {
                let mut stmt = conn.prepare(
                    r"
                    SELECT d.crate_name, d.item_name,
                           bm25(docs_fts, 1.0, 3.0, 2.0, 1.5, 1.0) as score
                    FROM docs_fts
                    JOIN docs d ON d.id = docs_fts.rowid
                    WHERE docs_fts MATCH ?1
                    ORDER BY score ASC
                    LIMIT 10
                    ",
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
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    "fn spawn()",
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
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    "fn spawn()",
                    "Spawns a task.",
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let r1 = db
            .call(|conn| is_crate_indexed(conn, "tokio_hash_v2"))
            .await
            .unwrap();
        assert!(!r1);
        let r2 = db
            .call(|conn| is_crate_indexed(conn, "tokio_hash"))
            .await
            .unwrap();
        assert!(r2);
    }

    #[tokio::test]
    async fn fts_search_by_parent_name() -> AppResult<()> {
        let db = setup_db();

        db.call(|conn| {
            conn.execute(
                INSERT_SQL,
                params![
                    "std",
                    "1.0.0",
                    "std_hash",
                    "insert",
                    "Method",
                    "HashMap",
                    "Struct",
                    None::<String>,
                    "fn insert(&mut self, k: K, v: V) -> Option<V>",
                    "Inserts a key-value pair.",
                ],
            )?;
            conn.execute(
                INSERT_SQL,
                params![
                    "std",
                    "1.0.0",
                    "std_hash",
                    "insert",
                    "Method",
                    "BTreeMap",
                    "Struct",
                    None::<String>,
                    "fn insert(&mut self, k: K, v: V) -> Option<V>",
                    "Inserts a key-value pair.",
                ],
            )?;
            Ok(())
        })
        .await?;

        // Search with parent_name filter via FTS5
        let results = db
            .call(|conn| {
                let mut stmt = conn.prepare(
                    r"
                    SELECT d.item_name, d.parent_name
                    FROM docs_fts
                    JOIN docs d ON d.id = docs_fts.rowid
                    WHERE docs_fts MATCH 'insert'
                    AND d.parent_name = 'HashMap'
                    ",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await?;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "HashMap");
        Ok(())
    }

    #[tokio::test]
    async fn fts_search_by_signature() -> AppResult<()> {
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
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    "async fn spawn<F: Future>(future: F) -> JoinHandle<F::Output>",
                    "Spawns a new asynchronous task.",
                ],
            )?;
            Ok(())
        })
        .await?;

        // Search matching signature content
        let results = db
            .call(|conn| {
                let mut stmt = conn.prepare(
                    r"
                    SELECT d.item_name, d.signature
                    FROM docs_fts
                    JOIN docs d ON d.id = docs_fts.rowid
                    WHERE docs_fts MATCH 'JoinHandle'
                    ",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await?;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "spawn");
        assert!(results[0].1.contains("JoinHandle"));
        Ok(())
    }

    // ───── Type renderer unit tests ─────

    #[test]
    fn render_primitive_types() {
        assert_eq!(render_type(&Type::Primitive("i32".into()), 0), "i32");
        assert_eq!(render_type(&Type::Primitive("bool".into()), 0), "bool");
    }

    #[test]
    fn render_generic_type() {
        assert_eq!(render_type(&Type::Generic("T".into()), 0), "T");
    }

    #[test]
    fn render_borrowed_ref() {
        let ty = Type::BorrowedRef {
            lifetime: Some("'a".into()),
            is_mutable: true,
            type_: Box::new(Type::Primitive("str".into())),
        };
        assert_eq!(render_type(&ty, 0), "&'a mut str");

        let ty2 = Type::BorrowedRef {
            lifetime: None,
            is_mutable: false,
            type_: Box::new(Type::Primitive("str".into())),
        };
        assert_eq!(render_type(&ty2, 0), "&str");
    }

    #[test]
    fn render_tuple_type() {
        let ty = Type::Tuple(vec![
            Type::Primitive("i32".into()),
            Type::Primitive("bool".into()),
        ]);
        assert_eq!(render_type(&ty, 0), "(i32, bool)");
        assert_eq!(render_type(&Type::Tuple(vec![]), 0), "()");
    }

    #[test]
    fn render_slice_and_array() {
        let slice = Type::Slice(Box::new(Type::Primitive("u8".into())));
        assert_eq!(render_type(&slice, 0), "[u8]");

        let array = Type::Array {
            type_: Box::new(Type::Primitive("u8".into())),
            len: "32".into(),
        };
        assert_eq!(render_type(&array, 0), "[u8; 32]");
    }

    #[test]
    fn render_raw_pointer() {
        let ty = Type::RawPointer {
            is_mutable: true,
            type_: Box::new(Type::Primitive("u8".into())),
        };
        assert_eq!(render_type(&ty, 0), "*mut u8");

        let ty2 = Type::RawPointer {
            is_mutable: false,
            type_: Box::new(Type::Primitive("u8".into())),
        };
        assert_eq!(render_type(&ty2, 0), "*const u8");
    }

    #[test]
    fn render_infer() {
        assert_eq!(render_type(&Type::Infer, 0), "_");
    }

    #[test]
    fn render_depth_limit_prevents_stack_overflow() {
        // Build a deeply nested type
        let mut ty = Type::Primitive("i32".into());
        for _ in 0..30 {
            ty = Type::Slice(Box::new(ty));
        }
        let rendered = render_type(&ty, 0);
        assert!(rendered.contains("..."), "Should hit depth limit");
    }

    #[tokio::test]
    async fn project_crate_scopes_includes_workspace_and_deps() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let meta = cargo_metadata::MetadataCommand::new()
            .manifest_path(manifest)
            .exec()
            .expect("cargo metadata should succeed on cratedex itself");

        let crates = project_crate_scopes(&meta).unwrap();
        assert!(!crates.is_empty(), "Should have at least one crate");

        let names: Vec<&str> = crates.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"cratedex"),
            "Should include cratedex itself"
        );
        assert!(names.contains(&"serde"), "serde should be a transitive dep");
        assert!(names.contains(&"tokio"), "tokio should be a direct dep");
    }

    #[test]
    fn schema_migration_detects_old_schema() {
        let db = Db::open(":memory:").unwrap();
        let conn = db.conn.lock().unwrap();
        // Create old-style table without signature column
        conn.execute_batch(
            r#"CREATE TABLE IF NOT EXISTS "docs" (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                crate_name TEXT NOT NULL,
                crate_version TEXT NOT NULL,
                package_id_hash TEXT NOT NULL,
                item_name TEXT NOT NULL,
                kind TEXT NOT NULL,
                text TEXT NOT NULL
            )"#,
        )
        .unwrap();
        // Calling ensure_docs_table_and_fts should detect and recreate
        ensure_docs_table_and_fts(&conn).unwrap();
        // Verify new column exists
        let has_sig: i64 = conn
            .prepare("SELECT count(*) FROM pragma_table_info('docs') WHERE name = 'signature'")
            .unwrap()
            .query_row([], |row| row.get(0))
            .unwrap();
        assert_eq!(has_sig, 1);
    }
}
