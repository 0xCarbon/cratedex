//! The metadata engine is responsible for understanding the project's structure.

use crate::engine::command::{new_cargo_command, run_with_timeout};
use crate::error::AppResult;
use cargo_metadata::Metadata;
use std::path::Path;
use std::time::Duration;
use tracing::{info, info_span};

const METADATA_TIMEOUT: Duration = Duration::from_mins(1);

/// Runs `cargo metadata` for the given project path and returns the parsed result.
pub async fn load_metadata(project_path: &Path) -> AppResult<Metadata> {
    let span = info_span!("load_metadata", path = %project_path.display());
    let _enter = span.enter();
    info!("Loading project metadata via `cargo metadata`...");
    let mut cmd = new_cargo_command(project_path);
    cmd.arg("metadata").arg("--format-version=1");
    let metadata = run_with_timeout(&mut cmd, METADATA_TIMEOUT, "`cargo metadata`").await?;
    let metadata_json = String::from_utf8(metadata.stdout)?;
    let metadata: Metadata = serde_json::from_str(&metadata_json)?;
    info!(
        "Successfully loaded metadata for workspace: {}",
        metadata.workspace_root
    );
    Ok(metadata)
}
