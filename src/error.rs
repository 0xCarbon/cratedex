//! Defines the custom error types for the application.

use thiserror::Error;

pub type AppResult<T> = std::result::Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Metadata error: {0}")]
    Metadata(#[from] cargo_metadata::Error),

    #[error("MCP Server error: {0}")]
    Server(#[from] rmcp::ErrorData),

    #[error("MCP Server initialization error: {0}")]
    ServerInit(#[from] Box<rmcp::service::ServerInitializeError>),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("UTF8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Task join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
