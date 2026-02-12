//! Extension traits for error handling

use rmcp::ErrorData as McpError;

/// Extension trait for converting errors to MCP internal errors
pub trait ToMcpError<T> {
    /// Convert an error to an MCP internal error with context
    fn mcp_internal_err(self, context: &str) -> Result<T, McpError>;
}

impl<T, E: std::fmt::Display> ToMcpError<T> for Result<T, E> {
    fn mcp_internal_err(self, context: &str) -> Result<T, McpError> {
        self.map_err(|e| McpError::internal_error(format!("{}: {}", context, e), None))
    }
}
