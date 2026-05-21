//! MCP helper functions — error and result formatting.

use rmcp::{ErrorData as McpError, model::*};

use crate::core::error::Error;

/// Convert a crate `Error` into an MCP protocol error.
pub fn mcp_err(e: Error) -> McpError {
    use miette::Diagnostic;
    let mut msg = e.to_string();
    if let Some(code) = e.code() {
        msg = format!("[{code}] {msg}");
    }
    if let Some(help) = e.help() {
        msg = format!("{msg}\n\nhelp: {help}");
    }
    McpError::internal_error(msg, None)
}

/// Wrap a JSON value into a successful MCP call result.
pub fn json_result(value: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
    )])
}

/// Wrap a plain text string into a successful MCP call result.
pub fn text_result(s: String) -> CallToolResult {
    CallToolResult::success(vec![Content::text(s)])
}
