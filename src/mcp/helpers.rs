//! MCP helper functions — error and result formatting.

use std::future::Future;

use rmcp::{ErrorData as McpError, model::*};

use crate::core::error::{Error, Result};

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
    // `unwrap_or_else` is a safe fallback, not a panic: any `serde_json::Value`
    // round-trips through `to_string()`, so pretty-printing failure degrades
    // gracefully instead of bringing the MCP transport down.
    CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
    )])
}

/// Wrap a plain text string into a successful MCP call result.
pub fn text_result(s: String) -> CallToolResult {
    CallToolResult::success(vec![Content::text(s)])
}

/// Run a permission check (or `.and(...)`-chained checks), then a future,
/// wrapping the JSON result into a `CallToolResult`. Any crate `Error`
/// becomes an `McpError` via [`mcp_err`].
pub async fn run_json<F>(
    check: Result<()>,
    fut: F,
) -> std::result::Result<CallToolResult, McpError>
where
    F: Future<Output = Result<serde_json::Value>>,
{
    check.map_err(mcp_err)?;
    fut.await.map(json_result).map_err(mcp_err)
}

/// Like [`run_json`] but wraps a plain text result.
pub async fn run_text<F>(
    check: Result<()>,
    fut: F,
) -> std::result::Result<CallToolResult, McpError>
where
    F: Future<Output = Result<String>>,
{
    check.map_err(mcp_err)?;
    fut.await.map(text_result).map_err(mcp_err)
}
