use rmcp::{ErrorData as McpError, model::CallToolResult, model::Content};

use crate::core::error::Error;

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

pub fn json_result(value: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
    )])
}

pub fn text_result(s: String) -> CallToolResult {
    CallToolResult::success(vec![Content::text(s)])
}
