//! MCP helper functions — error and result formatting.

use std::future::Future;

use miette::Diagnostic;
use rmcp::{ErrorData as McpError, model::*};
use serde_json::json;
use tracing::Instrument;

use crate::core::error::{Error, Result};

/// Build the structured JSON `data` payload that accompanies an MCP error.
///
/// Includes the miette diagnostic code, help text, and a `retryable` hint
/// so AI agent clients can decide whether to retry the call without parsing
/// the human-readable message.
fn error_data(e: &Error) -> serde_json::Value {
    let code = e.code().map(|c| c.to_string());
    let help = e.help().map(|h| h.to_string());
    json!({
        "code": code,
        "help": help,
        "retryable": is_retryable(e),
    })
}

/// True when the error represents a transient failure the client may retry.
fn is_retryable(e: &Error) -> bool {
    matches!(
        e,
        Error::Network(_) | Error::Mcp { .. } | Error::InvalidJson(_)
    )
}

/// Build the human-readable MCP error message: `[code] <display>\n\nhelp: <help>`.
fn error_message(e: &Error) -> String {
    let mut msg = e.to_string();
    if let Some(code) = e.code() {
        msg = format!("[{code}] {msg}");
    }
    if let Some(help) = e.help() {
        msg = format!("{msg}\n\nhelp: {help}");
    }
    msg
}

/// Convert a crate `Error` into an MCP protocol error with structured data.
///
/// The `data` payload exposes the diagnostic code, help text, and a
/// `retryable` flag for client-side handling.
pub fn mcp_err(e: Error) -> McpError {
    let msg = error_message(&e);
    let data = error_data(&e);
    McpError::internal_error(msg, Some(data))
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

/// Build a tool-level error result (`isError: true`) carrying both the
/// human-readable message and the structured data payload.
fn error_tool_result(e: &Error) -> CallToolResult {
    let msg = error_message(e);
    let data = error_data(e);
    let body = json!({
        "error": msg,
        "data": data,
    });
    let text = serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string());
    CallToolResult::error(vec![Content::text(text)])
}

/// The outcome label recorded on a tool's span.
fn outcome_for(e: &Error) -> &'static str {
    match e {
        Error::PolicyViolation { .. } | Error::Forbidden { .. } => "permission_denied",
        _ => "error",
    }
}

/// Run a permission check (or `.and(...)`-chained checks), then a future,
/// and wrap the JSON result. Errors are surfaced as a `CallToolResult` with
/// `is_error: true` (per MCP spec) rather than as a transport-level `McpError`,
/// so an AI agent client can recover without aborting its loop.
pub async fn run_json<F>(tool: &str, check: Result<()>, fut: F) -> CallToolResult
where
    F: Future<Output = Result<serde_json::Value>>,
{
    let span = tracing::info_span!("mcp_tool", tool = tool, outcome = tracing::field::Empty);
    async move {
        match check {
            Err(e) => {
                tracing::warn!(tool = tool, error = %e, "MCP tool error");
                tracing::Span::current().record("outcome", outcome_for(&e));
                error_tool_result(&e)
            }
            Ok(()) => match fut.await {
                Ok(v) => {
                    tracing::Span::current().record("outcome", "success");
                    json_result(v)
                }
                Err(e) => {
                    tracing::warn!(tool = tool, error = %e, "MCP tool error");
                    tracing::Span::current().record("outcome", outcome_for(&e));
                    error_tool_result(&e)
                }
            },
        }
    }
    .instrument(span)
    .await
}

/// Like [`run_json`] but wraps a plain text result.
pub async fn run_text<F>(tool: &str, check: Result<()>, fut: F) -> CallToolResult
where
    F: Future<Output = Result<String>>,
{
    let span = tracing::info_span!("mcp_tool", tool = tool, outcome = tracing::field::Empty);
    async move {
        match check {
            Err(e) => {
                tracing::warn!(tool = tool, error = %e, "MCP tool error");
                tracing::Span::current().record("outcome", outcome_for(&e));
                error_tool_result(&e)
            }
            Ok(()) => match fut.await {
                Ok(s) => {
                    tracing::Span::current().record("outcome", "success");
                    text_result(s)
                }
                Err(e) => {
                    tracing::warn!(tool = tool, error = %e, "MCP tool error");
                    tracing::Span::current().record("outcome", outcome_for(&e));
                    error_tool_result(&e)
                }
            },
        }
    }
    .instrument(span)
    .await
}
