//! Shared resolution of the daemon's SQLite state database path.
//!
//! Used by the daemon runtime, the `dns job` commands, and the MCP sync tool
//! so every surface agrees on where ownership/run state lives.

use std::path::PathBuf;

use crate::control_plane::config::AppConfig;

/// Resolve the SQLite state database path.
///
/// Priority:
/// 1. `config.daemon.state_db` if present.
/// 2. `DNSYNC_STATE_DB` environment variable if set.
/// 3. `$XDG_DATA_HOME/dnsync/state.db`, falling back to
///    `$HOME/.local/share/dnsync/state.db`, then `./dnsync/state.db`.
pub fn resolve_state_db(config: &AppConfig) -> PathBuf {
    if let Some(ref daemon) = config.daemon
        && let Some(ref p) = daemon.state_db
    {
        return p.clone();
    }

    if let Ok(p) = std::env::var("DNSYNC_STATE_DB") {
        return PathBuf::from(p);
    }

    xdg_data_home().join("dnsync").join("state.db")
}

/// Resolve the base data directory following XDG conventions.
fn xdg_data_home() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local").join("share");
    }
    PathBuf::from(".")
}
