use diesel::connection::SimpleConnection;
use diesel::sqlite::SqliteConnection;

const INIT_SQL: &str = "
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS daemon_health (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    daemon_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    last_heartbeat_at TEXT NOT NULL,
    daemon_state TEXT NOT NULL,
    overall_health TEXT NOT NULL,
    last_health_change_at TEXT NOT NULL,
    last_error_summary TEXT,
    jobs_total INTEGER NOT NULL DEFAULT 0,
    jobs_enabled INTEGER NOT NULL DEFAULT 0,
    jobs_healthy INTEGER NOT NULL DEFAULT 0,
    jobs_degraded INTEGER NOT NULL DEFAULT 0,
    jobs_running INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS job_status (
    job_id TEXT PRIMARY KEY,
    job_kind TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    current_state TEXT NOT NULL,
    last_started_at TEXT,
    last_finished_at TEXT,
    last_success_at TEXT,
    last_failure_at TEXT,
    last_error_summary TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_run_id TEXT
);

CREATE TABLE IF NOT EXISTS job_runs (
    run_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    job_kind TEXT NOT NULL,
    trigger_kind TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    outcome TEXT,
    error_summary TEXT,
    duration_ms INTEGER
);
";

/// Runs all schema migrations on an open connection.
/// Uses `batch_execute` which supports multiple semicolon-separated statements.
pub fn run_migrations(conn: &mut SqliteConnection) -> Result<(), String> {
    conn.batch_execute(INIT_SQL)
        .map_err(|e| format!("migration failed: {e}"))
}
