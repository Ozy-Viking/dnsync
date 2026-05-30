// @generated — maintained by hand to match DDL in migrations.rs

diesel::table! {
    daemon_health (id) {
        id -> Integer,
        daemon_id -> Text,
        started_at -> Text,
        last_heartbeat_at -> Text,
        daemon_state -> Text,
        overall_health -> Text,
        last_health_change_at -> Text,
        last_error_summary -> Nullable<Text>,
        jobs_total -> Integer,
        jobs_enabled -> Integer,
        jobs_healthy -> Integer,
        jobs_degraded -> Integer,
        jobs_running -> Integer,
    }
}

diesel::table! {
    job_status (job_id) {
        job_id -> Text,
        job_kind -> Text,
        enabled -> Integer,
        current_state -> Text,
        last_started_at -> Nullable<Text>,
        last_finished_at -> Nullable<Text>,
        last_success_at -> Nullable<Text>,
        last_failure_at -> Nullable<Text>,
        last_error_summary -> Nullable<Text>,
        consecutive_failures -> Integer,
        last_run_id -> Nullable<Text>,
    }
}

diesel::table! {
    job_runs (run_id) {
        run_id -> Text,
        job_id -> Text,
        job_kind -> Text,
        trigger_kind -> Text,
        started_at -> Text,
        finished_at -> Nullable<Text>,
        outcome -> Nullable<Text>,
        error_summary -> Nullable<Text>,
        duration_ms -> Nullable<Integer>,
    }
}
