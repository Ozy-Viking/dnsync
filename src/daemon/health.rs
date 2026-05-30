//! Daemon health aggregation logic.

use tracing::trace;

use crate::daemon::types::{HealthState, JobStatus};

/// Return the worst `HealthState` from an iterator of states.
///
/// Returns `HealthState::Healthy` when the iterator is empty.
pub fn worst_state<I: Iterator<Item = HealthState>>(states: I) -> HealthState {
    states.max().unwrap_or(HealthState::Healthy)
}

/// Compute overall daemon health from a slice of job statuses.
///
/// Rules (applied in order):
/// 1. If there are no enabled jobs → `Healthy`
/// 2. If ALL critical jobs have `consecutive_failures >= threshold` → `Fatal`
///    (only when there is at least one critical job)
/// 3. Otherwise → worst `HealthState` across all enabled jobs
pub fn aggregate_daemon_health(jobs: &[JobStatus], critical_threshold: u32) -> HealthState {
    let enabled: Vec<&JobStatus> = jobs.iter().filter(|j| j.enabled).collect();

    trace!(
        total_jobs = jobs.len(),
        enabled_jobs = enabled.len(),
        "aggregating daemon health"
    );

    if enabled.is_empty() {
        trace!("no enabled jobs; overall health is Healthy");
        return HealthState::Healthy;
    }

    // Check critical escalation: ALL critical jobs must have failed >= threshold times.
    let critical_jobs: Vec<&JobStatus> = enabled.iter().copied().filter(|j| j.critical).collect();
    trace!(
        critical_jobs = critical_jobs.len(),
        critical_threshold,
        "checking critical job escalation"
    );
    if !critical_jobs.is_empty()
        && critical_jobs
            .iter()
            .all(|j| j.consecutive_failures >= critical_threshold)
    {
        trace!("all critical jobs exceeded failure threshold; escalating to Fatal");
        return HealthState::Fatal;
    }

    // Aggregate worst state across all enabled jobs.
    let state = worst_state(enabled.iter().map(|j| j.state));
    trace!(overall_health = ?state, "aggregated health state computed");
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::types::{HealthState, JobKind, JobStatus};

    fn make_job(id: &str, state: HealthState, critical: bool, failures: u32) -> JobStatus {
        JobStatus {
            job_id: id.to_string(),
            kind: JobKind::RecordSync,
            enabled: true,
            state,
            consecutive_failures: failures,
            critical,
        }
    }

    fn make_disabled_job(id: &str) -> JobStatus {
        JobStatus {
            job_id: id.to_string(),
            kind: JobKind::RecordSync,
            enabled: false,
            state: HealthState::Fatal,
            consecutive_failures: 99,
            critical: true,
        }
    }

    #[test]
    fn test_worst_state_empty_is_healthy() {
        let result = worst_state(std::iter::empty());
        assert_eq!(result, HealthState::Healthy);
    }

    #[test]
    fn test_worst_state_mixed() {
        let states = vec![
            HealthState::Healthy,
            HealthState::Degraded,
            HealthState::Stale,
        ];
        let result = worst_state(states.into_iter());
        assert_eq!(result, HealthState::Stale);
    }

    #[test]
    fn test_all_healthy_jobs_is_healthy() {
        let jobs = vec![
            make_job("a", HealthState::Healthy, false, 0),
            make_job("b", HealthState::Healthy, false, 0),
        ];
        let result = aggregate_daemon_health(&jobs, 5);
        assert_eq!(result, HealthState::Healthy);
    }

    #[test]
    fn test_one_degraded_job_is_degraded() {
        let jobs = vec![
            make_job("a", HealthState::Healthy, false, 0),
            make_job("b", HealthState::Degraded, false, 0),
        ];
        let result = aggregate_daemon_health(&jobs, 5);
        assert_eq!(result, HealthState::Degraded);
    }

    #[test]
    fn test_no_enabled_jobs_is_healthy() {
        let jobs = vec![make_disabled_job("a"), make_disabled_job("b")];
        let result = aggregate_daemon_health(&jobs, 5);
        assert_eq!(result, HealthState::Healthy);
    }

    #[test]
    fn test_all_critical_fail_5x_is_fatal() {
        let jobs = vec![
            make_job("a", HealthState::Degraded, true, 5),
            make_job("b", HealthState::Degraded, true, 6),
        ];
        let result = aggregate_daemon_health(&jobs, 5);
        assert_eq!(result, HealthState::Fatal);
    }

    #[test]
    fn test_one_critical_passing_is_degraded_not_fatal() {
        // Even if one critical job has many failures, if another critical job is
        // still passing, we don't escalate to Fatal.
        let jobs = vec![
            make_job("a", HealthState::Degraded, true, 10),
            make_job("b", HealthState::Healthy, true, 0), // this one is passing
        ];
        let result = aggregate_daemon_health(&jobs, 5);
        // Should be Degraded (worst state), not Fatal
        assert_eq!(result, HealthState::Degraded);
    }

    #[test]
    fn test_noncritical_failures_never_escalate_to_fatal() {
        // Non-critical jobs with many failures should never produce Fatal.
        let jobs = vec![
            make_job("a", HealthState::Degraded, false, 100),
            make_job("b", HealthState::Degraded, false, 200),
        ];
        let result = aggregate_daemon_health(&jobs, 5);
        assert_eq!(result, HealthState::Degraded);
        assert_ne!(result, HealthState::Fatal);
    }
}
