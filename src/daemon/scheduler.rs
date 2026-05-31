//! Async scheduler math: computes when each job should next fire.
//!
//! This module is pure scheduling logic — it does NOT execute jobs.
//! It provides helpers to compute next-fire times, apply optional jitter,
//! and select the soonest job from a list.

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use cron::Schedule;
use tracing::debug;

/// A job definition used by the scheduler.
pub struct ScheduledJob {
    pub id: String,
    /// A validated 6-field cron expression (sec min hour dom mon dow),
    /// as returned by `crate::daemon::schedule::parse_schedule`.
    pub cron_expr: String,
    pub timezone: Tz,
    /// Maximum random jitter added to each trigger time. `Duration::ZERO` = no jitter.
    pub jitter_max: Duration,
    pub enabled: bool,
}

/// An event emitted when a job is due to run.
pub struct JobTrigger {
    pub job_id: String,
    /// The cron tick time (before jitter is applied).
    pub scheduled_at: DateTime<Utc>,
    pub trigger_kind: crate::daemon::types::TriggerKind,
    /// Whether the job should run in dry-run mode (no writes).
    pub dry_run: bool,
}

/// Compute the next fire time for `job` strictly after `after`.
///
/// The computation is done in the job's configured timezone so that
/// DST transitions and local-midnight rules are respected correctly.
/// Returns `None` only if the cron expression produces no future dates
/// (which should not happen for valid, non-expiring expressions).
pub fn next_after(job: &ScheduledJob, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let schedule = Schedule::from_str(&job.cron_expr).ok()?;
    // Convert the reference instant into the job's timezone, then use it
    // as the "after" anchor. The `cron` crate accepts any TimeZone, so we
    // pass the tz-aware DateTime directly and convert the result back to UTC.
    let after_in_tz = after.with_timezone(&job.timezone);
    schedule
        .after(&after_in_tz)
        .next()
        .map(|t| t.with_timezone(&Utc))
}

/// Add a random jitter of `[0, max)` milliseconds to `deadline`.
///
/// When `max` is [`Duration::ZERO`] the deadline is returned unchanged.
pub fn apply_jitter(deadline: DateTime<Utc>, max: Duration, rng: &mut impl rand::Rng) -> DateTime<Utc> {
    let max_millis = max.as_millis();
    if max_millis == 0 {
        return deadline;
    }
    let jitter_ms = rng.gen_range(0..max_millis) as i64;
    deadline + chrono::Duration::milliseconds(jitter_ms)
}

/// Given a slice of jobs, return the enabled job whose next fire time is
/// soonest after `now`, together with that fire time.
///
/// Returns `None` when the slice is empty or every job is disabled.
pub fn next_job_to_fire<'a>(
    jobs: &'a [ScheduledJob],
    now: DateTime<Utc>,
) -> Option<(&'a ScheduledJob, DateTime<Utc>)> {
    let result = jobs
        .iter()
        .filter(|j| j.enabled)
        .filter_map(|j| {
            let t = next_after(j, now)?;
            debug!(job_id = %j.id, next_fire_time = %t, "computed next fire time for job");
            Some((j, t))
        })
        .min_by_key(|(_, t)| *t);

    if let Some((job, fire_time)) = &result {
        debug!(job_id = %job.id, fire_time = %fire_time, "next job to fire selected");
    } else {
        debug!("no enabled jobs with a future fire time");
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use rand::{SeedableRng, rngs::StdRng};

    // Helper: build a minimal ScheduledJob
    fn job(id: &str, cron_expr: &str) -> ScheduledJob {
        ScheduledJob {
            id: id.to_string(),
            cron_expr: cron_expr.to_string(),
            timezone: chrono_tz::UTC,
            jitter_max: Duration::ZERO,
            enabled: true,
        }
    }

    fn job_tz(id: &str, cron_expr: &str, tz: Tz) -> ScheduledJob {
        ScheduledJob {
            id: id.to_string(),
            cron_expr: cron_expr.to_string(),
            timezone: tz,
            jitter_max: Duration::ZERO,
            enabled: true,
        }
    }

    // ── next_after ────────────────────────────────────────────────────────────

    /// "0 */5 * * * *" — every 5 minutes on the minute.
    /// If now is 12:03, next tick should be 12:05:00.
    #[test]
    fn test_next_after_basic() {
        let j = job("j1", "0 */5 * * * *");
        // 2024-01-15 12:03:00 UTC
        let now = Utc.with_ymd_and_hms(2024, 1, 15, 12, 3, 0).unwrap();
        let next = next_after(&j, now).expect("should return a next time");
        let expected = Utc.with_ymd_and_hms(2024, 1, 15, 12, 5, 0).unwrap();
        assert_eq!(next, expected, "expected 12:05:00 but got {next}");
    }

    /// If now is 12:58, the next 5-min tick crosses the hour to 13:00:00.
    #[test]
    fn test_next_after_crosses_hour() {
        let j = job("j2", "0 */5 * * * *");
        let now = Utc.with_ymd_and_hms(2024, 1, 15, 12, 58, 0).unwrap();
        let next = next_after(&j, now).expect("should return a next time");
        let expected = Utc.with_ymd_and_hms(2024, 1, 15, 13, 0, 0).unwrap();
        assert_eq!(next, expected, "expected 13:00:00 but got {next}");
    }

    /// "0 * * * * *" fires every minute; next tick should be within 60 s.
    #[test]
    fn test_next_after_every_minute() {
        let j = job("j3", "0 * * * * *");
        let now = Utc::now();
        let next = next_after(&j, now).expect("should return a next time");
        let delta = next - now;
        assert!(
            delta.num_seconds() > 0 && delta.num_seconds() <= 60,
            "expected delta in (0, 60] seconds, got {delta}"
        );
    }

    // ── apply_jitter ──────────────────────────────────────────────────────────

    /// Zero max jitter → deadline unchanged.
    #[test]
    fn test_apply_jitter_zero_max() {
        let deadline = Utc.with_ymd_and_hms(2024, 6, 1, 9, 0, 0).unwrap();
        let mut rng = StdRng::from_entropy();
        let result = apply_jitter(deadline, Duration::ZERO, &mut rng);
        assert_eq!(result, deadline);
    }

    /// Jitter is always in `[0, max)`.  Run 100 times to be confident.
    #[test]
    fn test_apply_jitter_within_bounds() {
        let deadline = Utc.with_ymd_and_hms(2024, 6, 1, 9, 0, 0).unwrap();
        let max = Duration::from_secs(60);
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..100 {
            let result = apply_jitter(deadline, max, &mut rng);
            let delta_ms = (result - deadline).num_milliseconds();
            assert!(
                delta_ms >= 0 && delta_ms < max.as_millis() as i64,
                "jitter {delta_ms} ms out of [0, {})",
                max.as_millis()
            );
        }
    }

    // ── next_job_to_fire ──────────────────────────────────────────────────────

    /// Empty slice → None.
    #[test]
    fn test_next_job_to_fire_empty() {
        let jobs: Vec<ScheduledJob> = vec![];
        let now = Utc::now();
        assert!(next_job_to_fire(&jobs, now).is_none());
    }

    /// All disabled → None.
    #[test]
    fn test_next_job_to_fire_disabled() {
        let mut j = job("j1", "0 */5 * * * *");
        j.enabled = false;
        let jobs = vec![j];
        let now = Utc::now();
        assert!(next_job_to_fire(&jobs, now).is_none());
    }

    /// Single enabled job → returns it.
    #[test]
    fn test_next_job_to_fire_single() {
        let j = job("j1", "0 */5 * * * *");
        let now = Utc.with_ymd_and_hms(2024, 1, 15, 12, 3, 0).unwrap();
        let jobs = vec![j];
        let (picked, fire_time) = next_job_to_fire(&jobs, now).expect("should find a job");
        assert_eq!(picked.id, "j1");
        let expected = Utc.with_ymd_and_hms(2024, 1, 15, 12, 5, 0).unwrap();
        assert_eq!(fire_time, expected);
    }

    /// Two jobs with different schedules — picks the one firing soonest.
    /// j_fast fires every minute, j_slow fires every hour.
    /// Soonest from 12:03 → j_fast at 12:04:00.
    #[test]
    fn test_next_job_to_fire_picks_soonest() {
        let j_fast = job("fast", "0 * * * * *");  // every minute
        let j_slow = job("slow", "0 0 * * * *");  // top of every hour
        let now = Utc.with_ymd_and_hms(2024, 1, 15, 12, 3, 0).unwrap();
        let jobs = vec![j_fast, j_slow];
        let (picked, _) = next_job_to_fire(&jobs, now).expect("should find a job");
        assert_eq!(picked.id, "fast", "expected 'fast' to fire soonest");
    }

    /// Use US/Eastern (UTC-5 / UTC-4 DST).
    /// "0 0 8 * * *" fires at 08:00 Eastern every day.
    /// In winter (EST = UTC-5) that's 13:00 UTC.
    #[test]
    fn test_timezone_respected() {
        let tz = chrono_tz::US::Eastern;
        let j = job_tz("tz_job", "0 0 8 * * *", tz);
        // 2024-01-15 is winter — EST is UTC-5.
        // Reference time just after midnight UTC (07:59 EST).
        let now = Utc.with_ymd_and_hms(2024, 1, 15, 12, 59, 0).unwrap();
        let next = next_after(&j, now).expect("should return a next time");
        // 08:00 EST on 2024-01-15 = 13:00 UTC.
        let expected = Utc.with_ymd_and_hms(2024, 1, 15, 13, 0, 0).unwrap();
        assert_eq!(next, expected, "expected 13:00 UTC (08:00 EST) but got {next}");
    }
}
