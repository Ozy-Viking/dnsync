//! Core runtime types for the dnsync daemon.

use serde::{Deserialize, Serialize};

/// The class of work a daemon job performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    RecordSync,
    ZoneSync,
    ZoneExport,
}

/// Observable health of a daemon job or the daemon as a whole.
///
/// Ordered from best to worst: `Healthy < Degraded < Stale < Fatal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Stale,
    Fatal,
}

impl PartialOrd for HealthState {
    /// Compare two health states and produce their ordering based on severity.
    
    ///
    
    /// # Examples
    
    ///
    
    /// ```rust,ignore
    
    /// use std::cmp::Ordering;
    
    /// let a = crate::daemon::types::HealthState::Healthy;
    
    /// let b = crate::daemon::types::HealthState::Fatal;
    
    /// assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
    
    /// ```
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HealthState {
    /// Compare two `HealthState` values according to their severity ranking.
    ///
    /// The severity ordering is: `Healthy` < `Degraded` < `Stale` < `Fatal`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::daemon::types::HealthState;
    /// assert!(HealthState::Healthy < HealthState::Degraded);
    /// assert!(HealthState::Stale > HealthState::Degraded);
    /// assert_eq!(HealthState::Fatal.cmp(&HealthState::Fatal), std::cmp::Ordering::Equal);
    /// ```
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(s: &HealthState) -> u8 {
            match s {
                HealthState::Healthy => 0,
                HealthState::Degraded => 1,
                HealthState::Stale => 2,
                HealthState::Fatal => 3,
            }
        }
        rank(self).cmp(&rank(other))
    }
}

/// What initiated a job run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    Scheduled,
    Manual,
}

/// Snapshot of a single job's runtime status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobStatus {
    pub job_id: String,
    pub kind: JobKind,
    pub enabled: bool,
    pub state: HealthState,
    pub consecutive_failures: u32,
    pub critical: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_health_state_ordering() {
        assert!(HealthState::Healthy < HealthState::Degraded);
        assert!(HealthState::Degraded < HealthState::Stale);
        assert!(HealthState::Stale < HealthState::Fatal);
        assert!(HealthState::Healthy < HealthState::Fatal);
    }

    #[test]
    fn test_health_state_max() {
        let states = vec![
            HealthState::Healthy,
            HealthState::Stale,
            HealthState::Degraded,
        ];
        let worst = states.into_iter().max().unwrap();
        assert_eq!(worst, HealthState::Stale);

        let states2 = vec![
            HealthState::Degraded,
            HealthState::Fatal,
            HealthState::Healthy,
        ];
        let worst2 = states2.into_iter().max().unwrap();
        assert_eq!(worst2, HealthState::Fatal);
    }

    #[test]
    fn test_job_kind_serialization() {
        let kinds = [
            JobKind::RecordSync,
            JobKind::ZoneSync,
            JobKind::ZoneExport,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).expect("serialization should succeed");
            let back: JobKind =
                serde_json::from_str(&json).expect("deserialization should succeed");
            assert_eq!(kind, back);
        }
        // Verify snake_case serialization
        assert_eq!(
            serde_json::to_string(&JobKind::RecordSync).unwrap(),
            r#""record_sync""#
        );
        assert_eq!(
            serde_json::to_string(&JobKind::ZoneExport).unwrap(),
            r#""zone_export""#
        );
    }

    #[test]
    fn test_trigger_kind_serialization() {
        let kinds = [TriggerKind::Scheduled, TriggerKind::Manual];
        for kind in kinds {
            let json = serde_json::to_string(&kind).expect("serialization should succeed");
            let back: TriggerKind =
                serde_json::from_str(&json).expect("deserialization should succeed");
            assert_eq!(kind, back);
        }
        assert_eq!(
            serde_json::to_string(&TriggerKind::Scheduled).unwrap(),
            r#""scheduled""#
        );
        assert_eq!(
            serde_json::to_string(&TriggerKind::Manual).unwrap(),
            r#""manual""#
        );
    }
}
