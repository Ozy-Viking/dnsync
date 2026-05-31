//! Schedule parsing for daemon jobs.
//!
//! Accepts either an interval shorthand (`"5m"`, `"1h"`, `"30m"`, `"1d"`) or
//! a standard 5-field cron expression (`"*/5 * * * *"`), and returns a validated
//! 6-field cron expression suitable for the `cron` crate (sec min hour dom mon dow).

use cron::Schedule;
use std::str::FromStr;

/// Convert a schedule string into a validated six-field cron expression.
///
/// Accepts:
/// - interval shorthands like `"5m"`, `"1h"`, `"1d"` (minutes, hours, days);
/// - a 5-field cron (seconds field will be prefixed with `"0 "`); or
/// - a 6-field cron (returned as-is after validation).
///
/// Intervals must be at least 1 minute; sub-minute intervals (e.g. `"30s"`) and out-of-range values produce an `Err` describing the problem.
///
/// # Examples
///
/// ```
/// // interval shorthand -> 6-field cron
/// assert_eq!(parse_schedule("5m").unwrap(), "0 */5 * * * *");
///
/// // 5-field cron is normalized to 6 fields by prepending "0 "
/// assert_eq!(parse_schedule("*/15 * * * *").unwrap(), "0 */15 * * * *");
/// ```
pub fn parse_schedule(input: &str) -> Result<String, String> {
    let trimmed = input.trim();

    // Try interval shorthand first (e.g. "5m", "1h", "1d", "30s").
    if let Some(expr) = try_parse_interval(trimmed)? {
        validate_cron_expression(&expr)?;
        return Ok(expr);
    }

    // Count fields to distinguish 5-field vs 6-field cron.
    let field_count = trimmed.split_whitespace().count();
    let expr = match field_count {
        5 => format!("0 {trimmed}"),
        6 => trimmed.to_string(),
        _ => {
            return Err(format!(
                "invalid schedule '{trimmed}': expected an interval (e.g. '5m', '1h', '1d') \
                 or a 5- or 6-field cron expression"
            ));
        }
    };

    validate_cron_expression(&expr)?;
    Ok(expr)
}

/// Parse an interval shorthand like `15m`, `2h`, or `1d` into a 6-field cron expression.
///
/// Returns `Ok(Some(expr))` with a 6-field cron expression when `input` is a supported interval
/// shorthand (`Nm`, `Nh`, `Nd` where N >= 1). Returns `Ok(None)` if `input` does not end with a
/// recognized interval suffix (not an interval shorthand). Returns `Err` with a human-readable
/// message for invalid numeric values, zero, intervals below the 1-minute minimum (seconds), or
/// values that exceed supported maxima (minutes > 59, hours > 23, days > 31).
///
/// # Examples
///
/// ```
/// assert_eq!(try_parse_interval("15m"), Ok(Some("0 */15 * * * *".to_string())));
/// assert_eq!(try_parse_interval("1d"), Ok(Some("0 0 0 * * *".to_string())));
/// assert_eq!(try_parse_interval("garbage"), Ok(None));
/// assert!(try_parse_interval("30s").is_err());
/// ```
fn try_parse_interval(input: &str) -> Result<Option<String>, String> {
    let (value_str, unit) = if let Some(s) = input.strip_suffix('m') {
        (s, 'm')
    } else if let Some(s) = input.strip_suffix('h') {
        (s, 'h')
    } else if let Some(s) = input.strip_suffix('d') {
        (s, 'd')
    } else if let Some(s) = input.strip_suffix('s') {
        (s, 's')
    } else {
        return Ok(None);
    };

    let n: u64 = value_str.parse().map_err(|_| {
        format!("invalid interval '{input}': '{value_str}' is not a valid integer")
    })?;

    if n == 0 {
        return Err(format!("invalid interval '{input}': value must be at least 1"));
    }

    match unit {
        's' => Err(format!(
            "interval '{input}' is below the minimum of 1 minute"
        )),
        'm' => {
            if n > 59 {
                return Err(format!(
                    "interval '{input}' exceeds maximum of 59 minutes"
                ));
            }
            Ok(Some(format!("0 */{n} * * * *")))
        }
        'h' => {
            if n > 23 {
                return Err(format!(
                    "interval '{input}' exceeds maximum of 23 hours"
                ));
            }
            Ok(Some(format!("0 0 */{n} * * *")))
        }
        'd' => {
            if n > 31 {
                return Err(format!(
                    "interval '{input}' exceeds maximum of 31 days"
                ));
            }
            if n == 1 {
                Ok(Some("0 0 0 * * *".to_string()))
            } else {
                // There's no "*/n" for days-of-month in a clean way; use step notation.
                Ok(Some(format!("0 0 0 */{n} * *")))
            }
        }
        _ => unreachable!(),
    }
}

/// Validates a 6-field cron expression and returns an error message if parsing fails.
///
/// # Examples
///
/// ```
/// let ok = validate_cron_expression("0 0 * * * *");
/// assert!(ok.is_ok());
///
/// let err = validate_cron_expression("99 * * * * *");
/// assert!(err.is_err());
/// ```
fn validate_cron_expression(expr: &str) -> Result<(), String> {
    Schedule::from_str(expr)
        .map_err(|e| format!("invalid cron expression '{expr}': {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cron::Schedule;
    use std::str::FromStr;

    #[test]
    fn test_interval_5m_to_cron() {
        let result = parse_schedule("5m").unwrap();
        assert_eq!(result, "0 */5 * * * *");
    }

    #[test]
    fn test_interval_1h_to_cron() {
        let result = parse_schedule("1h").unwrap();
        assert_eq!(result, "0 0 */1 * * *");
    }

    #[test]
    fn test_interval_1d_to_cron() {
        let result = parse_schedule("1d").unwrap();
        assert_eq!(result, "0 0 0 * * *");
    }

    #[test]
    fn test_interval_15m_to_cron() {
        let result = parse_schedule("15m").unwrap();
        assert_eq!(result, "0 */15 * * * *");
    }

    #[test]
    fn test_interval_30m_to_cron() {
        let result = parse_schedule("30m").unwrap();
        assert_eq!(result, "0 */30 * * * *");
    }

    #[test]
    fn test_interval_6h_to_cron() {
        let result = parse_schedule("6h").unwrap();
        assert_eq!(result, "0 0 */6 * * *");
    }

    #[test]
    fn test_5field_cron_normalises_to_6field() {
        let result = parse_schedule("*/5 * * * *").unwrap();
        assert_eq!(result, "0 */5 * * * *");
    }

    #[test]
    fn test_6field_cron_passes_through() {
        let result = parse_schedule("0 */10 * * * *").unwrap();
        assert_eq!(result, "0 */10 * * * *");
    }

    #[test]
    fn test_interval_below_1m_errors() {
        let err = parse_schedule("30s").unwrap_err();
        assert!(
            err.contains("below the minimum"),
            "expected 'below the minimum' in: {err}"
        );
    }

    #[test]
    fn test_invalid_input_errors() {
        // Completely invalid string
        let err = parse_schedule("garbage").unwrap_err();
        assert!(!err.is_empty(), "expected an error for 'garbage'");

        // Invalid cron expression (out-of-range field)
        let err2 = parse_schedule("99 * * * *").unwrap_err();
        assert!(!err2.is_empty(), "expected an error for invalid cron");
    }

    #[test]
    fn test_interval_too_many_minutes_errors() {
        let err = parse_schedule("90m").unwrap_err();
        assert!(
            err.contains("exceeds maximum of 59 minutes"),
            "expected 'exceeds maximum of 59 minutes' in: {err}"
        );
    }

    #[test]
    fn test_interval_too_many_hours_errors() {
        let err = parse_schedule("25h").unwrap_err();
        assert!(
            err.contains("exceeds maximum of 23 hours"),
            "expected 'exceeds maximum of 23 hours' in: {err}"
        );
    }

    #[test]
    fn test_cron_next_occurrence() {
        let expr = parse_schedule("5m").unwrap();
        let schedule = Schedule::from_str(&expr).expect("should parse as Schedule");
        let upcoming: Vec<_> = schedule.upcoming(chrono::Utc).take(3).collect();
        assert_eq!(upcoming.len(), 3, "should produce 3 upcoming times");
        // Each consecutive time should be later than the previous.
        for window in upcoming.windows(2) {
            assert!(
                window[1] > window[0],
                "upcoming times should be in ascending order"
            );
        }
    }
}
