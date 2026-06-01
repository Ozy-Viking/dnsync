//! CLI-side time-argument parsing for the `logs` command.
//!
//! Converts user-supplied `--start`/`--end` values (relative durations, times of
//! day, or ISO 8601 strings) into ISO 8601 datetime strings.

/// Resolve a time argument to an ISO 8601 datetime string.
///
/// Accepts three forms:
/// 1. Relative duration (`10m`, `2h`, `1d`, `30s`) — subtracted from now
/// 2. Time of day (`HH:MM` or `HH:MM:SS`) — resolved to the most recent past occurrence
/// 3. Any other string — returned unchanged (assumed ISO 8601)
pub fn resolve_time(s: &str) -> String {
    if let Some(offset_secs) = parse_relative_duration(s) {
        let now = now_unix_secs();
        return unix_to_iso8601(now.saturating_sub(offset_secs));
    }
    if let Some(day_secs) = parse_time_of_day(s) {
        let now = now_unix_secs();
        let today_midnight = now - (now % 86400);
        let candidate = today_midnight + day_secs;
        let target = if candidate > now {
            candidate.saturating_sub(86400)
        } else {
            candidate
        };
        return unix_to_iso8601(target);
    }
    s.to_string()
}

fn parse_relative_duration(s: &str) -> Option<u64> {
    let (num_str, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = num_str.parse().ok()?;
    match unit {
        "s" => Some(n),
        "m" => Some(n * 60),
        "h" => Some(n * 3600),
        "d" => Some(n * 86400),
        _ => None,
    }
}

fn parse_time_of_day(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    let h: u64 = parts[0].parse().ok()?;
    let m: u64 = parts[1].parse().ok()?;
    let sec: u64 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
    if h >= 24 || m >= 60 || sec >= 60 {
        return None;
    }
    Some(h * 3600 + m * 60 + sec)
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_to_iso8601(secs: u64) -> String {
    let (year, month, day) = days_to_ymd(secs / 86400);
    let t = secs % 86400;
    let h = t / 3600;
    let m = (t % 3600) / 60;
    let s = t % 60;
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}")
}

fn days_to_ymd(mut days: u64) -> (u32, u8, u8) {
    let mut year = 1970u32;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let month_lens = [
        31u8,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u8;
    for &ml in &month_lens {
        if days < ml as u64 {
            break;
        }
        days -= ml as u64;
        month += 1;
    }
    (year, month, days as u8 + 1)
}

fn is_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}
