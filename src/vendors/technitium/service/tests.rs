
use super::*;
use serde_json::json;

#[test]
fn latest_log_file_name_picks_latest_file() {
    let raw = json!({
        "response": {
            "logFiles": [
                {"fileName": "2026-05-28", "size": "1 KB"},
                {"fileName": "2026-05-29", "size": "2 KB"}
            ]
        },
        "status": "ok"
    });

    assert_eq!(latest_log_file_name(&raw).unwrap(), "2026-05-29");
}

#[test]
fn parse_log_file_extracts_and_filters_recent_lines() {
    let text = "\
[2026-05-29 05:36:25 Local] [10.2.65.122:0] [admin] New record was added to Primary zone 'hankin.io' successfully
[2026-05-29 05:36:30 Local] DNS Server failed to notify name server '10.5.161.84' (RCODE=Refused) for zone: hankin.io
[2026-05-29 05:36:31 Local] Saved zone file for domain: hankin.io
";

    let lines = parse_log_file(
        text,
        &LogsOptions {
            lines: Some(1),
            start: None,
            end: None,
            level: Some(LogLevel::Error),
        },
    );

    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].level, LogLevel::Error);
    assert_eq!(lines[0].title.as_deref(), Some("notify"));
    assert!(lines[0].message.contains("RCODE=Refused"));
}

#[test]
fn parse_log_file_line_ignores_unstructured_lines() {
    assert!(parse_log_file_line("not a technitium log line").is_none());
}
