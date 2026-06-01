//! dig-style table output.

use super::*;

// ───── Rendering ─────────────────────────────────────────────────────────────

pub(crate) fn print_table(blocks: &[QueryResultBlock], asked_types: &[String]) {
    let multi_type = asked_types.len() > 1;
    let multi_server = distinct_server_count(blocks) > 1;
    let mut first = true;
    let mut current_server: Option<&str> = None;
    for block in blocks {
        if !first {
            println!();
        }
        first = false;
        // When results span more than one server, group each server's
        // blocks under a `=== Server: id (vendor) ===` header (matching
        // the `record list` cross-server output style).
        if multi_server && block.server_id.as_deref() != current_server {
            current_server = block.server_id.as_deref();
            if let Some(id) = current_server {
                match block.server_vendor {
                    Some(vendor) => println!("=== Server: {id} ({vendor:?}) ==="),
                    None => println!("=== Server: {id} ==="),
                }
            }
        }
        print_header(block);
        println!();
        let rows = expand_rows(block, multi_type);
        print_rows(&rows, multi_type);
    }
}

/// Number of distinct named servers represented across the blocks. Used
/// to decide whether headers need to spell out which server a block
/// belongs to.
pub(crate) fn distinct_server_count(blocks: &[QueryResultBlock]) -> usize {
    let mut ids: Vec<&str> = blocks
        .iter()
        .filter_map(|b| b.server_id.as_deref())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids.len()
}

pub(crate) fn print_header(block: &QueryResultBlock) {
    let mut line = format!(
        "@ {}  {}",
        block.target_label,
        transport_word(block.transport)
    );
    for (k, v) in &block.extras {
        if v.is_empty() {
            line.push_str("  ");
            line.push_str(k);
        } else {
            let _ = write!(&mut line, "  {k}={v}");
        }
    }
    let _ = write!(&mut line, "  {}ms", block.elapsed.as_millis());
    println!("{line}");
}

#[derive(Debug)]
pub(crate) struct Row {
    name: String,
    rr_type: String,
    ttl: Option<String>,
    data: String,
}

pub(crate) fn expand_rows(block: &QueryResultBlock, _multi_type: bool) -> Vec<Row> {
    // For noerror, one row per record value; for non-noerror, one row
    // per asked type with the status word as the data field. Status
    // rows fall back to `queried_name` so NXDOMAIN/TIMEOUT/etc still
    // show what was asked.
    let mut rows = Vec::new();
    if let Some(status_word) = block.status.header_word() {
        let name = trim_trailing_dot(&block.queried_name).to_string();
        for rr_type in &block.asked_types {
            rows.push(Row {
                name: name.clone(),
                rr_type: rr_type.clone(),
                ttl: None,
                data: status_word.to_string(),
            });
        }
        return rows;
    }
    for record in &block.records {
        for value in &record.values {
            rows.push(Row {
                name: trim_trailing_dot(&record.name).to_string(),
                rr_type: record.record_type.clone(),
                ttl: record.ttl.map(|ttl| ttl.to_string()),
                data: value.clone(),
            });
        }
    }
    rows
}

pub(crate) fn trim_trailing_dot(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

pub(crate) fn print_rows(rows: &[Row], multi_type: bool) {
    if rows.is_empty() {
        return;
    }
    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    let type_w = rows.iter().map(|r| r.rr_type.len()).max().unwrap_or(0);
    let ttl_w = rows
        .iter()
        .map(|r| r.ttl.as_deref().unwrap_or("").len())
        .max()
        .unwrap_or(0);

    for row in rows {
        let mut line = String::new();
        let _ = write!(&mut line, "{:<name_w$}", row.name);
        if multi_type
            || ttl_w > 0
            || rows.iter().any(|r| r.ttl.is_some())
            || !row.rr_type.is_empty()
        {
            let _ = write!(&mut line, "  {:<type_w$}", row.rr_type);
        }
        if let Some(ttl) = &row.ttl {
            let _ = write!(&mut line, "  {:<ttl_w$}", ttl);
        }
        let _ = write!(&mut line, "  {}", row.data);
        println!("{line}");
    }
}

pub(crate) fn print_short(blocks: &[QueryResultBlock]) {
    for block in blocks {
        for record in &block.records {
            for value in &record.values {
                println!("{value}");
            }
        }
    }
}
