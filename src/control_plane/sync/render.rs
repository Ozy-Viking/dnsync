//! sync plan table and JSON rendering.

use super::*;

/// A compact, human-readable rendering of a record's value.
pub(crate) fn value_display(record: &RecordData) -> String {
    record
        .to_api_params()
        .into_iter()
        .skip(1) // drop the leading ("type", ...) param
        .map(|(_, value)| value)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Print the sync plan as an aligned table.
pub(crate) fn render_table(from_id: &str, to_id: &str, plans: &[ZonePlan], apply: bool) {
    let mode = if apply { "apply" } else { "dry run" };
    println!("Sync plan: {from_id} -> {to_id}  ({mode})");

    let mut adds = 0;
    let mut deletes = 0;
    let mut unchanged = 0;
    let mut skipped = 0;
    let mut untouched = 0;

    for plan in plans {
        adds += plan.adds.len();
        deletes += plan.deletes.len();
        unchanged += plan.unchanged;
        skipped += plan.skipped;
        untouched += plan.untouched;

        if plan.adds.is_empty() && plan.deletes.is_empty() {
            continue;
        }
        println!("\nZone: {}", plan.zone);
        for rec in &plan.adds {
            println!(
                "  + {:<28} {:<6} {}",
                rec.fqdn,
                rec.rtype,
                value_display(&rec.record)
            );
        }
        for rec in &plan.deletes {
            println!(
                "  - {:<28} {:<6} {}",
                rec.fqdn,
                rec.rtype,
                value_display(&rec.record)
            );
        }
    }

    println!(
        "\n{adds} to add, {deletes} to remove, {unchanged} unchanged, \
         {skipped} skipped (not syncable)."
    );
    if untouched > 0 {
        println!("{untouched} destination record(s) absent from the source were left untouched.");
    }
    if adds + deletes == 0 {
        println!("Already in sync — nothing to do.");
    } else if !apply {
        println!("Dry run — no changes written. Re-run with --apply to commit.");
    }
}

/// Print the sync plan as JSON.
pub(crate) fn sync_plan_json(
    from_id: &str,
    to_id: &str,
    plans: &[ZonePlan],
    apply: bool,
) -> serde_json::Value {
    let rec_json = |rec: &PlannedRecord| {
        serde_json::json!({
            "name": rec.fqdn,
            "type": rec.rtype,
            "ttl": rec.ttl,
            "value": value_display(&rec.record),
        })
    };

    let zones: Vec<_> = plans
        .iter()
        .map(|plan| {
            serde_json::json!({
                "zone": plan.zone,
                "add": plan.adds.iter().map(rec_json).collect::<Vec<_>>(),
                "remove": plan.deletes.iter().map(rec_json).collect::<Vec<_>>(),
                "unchanged": plan.unchanged,
                "untouched": plan.untouched,
                "skipped": plan.skipped,
            })
        })
        .collect();

    serde_json::json!({
        "from": from_id,
        "to": to_id,
        "applied": apply,
        "zones": zones,
    })
}
