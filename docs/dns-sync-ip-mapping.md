# Record Sync with IP Mapping

This document is the audit + design record for the `dns sync` feature: a
record-level sync between two configured DNS servers that can rewrite specific
IP addresses en route (for example, mapping a public/external address to its
internal LAN equivalent — "split-horizon" DNS).

## Background — gap analysis

`dnsync` is named for **DNS sync**, but before this feature the only sync
primitive was `dns zone transfer`: a coarse BIND-file export→import between two
configured servers. The audit found the following gaps.

1. **No record-level sync.** `zone transfer` is an all-or-nothing BIND-file
   copy — no diffing, no idempotency, no dry-run, no per-record transformation.
   Pangolin cannot participate at all (it has no zone import/export).
2. **No IP transformation / split-horizon support.** There was no way to
   declare "external IP X equals internal IP Y". The closest existing feature,
   `--use-local-ip`, is Pangolin-only, a read/display-time preference, and
   relies on live resolution finding a private address rather than an explicit
   declared mapping.
3. **`ServerLocation` (local/external) was computed but unused.** The config
   already classifies each server as local or external; nothing consumed it.
4. **`VendorCapabilities` is barely used.** Operations do not check vendor
   capabilities before calling; unsupported-operation errors are hand-coded.
5. **Typed record data is lost cross-vendor.** `ZoneRecord.parsed` is only
   populated on the Technitium list path; other vendors leave it `None`, and
   the parsing helper was private — so no feature could rely on typed records.
6. **No bulk record operations.** Record add/delete is one HTTP call each.
7. **Docs/metadata drift.** `TODO.md` referenced docs that no longer exist;
   `Cargo.toml` still described the project as Technitium-only.

This feature addresses gaps 1, 2 and 5 directly.

## `dns sync`

A new vendor-neutral command that copies records from a source server to a
destination server, applying an explicit IP-address mapping to A/AAAA records.

```bash
dns sync <PROFILE>                                  # run a named profile (dry run)
dns sync <PROFILE> --apply                          # commit the changes
dns sync --from cf --to home --zone example.com \
         --map 203.0.113.10=192.168.1.10            # ad-hoc, no profile
```

### Behaviour

- **Dry-run by default.** Sync prints the planned changes and writes nothing.
  Pass `--apply` to commit.
- **Additive.** Sync adds records missing on the destination and updates record
  sets whose values differ (adding new values, removing stale ones within that
  same name+type set). Record sets that exist only on the destination — names
  the source does not have at all — are never pruned.
- **IP mapping.** For `A` and `AAAA` records, if the address matches a mapping
  entry, the mapped address is written instead. All other record types and
  unmapped addresses pass through unchanged.
- **Vendor-neutral.** Works between any pair of supported vendors (Technitium,
  Pangolin, Cloudflare), because it reads records and writes individual records
  through the shared `core::dns` traits rather than through zone files.
- Server-managed records (SOA, DNSSEC: RRSIG/DNSKEY/NSEC/NSEC3) and disabled
  records are skipped. Source TTLs are preserved.

### Flags

| Flag | Meaning |
|---|---|
| `<PROFILE>` | Named `[[sync]]` profile from the config file |
| `--from <id>` | Source server id (overrides the profile) |
| `--to <id>` | Destination server id (overrides the profile) |
| `--zone <zone>` | Zone to sync, repeatable (overrides the profile) |
| `--map SRC=DST` | IP rewrite for A/AAAA records, repeatable (merges over the profile) |
| `--apply` | Commit the changes (otherwise sync only previews) |
| `--json` | Emit the sync plan as JSON |

When no zone is given, sync covers every zone found on the source server.

### Config — `[[sync]]` profiles

Sync pairs and their IP-mapping tables can be stored in the config file as
named profiles, alongside `[[servers]]`:

```toml
[[sync]]
name  = "home"             # dns sync home
from  = "cf"               # source server id (a [[servers]] entry)
to    = "home"             # destination server id
zones = ["example.com"]    # optional; omit to sync all source zones

[sync.ip_map]
"203.0.113.10" = "192.168.1.10"
"203.0.113.11" = "192.168.1.11"
```

`from`/`to` must reference real server ids. Each `ip_map` pair must be a valid
IP address, and both sides must be the same family (IPv4↔IPv4 or IPv6↔IPv6);
the config loader rejects mismatches.

CLI flags override the profile; `--map` entries merge into and override the
profile's `ip_map`.

## Known parity gaps (required work)

Per `agents.md` ("The MCP surface is a full peer to the CLI… Treat any gap
between CLI and MCP capability as a bug"), the following gaps are **bugs to be
fixed**, not optional enhancements:

- **MCP `sync` tool** — `dns sync` exists on the CLI but has no MCP equivalent.
  The MCP server must expose a `sync` tool that mirrors the CLI surface
  (profiles, `--from`/`--to`/`--zone`/`--map`, dry-run-by-default, `--apply`).
- **MCP `diff` tool** — once `dns diff` lands as a CLI command, the matching
  MCP tool ships with it. A CLI-only `diff` would itself be a parity bug.

These items are tracked as required work and must not be re-classified as
"future" or "possible" features.

## Possible future features

The audit also surfaced a backlog of related capabilities worth considering:

- **CIDR/subnet remapping** — remap whole networks (`203.0.113.0/24` →
  `192.168.1.0/24`) instead of listing every host.
- **Per-hostname overrides** — force a record's value by name, not by IP.
- **`dns diff`** — drift report between two servers with no write path.
- **`dns sync --prune`** — opt-in mirror mode that removes destination records
  absent from the source.
- **Continuous / scheduled sync** — a `--watch` mode or cron-friendly runs.
- **Split-horizon via `ServerLocation`** — auto-select internal vs external
  addresses using the already-computed server location.
- **Capability-driven command gating** — make `VendorCapabilities` enforced,
  skipping record types a destination vendor cannot write.
- **Sync filters** — include/exclude by record type or name glob.
- **Conflict policy** — source-wins / destination-wins / interactive.
- **Zone backup & restore** plus an audit log of applied changes.
- **Dynamic DNS** — keep an `A` record pointed at the current public IP.
- **Additional vendors** — Route53, PowerDNS, BIND, AdGuard Home, Pi-hole.
