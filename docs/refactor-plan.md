# DNSync Codebase Audit & Refactor Plan

Status: **executed**. All 24 files >500 LOC were split into modules, `main.rs`
is an entry point only, and the deep relayering (R1/R2) landed. R3 (`clap` in
`core`) was resolved by keeping the derives and documenting the exception (no
duplication), per the maintainer's call. The phases below record the original
plan; see `TODO.md` for the completion checklist.

Scope agreed: *everything* — split every file >500 LOC into modules, reduce
`main.rs` to an entry point, and perform the deep relayering that pulls vendor
specifics out of `core`.

This plan is the contract for the refactor. Each phase is independently
compilable and committed; the build stays green between phases.

---

## 1. Audit findings

### 1.1 Files over 500 lines (24)

| LOC | File | Dominant content |
|----:|------|------------------|
| 3999 | `control_plane/config.rs` | schema + load/save + toml render + validation + defaults |
| 2399 | `cli/query.rs` | query args, planning, execution, table/json output, tests |
| 1604 | `control_plane/sync.rs` | plan/diff/apply + render + ~680 LOC tests |
| 1249 | `core/dns/records.rs` | `RecordData`/`RecordSelector` + DNSSEC enums + ops + tests |
| 1170 | `mcp/server.rs` | `DnsServer` + ~40 `#[tool]` handlers + `ServerHandler` |
| 1158 | `core/dns/validation.rs` | types + resolver + compare + ~550 LOC tests |
|  974 | `vendors/cloudflare/service.rs` | DNS trait impls |
|  788 | `cli/interactive.rs` | add/server wizards |
|  763 | `main.rs` | **full command dispatch (rule violation)** |
|  740 | `vendors/pangolin/service.rs` | DNS trait impls |
|  687 | `control_plane/policy.rs` | `Policy`, `PolicyRule`, checks |
|  648 | `vendors/unifi/mapping.rs` | record mapping |
|  647 | `cli/mod.rs` | `Cli` + all subcommand enums |
|  619 | `daemon/commands.rs` | job list/run, healthcheck |
|  619 | `core/dns/responses.rs` | **neutral structs + Technitium JSON parsing (leak)** |
|  594 | `core/dns/resolver.rs` | hickory resolver builders per transport |
|  557 | `daemon/runtime.rs` | daemon foreground loop |
|  533 | `core/dns/records/query.rs` | `list_records_for_query` + helpers |
|  527 | `vendors/cloudflare/mapping.rs` | record mapping |
|  520 | `vendors/pihole/service.rs` | DNS trait impls |
|  519 | `vendors/unifi/client.rs` | HTTP endpoints |
|  518 | `vendors/unifi/service.rs` | DNS trait impls |
|  517 | `daemon/db/store.rs` | diesel queries |
|  501 | `vendors/technitium/service.rs` | DNS trait impls |

### 1.2 Location / layering problems (vs. `docs/function-placement-guide.md`)

- **L1 — `main.rs` does the work.** Owns `run_inner` (the whole command match),
  `run_mcp` (starts the rmcp server), `run_zone_transfer`, `build_endpoint_update`.
  The user's rule: entry point only.
- **L2 — `cli/runner.rs` is the central CLI runner.** Guide §11 wants no central
  runner; CLI should be command shapes only. `runner.rs` also holds generic
  time-parsing utilities (`resolve_time`, `unix_to_iso8601`, …).
- **R1 — Technitium error variant in `core::error`.** `Error` carries a
  Technitium-specific variant with Technitium hint text.
- **R2 — Technitium JSON parsing in `core::dns::responses`.** `ListRecordsResponse::from_value`
  + `parse_record_data` know vendor field shapes. The structs are neutral; the
  *parsing* is vendor-specific and must move to `vendors/technitium`.
- **R3 — `clap` in `core`.** `core::dns::records` (`RecordData`, `RecordSelector`),
  `core::dns::zones` (`ZoneImportOptions`), `core::dns::logs` (`LogLevel`) derive
  clap traits. Guide flags `core/* imports clap` as a smell.
- **D1 — Guide is stale.** It documents nothing about `daemon/`, `vendors/unifi`,
  `vendors/pihole`, `formatter`, `core::dns::{resolver,validation,names,capabilities}`,
  or `control_plane::transfer`. The guide must be updated to match reality.

---

## 2. Target module structure

Convention for every split: `foo.rs` → `foo/mod.rs` (public API + re-exports) plus
submodules by responsibility, and `#[cfg(test)] mod tests;` → `foo/tests.rs`.
Public paths are preserved via re-exports so downstream `use` sites don't churn.

### 2.1 `main.rs` (763 → ~60 LOC)  [Phase 1]

Keeps only: feature `compile_error!` guards, `main()` (parse → `init_tracing` →
dispatch → error/exit mapping). Everything else moves to a new `cli::dispatch`:

```text
src/cli/dispatch/
  mod.rs          run(cli), run_inner(cli) top-level match, run_with_client
  config_cmd.rs   ConfigCmd handling + build_endpoint_update
  daemon_cmd.rs   Daemon / Job / Healthcheck handling
  cross_server.rs record-list-across-servers, zone transfer, sync orchestration
  logs_time.rs    resolve_time + duration/time-of-day parsing (from runner.rs)
  tests.rs        (moved from main.rs)
```

- `run_mcp`'s rmcp `.serve()` body moves into **`mcp::server::serve_stdio(config, access, allow_zone)`**
  so `cli` never imports `rmcp` (fixes the only new smell this would create).
- **`cli/runner.rs` is deleted** (L2): its `run()` dispatch folds into
  `cli::dispatch`, `run_record_list_across_servers` → `cross_server.rs`, time
  helpers → `logs_time.rs`.

### 2.2 `control_plane/config/` (3999)  [Phase 2 — largest]

```text
control_plane/config/
  mod.rs        re-exports; AppConfig::{load,load_if_exists,selected_server,validate orchestration,redact}
  types/
    mod.rs      re-exports
    server.rs   DnsServerConfig, DnsServerConfigRaw (+From), AppConfig, McpPermissions
    transport.rs DnsTransportConfig, Dot/Doh/Doq configs, ValidationTransport
    cluster.rs  ClusterConfig, ClusterWritePolicy
    validation_endpoint.rs ValidationEndpointConfig (+FromStr)
    daemon.rs   DaemonConfig, JobConfig, JobKind, default_* fns
    vendor.rs   VendorKind, ServerLocation
  defaults.rs   apply_*_transport_defaults, default_base_url, add_missing_server_defaults, update_defaults, UpdateDefaultsReport
  validate.rs   validate_validation_endpoints, validate_server_transports, validate_clusters, validate_jobs, validate_ip_pair_for_job
  render.rs     starter, render_toml, render_starter_toml, *_transport_table, append_{server,daemon,job,cluster}_entry, policy_rule_name, vendor_name
  persist.rs    init_config, add_server, update_server_endpoint, EndpointUpdate, write_default_config, ensure_config_dir, load_from_path, write_private_file, restrict_dir_permissions, check_config_permissions
  resolve.rs    DnsServerConfig::{resolved_location,resolved_base_url,resolved_token}, url_host
```

### 2.3 `cli/query/` (2399)  [Phase 3]

```text
cli/query/
  mod.rs        QueryArgs, run_query (entry), re-exports
  parse.rs      split_targets, validate_cli_rules, parse_record_types, parse_ad_hoc, split_addr, describe_target
  plan.rs       QueryPlan/PlanTarget/TargetKind/NamedServer, build_*_plan, plan_targets_for_server, transport selection helpers
  execute.rs    execute_query, QueryOutcome, run_block, bootstrap_host/_doh_host, build_system_resolver, lookup_all, chase_chain, observed-record helpers
  result.rs     QueryResultBlock, QueryStatus, worst, exit_code_for
  output/
    mod.rs
    table.rs    print_table/header/rows, Row, expand_rows, print_short
    json.rs     Json* structs, print_json, build_json_value, json_result_for_block
  tests.rs
```

### 2.4 `control_plane/sync/` (1604)  [Phase 4]

```text
control_plane/sync/
  mod.rs    SyncDiffOptions, SyncApplySummary, run_sync, run_sync_json, re-exports
  plan.rs   PlannedRecord, Diff, ZonePlan, build_sync_plan, plan_zone(_with_clients), collect_records, diff_records, sort_key, canonical
  apply.rs  apply_plans(_with_client), apply_ip_map, parse_ip_pair
  render.rs render_table, sync_plan_json, value_display
  tests.rs
```

### 2.5 `core/dns/records/` (1249 — dir already exists w/ `query.rs`)  [Phase 5]

```text
core/dns/records/
  mod.rs       ops: list_records, create_record, delete_record; re-exports; pub mod query
  data.rs      RecordData (+impl type_name/to_api_params), default_* fns
  selector.rs  RecordSelector (+impl)
  enums.rs     DsAlgorithm, DigestType, Sshfp*, Tlsa*, FwdProtocol (+as_str)
  query/       (split of existing records/query.rs, Phase 12)
  tests.rs
```
R3 decision (clap) handled in Phase 13.

### 2.6 `mcp/server/` (1170)  [Phase 6]

```text
mcp/server/
  mod.rs      DnsServer, new, resolve_server, show_settings_secrets, ServerHandler, get_info, serve_stdio, tests
  zones.rs    zone tool handlers      #[tool_router(router = zones_router)]
  records.rs  record tool handlers    #[tool_router(router = records_router)]
  cache.rs    cache tool handlers
  access.rs   blocked/allowed handlers
  settings.rs settings + zone options handlers
  misc.rs     list_servers, get_config, version, stats, logs, sync, resolve
```
Routers merged in `mod.rs`. *Verification risk:* rmcp multi-`tool_router` merge —
confirmed against rmcp 1.7 before committing; fallback is grouping handlers into
fewer files. Handlers stay thin and delegate to `core::dns::*` (already do).

### 2.7 `core/dns/validation/` (1158)  [Phase 7]

```text
core/dns/validation/
  mod.rs      re-exports
  types.rs    ValidationOptions/Request/Report, ExpectedRecord, ObservedRecord, statuses, mismatches
  resolver.rs DnsEndpointResolver, HickoryDnsEndpointResolver, FakeDnsEndpointResolver, endpoint_timeout
  compare.rs  expected_records_from_response, compare_rrsets, normalize_*, fqdn_for_record
  tests.rs
```

### 2.8 Vendor service/mapping/client files  [Phases 8–11]

Split each oversized vendor file by **one file per trait impl** (a trait impl can't
straddle files) and by record-type groups for mapping:

- `vendors/cloudflare/service/` → `mod.rs` + `{zones,records,cache,stats,access,settings}.rs` (one per DNS sub-trait it implements).
- `vendors/cloudflare/mapping/` → `mod.rs` + `to_core.rs` / `from_core.rs` (+ tests).
- `vendors/pangolin/service/` → same trait-split pattern.
- `vendors/pihole/service/` → same.
- `vendors/technitium/service/` → same (only ~1 LOC over; minimal split).
- `vendors/unifi/service/` → same.
- `vendors/unifi/client/` → `mod.rs` + endpoint groups (`auth.rs`, `records.rs`, …).
- `vendors/unifi/mapping/` → `mod.rs` + `to_core.rs`/`from_core.rs` (+ tests).

### 2.9 `cli/mod.rs` (647)  [Phase 11]

```text
cli/
  mod.rs            Cli, Command, Command::name, pub mod decls
  commands/
    mod.rs
    config.rs       ConfigCmd, ServerEndpointCmd
    zone.rs         ZoneCmd
    record.rs       RecordCmd
    cache.rs        CacheCmd
    access.rs       BlockedCmd, AllowedCmd
    settings.rs     SettingsCmd
    job.rs          JobCmd
  tests.rs
```

### 2.10 `control_plane/policy/` (687)  [Phase 11]

```text
control_plane/policy/
  mod.rs   Policy, from_cli_and_config, check_zone, enforce, re-exports
  rule.rs  PolicyRule (+ parsing / ValueEnum)
  tests.rs
```

### 2.11 daemon + remaining core  [Phase 12]

- `daemon/commands/` → `mod.rs` + `jobs.rs` (list/run) + `health.rs`.
- `daemon/runtime/` → `mod.rs` + `loop.rs`/`setup.rs`.
- `daemon/db/store/` → `mod.rs` + `{jobs,runs,heartbeat}.rs` (+ tests).
- `core/dns/resolver/` → `mod.rs` + `{dns,dot,doh,doq}.rs` (+ tests).
- `core/dns/records/query/` → `mod.rs` + helpers (+ tests).

---

## 3. Deep relayering

### R1 — vendor-neutral error  [Phase 14]
Replace the Technitium-specific `Error` variant with a neutral
`Error::VendorApi { vendor, message, hint }`. Technitium hint text moves to
`vendors/technitium` which constructs the neutral error. Update `is_api_error`,
`exit_code`, and constructors accordingly.

### R2 — Technitium parsing out of `core::dns::responses`  [Phase 14]
Keep the neutral structs (`ZoneInfo`, `ZoneRecord`, `ListRecordsResponse`, DNSSEC
data types, `AnyRecordData`) in `core`. Move `ListRecordsResponse::from_value` and
`parse_record_data` (which know vendor JSON field names) into
`vendors/technitium/responses.rs` as `parse_list_records(value) -> ListRecordsResponse`.
Other vendors already map via their own `mapping.rs`; this removes the implicit
"core speaks Technitium" coupling. Move the related tests with the parser.

### R3 — `clap` out of `core`  [Phase 15 — recommend deferring]
`RecordData`/`RecordSelector`/`ZoneImportOptions`/`LogLevel` are shared domain
types that also happen to derive clap. Removing clap from `core` means either
(a) duplicating these as `cli`-side arg mirrors with `From` conversions, or
(b) accepting clap derives in `core` as a documented exception. Option (a) adds
significant mapping surface for `RecordData` (20+ variants) for little runtime
benefit. **Recommendation: option (b)** — keep the derives, add an explicit
"accepted exceptions" note to the guide. Flagged for your call before Phase 15
runs; the rest of the refactor does not depend on it.

### D1 — refresh the guide  [Phase 16]
Update `docs/function-placement-guide.md` to document `daemon/`, the full
`core::dns` resource set, `formatter`, `control_plane::transfer`, the new vendors,
and the `cli::dispatch` entry layer. Tick the relevant items in `TODO.md`.

---

## 4. Sequencing & verification

Phases run in order; **after each phase**: `cargo fmt --all`, `cargo check
--all-features`, `cargo test --all-features`, `cargo clippy --all-features
--all-targets -- -D warnings`, then commit. The branch
`claude/codebase-audit-refactor-unxya` accumulates one commit per phase, and a PR
is opened after the first pushed phase.

1. `main.rs` slim + `cli::dispatch` + delete `runner.rs` (L1, L2)
2. `control_plane/config/`
3. `cli/query/`
4. `control_plane/sync/`
5. `core/dns/records/`
6. `mcp/server/`
7. `core/dns/validation/`
8. cloudflare service+mapping
9. pangolin + technitium service
10. pihole service; unifi service+client+mapping
11. `cli/mod.rs` commands; `control_plane/policy/`
12. daemon (commands, runtime, db/store); `core/dns/resolver`; `records/query`
13. final size sweep (anything still >500 after moves)
14. R1 + R2 relayering
15. R3 (clap) — only if you approve option (a)
16. guide refresh + TODO tick

Net effect: 0 files >500 LOC, `main.rs` is an entry point only, no central CLI
runner, vendor specifics out of `core`, and a guide that matches the tree.
