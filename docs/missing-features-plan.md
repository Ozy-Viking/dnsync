# Missing Features Plan

Status: **proposed** — awaiting owner review. Date: 2026-07-02.

This is a repo-wide gap analysis and implementation plan. The yardstick is
`AGENTS.md`: every commitment it makes ("the MCP surface is a full peer to the
CLI", "DNS transport validation is first-class", "validation, benchmarking,
cache management … exist to support that mission") was checked against what the
code actually ships. Secondary sources: open items in `TODO.md`, the gap
analysis in `docs/dns-sync-ip-mapping.md` (gaps 3, 4 and 6 were explicitly not
addressed by the sync feature), `docs/validation_endpoint_analysis.md`, and a
sweep of `src/` (CLI `Command` enum vs. the MCP `#[tool]` surface, capability
usage, README coverage).

Every item below inherits the standing constraints from `AGENTS.md`:

- CLI and MCP land **together** — a CLI command with no MCP tool is incomplete.
- Vendor specifics stay in `vendors/<vendor>/`; DNS concepts go in `core/` /
  `control_plane/` (see `docs/function-placement-guide.md`).
- Safety is structural: dry-run by default for anything that writes, MCP
  access/zone policy enforced, no interactive prompts on production paths.
- Transport work targets all four: DNS, DoT, DoH, DoQ.
- Tick/extend `TODO.md` as each item lands.

---

## Priority 1 — deliver on stated commitments

### 1.1 `dns validate` + MCP `dns_validate` (wire up the dormant validation layer)

**Gap.** `AGENTS.md` calls DNS transport validation first-class and "being
added now", but the entire validation layer (`core/dns/validation/` — types,
`HickoryDnsEndpointResolver`, `compare_rrsets`, `ValidationReport`) is dead
code at runtime. `docs/validation_endpoint_analysis.md` confirms: *"No CLI/MCP/
vendor code calls `HickoryDnsEndpointResolver::query_endpoint()` or related
validation functions."* Even `ValidationEndpointConfig.enabled` is parsed but
never consulted. A validation layer that exists but is never run is the exact
failure mode `AGENTS.md` warns about: a tool that says DNS works when nobody
checked.

**Scope.**

- `dns validate [--server <ID>]... [--zone <ZONE>]... [--all-transports] [--json]`:
  for each selected server, fetch expected records through the vendor API
  (existing `ZoneRead`), resolve the same names through each configured
  transport block (`[servers.dns|dot|doh|doq]`, reusing the shared
  `ResolverTarget` builders), and compare with the existing
  `compare_rrsets` / `ValidationReport` machinery.
- Honour legacy `[[servers.validation_endpoints]]` and start consulting the
  `enabled` flag; keep the `no_validation_endpoints_configured` skip reason.
- MCP `dns_validate` with the same parameters and a stable JSON shape
  (read-only ⇒ allowed at `read` access; respects `allowed_zones`).
- Exit codes in the `dns query` style: 0 all-match, 1 mismatches, 2 errors.
- Follow-up (design doc first): grouped validation targets
  (`[[servers.validation_targets]]`, multiple transports per logical target)
  per the recommendation in `docs/validation_endpoint_analysis.md`.

**Touches** `core/dns/validation/`, `cli/` (new subcommand), `cli/dispatch/`,
`mcp/tools/` + `mcp/server/observe.rs`, README. **Size: L.**

### 1.2 Daemon parity on the MCP surface

**Gap.** The CLI has `dns job list`, `dns job run <id>`, and
`dns healthcheck`; the MCP server has no equivalent. Per `AGENTS.md`, any
CLI/MCP capability gap is a bug, and per-server `access` config — not
tool omission — is how operators throttle what MCP may do.

**Scope.**

- `dns_job_list` — configured jobs + last-run state from the state DB
  (read-only).
- `dns_job_run` — run one job now; dry-run by default with an `apply`
  parameter, gated by `write` access (or `delete` if the job prunes) and by
  `allowed_zones` against the job's zones.
- `dns_daemon_health` — the healthcheck read as a tool (read-only).
- Open question for the owner: an MCP equivalent of `dns config update` /
  `config add` would mutate the local config file from the MCP surface. Parity
  argues for it; the security model argues against. Flagged rather than
  assumed — decide before implementing (default: exclude, document the
  exception in `AGENTS.md`'s spirit of "say so loudly").

**Touches** `mcp/tools/`, `mcp/server/`, `daemon/commands/`, README. **Size: M.**

### 1.3 `dns diff` + MCP `dns_diff`

**Gap.** Tracked in `TODO.md` ("Add MCP `diff` tool to ship alongside any
future `dns diff` CLI command"). Sync already computes exactly this — a
`build_sync_plan` diff — but the only way to see it is `dns sync` (dry run),
which frames everything as pending writes and requires write intent.

**Scope.** `dns diff --from <ID> --to <ID> [--zone <ZONE>]... [--map ...]
[--json]`: run the existing sync planner, render as a comparison (adds /
changes / destination-only) with no apply path at all. Read-only ⇒ usable at
`read` access, which makes it the safe MCP answer for "are these servers in
sync?". Ships with `dns_diff`.

**Touches** `control_plane/sync/` (reuse plan + render), `cli/`,
`mcp/tools/sync.rs`, README. **Size: S–M** (planner exists).

### 1.4 `dns query --compare`

**Gap.** Tracked in `TODO.md` as the query-side complement of 1.3: diff
*resolved answers* across multiple resolvers/transports instead of vendor-API
record sets — the tool for "dns1 and dns2 disagree" and split-horizon checks.

**Scope.** `--compare` on `dns query`: fan out exactly as today (`--server`,
`--all-servers`, `--all-transports`, ad-hoc `@`), then pivot the result blocks
into a per-name/type comparison table highlighting disagreements; nonzero exit
on divergence. Mirror in `dns_resolve` via a `compare` parameter reusing the
same JSON shape.

**Touches** `cli/query/` (new output mode), `mcp/tools/resolve.rs`, README.
**Size: M.**

---

## Priority 2 — structural robustness

### 2.1 Enforce `VendorCapabilities` in the control plane

**Gap.** Gap 4 of the audit in `docs/dns-sync-ip-mapping.md`, still open:
`VendorCapabilities` is populated by every vendor but consulted only by tests
and the runtime delegation macro. Unsupported operations are hand-coded
`Error::unsupported` calls scattered through vendor services, and nothing
user-facing tells an operator up front what a vendor can do.

**Scope.**

- Central pre-flight check in the control plane (CLI dispatch + MCP tool
  entry): consult `capabilities()` before invoking an operation and return the
  uniform unsupported error — vendors keep their impls as a backstop.
- Expose the capability matrix: extend `dns_list_servers` output and add a
  `dns config`-adjacent CLI view so "UniFi can't manage zones" is discoverable
  rather than a runtime surprise (README currently explains this only in
  prose).
- Coordinate with in-flight **PR #56** (`unifi external api`) — it adds
  site-based zone listing to UniFi, which changes that vendor's matrix. Land
  this after #56 merges or rebase over it.

**Touches** `control_plane/`, `vendors/runtime.rs`, `mcp/server/meta.rs`,
`cli/`. **Size: M.**

### 2.2 Test-coverage debts (from `TODO.md`)

- Integration/fixture coverage for the newer vendor adapters (UniFi, Pi-hole,
  Cloudflare) focusing on **write paths** and unsupported-operation behaviour —
  `tests/` today leans on read-path client tests. **Size: M.**
- End-to-end DoQ validation tests that run when built with `--features doq`
  (feature is in defaults, so CI already builds it; the tests are the missing
  half). **Size: S–M.**

### 2.3 Clippy `-D warnings` cleanup

Pre-existing lint debt tracked in `TODO.md` (`empty_lines_after_doc_comment`,
`field_reassign_with_default`, `useless_conversion` in `worker.rs` /
`pihole/mapping.rs`, …). One sweep to zero warnings, then turn on
`cargo clippy --all-features --all-targets -- -D warnings` in
`.github/workflows/rust.yml` so the debt can't re-accumulate. **Size: S.**

---

## Priority 3 — promised features and follow-ons

### 3.1 `dns bench` + MCP `dns_benchmark`

**Gap.** Benchmarking is named in `AGENTS.md` as part of the mission and in
README / `docs/vendor-mapping.md` as a purpose of the per-server transport
blocks ("used by `dns query` …, endpoint validation, and future
benchmarking"). Nothing exists.

**Scope.** `dns bench [--server <ID>]... [--all-transports] [-t TYPE]
[--count N] [--concurrency C] [--json]`: repeated resolutions through the
shared `ResolverTarget` layer, reporting min/median/p95/max latency, success
rate, and per-transport comparison across DNS/DoT/DoH/DoQ. Read-only,
headless, table + `--json`. MCP `dns_benchmark` with the same shape (with a
conservative default `count` so an LLM can't accidentally hammer a resolver).

**Touches** new `core/dns/bench/` (or `control_plane`), `cli/`, `mcp/tools/`,
README. **Size: M–L.**

### 3.2 Bulk record operations

**Gap.** Gap 6 of the sync audit, still open: every record add/delete is one
HTTP call, so large sync applies and zone imports are slow against
rate-limited APIs (Cloudflare in particular has batch endpoints).

**Scope.** Optional `RecordWriteBulk` capability + trait with a default
implementation that loops single calls; implement natively where the vendor
API supports batching; have sync apply and zone import route through it.
No CLI surface change required (it's a performance feature), but `--json`
summaries should report batch counts. **Size: M.**

### 3.3 Consume `ServerLocation` (design first)

**Gap.** Gap 3 of the sync audit: the config classifies every server as
local/external (`resolved_location`), and nothing uses it. Candidate uses:
defaulting sync direction warnings (writing to an *external* authority from an
internal source deserves a louder prompt-free warning), generalizing
`--use-local-ip` beyond Pangolin, and validation expectations for
split-horizon zones. This needs a short design doc before code — the right
consumer isn't obvious, and `AGENTS.md` says push back rather than guess.
**Size: S (doc) + TBD.**

### 3.4 Ledger writes via `spawn_blocking`

Conditional item from `TODO.md`: move the daemon executor's inline SQLite
ledger calls onto `spawn_blocking` **if contention shows up**. Keep as a
watch-item; pair naturally with 2.2's daemon-side tests. **Size: S.**

---

## Priority 4 — documentation gaps (cheap, high leverage)

The README stops at the Claude Desktop MCP snippet and never mentions several
shipped subsystems. For a project whose primary deployment target is "a Docker
container configured entirely through `config.toml`" (`AGENTS.md`), the Docker
path being undocumented is the most glaring gap.

- **Daemon & jobs**: `dns daemon`, `[[jobs]]` config (kinds `record_sync` /
  `zone_sync` / `zone_export`, `schedule`/`interval`/`jitter`/`timezone`,
  `prune_synced`, `dry_run`, `critical`), `dns job list|run`,
  `dns healthcheck`. None of it is in the README today.
- **Docker / deployment**: document `Dockerfile`, `deploy/docker-compose.yml`
  (healthcheck wiring, read-only fs, state volume) and
  `deploy/dnsync.service`.
- **`dns logs`**: implemented (with `--start`/`--end`/`--level` time parsing)
  but absent from the README command list.
- **MCP tool catalog**: a table of the ~30 `dns_*` tools with the access level
  each requires, so operators can write `access` policy deliberately.
- **`dns config update`** exists in the CLI but is not in the README config
  section.

**Size: S–M total**, no code risk — good first slice.

---

## Suggested sequencing

| Order | Item | Why this order |
|---|---|---|
| 1 | 4.x docs sweep | Zero risk, closes the operator-facing gap immediately |
| 2 | 1.1 `dns validate` | The loudest unmet `AGENTS.md` commitment; unblocks 2.2's DoQ tests |
| 3 | 1.3 `dns diff` | Small, reuses the sync planner, closes a `TODO.md` parity item |
| 4 | 1.2 daemon MCP parity | Closes the remaining CLI/MCP gap |
| 5 | 2.1 capabilities (after PR #56) | Structural; avoids conflicting with the in-flight UniFi work |
| 6 | 2.2 + 2.3 tests & clippy gate | Hardens before feature growth |
| 7 | 1.4 `--compare`, 3.1 `bench` | Feature growth on the now-shared resolver layer |
| 8 | 3.2 bulk ops, 3.3 location design, 3.4 ledger | Performance / design follow-ons |

Each item is a separate PR, keeps the build green, updates `TODO.md` in the
same commit, and adds/updates docs alongside code per the house rules.

## Explicitly not planned

- Changing the `bye felicia` `Error::UserCancelled` wording — owner decision
  already recorded in `TODO.md`.
- MCP config-file mutation tools — pending the owner call flagged in 1.2.
- New vendors — out of scope here; `docs/new-vendor.md` + the PR template
  already cover that path.
