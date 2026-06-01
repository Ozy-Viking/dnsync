# DNSync Function Placement Guide

This document defines where functions, types, and modules should live in the `dnsync` Rust codebase.

The goal is to make the repository structure reflect responsibility, not historical placement.

## Core rule

Do not trust where a function currently lives.

A function should be placed according to what it actually does:

- DNS record behaviour belongs with DNS records.
- DNS zone behaviour belongs with DNS zones.
- DNS cache behaviour belongs with DNS cache.
- DNS stats behaviour belongs with DNS stats.
- DNS settings behaviour belongs with DNS settings.
- DNS allow/block/access-list behaviour belongs with DNS access lists.
- CLI and MCP are adapters only.
- Vendors are backend implementations only.
- Config and policy belong in the control plane.
- Shared DNS domain logic belongs in `core::dns`.

## Target architecture

```text
CLI command ─┐
             ├─> core::dns::<resource>::* ─> DNS traits ─> vendors::<vendor>::service ─> vendors::<vendor>::client
MCP tool  ───┘
```

For config commands:

```text
CLI config command ─> main.rs dispatch ─> control_plane::config
```

CLI and MCP should call the same underlying DNS resource operations wherever possible.

## Target top-level responsibilities

```text
src/
  main.rs
  cli/
  mcp/
  control_plane/
  core/
    dns/
  vendors/
```

## `main.rs`

`main.rs` owns:

- Program entrypoint.
- CLI parsing.
- Logging/tracing initialization.
- Process exit-code handling.
- Dispatching parsed CLI commands.

It may dispatch to:

- `control_plane::config` for config commands.
- `core::dns::<resource>` for DNS operations.
- `mcp::server` for MCP server startup.
- `cli::completions` for shell completions.

It must not own:

- DNS operation implementation.
- Vendor HTTP logic.
- MCP tool behaviour.
- Shared business logic.

## `cli/`

`cli/` owns CLI adapter shape only:

- CLI args.
- Subcommands.
- CLI-specific parameter structs.
- Shell completions.
- Interactive prompts/wizards.

Expected shape:

```text
src/cli/
  mod.rs            Cli + Command (top-level arg types only)
  commands.rs       subcommand enums (ConfigCmd, ZoneCmd, RecordCmd, ...)
  completions.rs
  interactive/      add/server wizards (wizards, prompts, display)
  query/            `dns query` (args, plan, execute, result, output)
  records.rs
  dispatch/         command dispatch invoked by main.rs
    mod.rs          top-level routing
    config_cmd.rs   config subcommand handling
    daemon_cmd.rs   daemon / job / healthcheck
    cross_server.rs record-list-across-servers, zone transfer
    client_cmd.rs   single-client command execution
    logs_time.rs    CLI time-argument parsing
```

`main.rs` is an entry point only: it parses the CLI, initialises tracing, and
calls `cli::dispatch::run`. There is **no central `cli/runner.rs`** — its old
responsibilities live in `cli::dispatch` (orchestration) and `core::dns`
(resource operations).

CLI code should not call vendor clients directly. The CLI layer must not import
`rmcp`; MCP startup goes through `mcp::server::serve_stdio`.

## `mcp/`

`mcp/` owns MCP adapter behaviour only:

```text
src/mcp/
  mod.rs
  server.rs
  params.rs
  helpers.rs
  tools/
    mod.rs
    records.rs
    zones.rs
    cache.rs
    stats.rs
    settings.rs
    access_lists.rs
```

MCP tools should:

1. Accept MCP params.
2. Convert MCP params into domain request types.
3. Call `core::dns::<resource>` operations.
4. Convert domain responses into MCP responses.

MCP tools should not:

- Call vendor clients directly.
- Duplicate CLI logic.
- Implement record/zone/cache/stats/settings logic directly.
- Own policy enforcement except through shared policy/context functions.

## `control_plane/`

`control_plane/` owns app-level control concerns:

```text
src/control_plane/
  mod.rs
  config.rs
  policy.rs
  app.rs
```

### `config.rs`

Owns:

- Config file schema.
- Config loading.
- Config saving.
- Config initialization.
- Config add/remove/list/update operations.
- Default vendor base URLs.
- Config redaction.
- Server selection.
- Vendor kind definitions, if applicable.

### `policy.rs`

Owns:

- Read-only checks.
- Allowed-zone checks.
- Permission evaluation.
- Policy structs.

### `app.rs`

May own:

- Runtime/app context creation.
- Shared context structs.
- Wiring config, selected vendor, and policy into a usable context.

`app.rs` must not become a dumping ground for DNS operations.

Do not put these in `control_plane::app`:

- `list_records`
- `create_record`
- `delete_record`
- `list_zones`
- `flush_cache`
- `get_stats`
- `get_settings`
- `block_domain`
- `allow_domain`

Those belong in the relevant `core::dns::<resource>` module.

## `core/`

`core/` owns vendor-neutral domain logic:

```text
src/core/
  mod.rs
  error.rs
  secret.rs
  dns/
    mod.rs
    service.rs
    capabilities.rs
    records/
    zones/
    cache/
    stats/
    settings/
    access_lists/
```

## `core::dns`

DNS resources should be organised by resource.

Preferred public paths:

```rust
core::dns::records::list_records(...)
core::dns::records::create_record(...)
core::dns::records::delete_record(...)
core::dns::records::normalize_record(...)
core::dns::records::validate_record(...)

core::dns::zones::list_zones(...)
core::dns::zones::create_zone(...)
core::dns::zones::delete_zone(...)

core::dns::cache::list_cache(...)
core::dns::cache::flush_cache(...)

core::dns::stats::get_stats(...)

core::dns::settings::get_settings(...)
core::dns::settings::update_settings(...)

core::dns::access_lists::list_blocked(...)
core::dns::access_lists::block_domain(...)
core::dns::access_lists::list_allowed(...)
core::dns::access_lists::allow_domain(...)
```

## Resource module layout

For larger resources, prefer directory modules:

```text
src/core/dns/records/
  mod.rs
  types.rs
  requests.rs
  responses.rs
  validation.rs
  normalize.rs
  ops.rs
```

Use the same pattern for other DNS resources when they grow:

```text
src/core/dns/zones/
src/core/dns/cache/
src/core/dns/stats/
src/core/dns/settings/
src/core/dns/access_lists/
```

Do not create unnecessary files if the resource is still small, but keep the public API resource-oriented.

## `core::dns::service`

Owns:

- Vendor-neutral DNS traits.
- Shared resource traits, if needed.
- `DnsService`.
- `DnsRead`.
- `DnsWrite`.
- `DnsVendor`.
- Trait signatures implemented by vendors.

## `core::dns::capabilities`

Owns:

- Supported operations.
- Supported record types.
- Vendor capability descriptions.
- Feature/capability declarations.

## `core::error`

Owns:

- Shared `Error`.
- Shared `Result<T>`.
- Error constructors/classification.

## `core::secret`

Owns:

- API token wrapper.
- Secret redaction.
- Safe display/debug behaviour for secrets.

## `vendors/`

`vendors/` owns vendor-specific implementation details:

```text
src/vendors/
  mod.rs
  runtime.rs
  technitium/
    mod.rs
    client.rs
    config.rs
    api.rs
    mapping.rs
    responses.rs
    service.rs
  pangolin/
    mod.rs
    client.rs
    mapping.rs
    responses.rs
    service.rs
  cloudflare/
    mod.rs
    client.rs
    mapping.rs
    responses.rs
    service.rs
```

Vendor modules own:

- HTTP clients.
- Vendor-specific endpoint calls.
- Vendor API request/response structs.
- Vendor-specific mapping into/from `core::dns` types.
- Implementations of shared DNS traits.

Vendor modules must not own:

- CLI command handling.
- MCP tool handling.
- Global app policy.
- Shared DNS domain types.
- Shared record validation unless genuinely vendor-specific.

## `vendors/mod.rs`

`src/vendors/mod.rs` should be a thin facade for the vendor subsystem.

It may contain:

- `pub mod runtime`.
- Feature-gated vendor module declarations.
- Vendor-subsystem re-exports.
- Tiny vendor-agnostic wrapper types.

Example:

```rust
pub mod runtime;

#[cfg(feature = "technitium")]
pub mod technitium;

#[cfg(feature = "pangolin")]
pub mod pangolin;

#[cfg(feature = "cloudflare")]
pub mod cloudflare;
```

It should not contain:

- Single-vendor feature-gated implementation functions.
- Vendor HTTP calls.
- Vendor API DTOs.
- Vendor mapping logic.
- DNS resource operations.
- CLI/MCP logic.
- Policy logic.
- Large factory/runtime dispatch logic.

If `vendors/mod.rs` grows beyond module declarations, re-exports, and one or two tiny generic types, it is probably accumulating misplaced logic.

## `vendors/runtime.rs`

`vendors/runtime.rs` owns runtime vendor wiring:

- Runtime vendor selection.
- Dynamic vendor enum/object dispatch.
- Selected-client construction.
- `ClientOverrides`.
- Shared vendor factory logic.

Examples of things that belong in `vendors/runtime.rs`:

```rust
pub enum VendorClient {
    Technitium(...),
    Pangolin(...),
    Cloudflare(...),
}
```

```rust
pub fn client_from_config(...) -> VendorClient
```

## Vendor feature-flag rule

If a function, type, module, or implementation is gated by a feature flag for exactly one vendor, it probably belongs in that vendor’s directory.

Rule of thumb:

```rust
#[cfg(feature = "technitium")]
fn some_function(...) { ... }
```

should usually live under:

```text
src/vendors/technitium/
```

Likewise:

```rust
#[cfg(feature = "pangolin")]
```

should usually live under:

```text
src/vendors/pangolin/
```

and:

```rust
#[cfg(feature = "cloudflare")]
```

should usually live under:

```text
src/vendors/cloudflare/
```

This is especially true for:

- Vendor client construction.
- Vendor-specific config/env handling.
- Vendor-specific API calls.
- Vendor-specific request/response structs.
- Vendor-specific mapping.
- Vendor-specific trait implementations.
- Vendor-specific tests.

A single-vendor feature flag outside `src/vendors/<vendor>/` is a smell.

Acceptable exceptions:

- `lib.rs`, `main.rs`, or `vendors/mod.rs` may use vendor feature flags to expose, register, or select vendor modules.
- `vendors/runtime.rs` may use vendor feature flags when constructing or dispatching to available vendors.
- Tests may use feature flags if they explicitly test feature-gated public behaviour.
- Shared traits in `core::dns::service` may be compiled regardless of vendor features and should not move into a vendor module.

Bad:

```rust
// src/core/dns/records.rs
#[cfg(feature = "technitium")]
fn technitium_record_to_core(...) { ... }
```

Better:

```rust
// src/vendors/technitium/mapping.rs
fn technitium_record_to_core(...) { ... }
```

Bad:

```rust
// src/control_plane/app.rs
#[cfg(feature = "cloudflare")]
fn cloudflare_client_from_config(...) { ... }
```

Better:

```rust
// src/vendors/cloudflare/mod.rs
fn client_from_server(...) { ... }
```

If code is genuinely shared across multiple vendors, it should not be gated by one vendor feature. Move it into `core`, `control_plane`, or `vendors/runtime` depending on responsibility.

## Function placement examples

| Function kind | Expected location |
|---|---|
| `list_records(...)` | `core::dns::records` |
| `create_record(...)` | `core::dns::records` |
| `delete_record(...)` | `core::dns::records` |
| `normalize_record(...)` | `core::dns::records` |
| `validate_record(...)` | `core::dns::records` |
| `list_zones(...)` | `core::dns::zones` |
| `create_zone(...)` | `core::dns::zones` |
| `delete_zone(...)` | `core::dns::zones` |
| `list_cache(...)` | `core::dns::cache` |
| `flush_cache(...)` | `core::dns::cache` |
| `get_stats(...)` | `core::dns::stats` |
| `get_settings(...)` | `core::dns::settings` |
| `update_settings(...)` | `core::dns::settings` |
| `list_blocked(...)` | `core::dns::access_lists` |
| `block_domain(...)` | `core::dns::access_lists` |
| `list_allowed(...)` | `core::dns::access_lists` |
| `allow_domain(...)` | `core::dns::access_lists` |
| `load_config(...)` | `control_plane::config` |
| `init_config(...)` | `control_plane::config` |
| `add_server_to_config(...)` | `control_plane::config` |
| `redact_config(...)` | `control_plane::config` |
| `selected_server(...)` | `control_plane::config` |
| `enforce_readonly(...)` | `control_plane::policy` |
| `check_zone_allowed(...)` | `control_plane::policy` |
| `vendor_client_from_config(...)` | `vendors::runtime` |
| `technitium_client_from_server(...)` | `vendors::technitium` |
| `cloudflare_client_from_server(...)` | `vendors::cloudflare` |
| `pangolin_client_from_server(...)` | `vendors::pangolin` |
| Vendor HTTP calls | `vendors::<vendor>::client` |
| Vendor record mapping | `vendors::<vendor>::mapping` |
| MCP record tool handler | `mcp::tools::records` |
| MCP params | `mcp::params` |
| CLI command structs/enums | `cli` |
| CLI interactive prompts | `cli::interactive` |

## Request/response types

Resource operation functions should accept domain request types, not CLI or MCP structs.

Good:

```rust
core::dns::records::ListRecordsRequest
core::dns::records::ListRecordsResponse
core::dns::records::list_records(ctx, request).await
```

Bad:

```rust
core::dns::records::list_records(cli::RecordCmd).await
core::dns::records::list_records(mcp::params::ListRecordsParams).await
```

CLI and MCP should convert their own input types into shared domain request types.

## Smell tests

A function is probably misplaced if any of these are true:

```text
cli/* imports reqwest
cli/* imports rmcp
mcp/* imports clap
mcp/* imports reqwest
core/* imports clap
core/* imports rmcp
vendors/* imports clap
vendors/* imports rmcp
vendors/* imports cli
vendors/* imports mcp
core/* knows about Technitium, Pangolin, or Cloudflare implementation details
vendor client code checks MCP readonly policy
MCP tools duplicate CLI logic
CLI code performs vendor HTTP calls directly
main.rs contains large DNS operation bodies
control_plane/app.rs contains list_records/create_record/list_zones/etc.
a function gated by a single vendor feature flag lives outside src/vendors/<vendor>/
```

Acceptable imports:

```text
main.rs imports cli, mcp, control_plane, core::dns, vendors::runtime
cli/* imports clap
mcp/* imports rmcp
vendors/* imports reqwest
core::dns imports shared traits/types/errors/secrets
control_plane imports config/policy/context types
```

### Accepted exception: `clap` derives in `core::dns`

`core::dns::records` (`RecordData`, `RecordSelector`), `core::dns::zones`
(`ZoneImportOptions`), and `core::dns::logs` (`LogLevel`) derive `clap` traits
(`Subcommand`/`Args`/`ValueEnum`). These are the shared domain types the CLI
parses directly; mirroring them with CLI-only arg types and `From` conversions
would duplicate a 20+ variant enum for no runtime benefit. We deliberately keep
the derives in `core` rather than duplicate the types. This is the *only*
sanctioned `core/* imports clap` case — do not add new ones.

## Module size and structure

No source file should exceed **500 lines**. When one grows past that, convert it
into a directory module (`foo.rs` → `foo/mod.rs`) and split it into submodules by
responsibility, keeping `mod.rs` as the public surface.

Conventions used across the tree:

- Submodules pull shared imports/items from the parent via `use super::*;`, and
  the parent re-exports them (`pub use sub::*;` for public API, `pub(crate) use
  sub::*;` for internal helpers and shared imports).
- Test modules move into a `tests.rs` (or a `tests/` directory split by area when
  they exceed 500 lines). They use `use super::*;`.
- A vendor `service.rs` splits by **trait impl** (one file per `impl Trait for
  Client`) when it grows; a single trait impl cannot straddle files.
- MCP tool handlers split by resource, each contributing a named `ToolRouter`
  via `#[tool_router(router = .., vis = "pub(crate)")]`, combined in
  `DnsServer::tool_router`.

## Subsystems not covered above

- `daemon/` — the sync daemon: runtime loop, scheduler, worker, job executors
  (`executor/`), persistence (`db/`), commands, health. It depends on
  `control_plane` and `core::dns`; it is not part of the CLI/MCP adapter layers.
- `vendors/{unifi,pihole}` — additional vendor backends; same rules as the other
  vendors.
- `core::dns::{resolver,validation,names,capabilities}` — vendor-neutral DNS
  transport resolution (DNS/DoT/DoH/DoQ), endpoint validation, name helpers, and
  capability declarations.
- `control_plane::transfer` — zone transfer between two configured servers.
- `formatter` — tracing/log event formatting for the binary.

## Refactor method

### 1. Classify functions by behaviour

Classify each existing function into one bucket:

- CLI adapter.
- MCP adapter.
- Config/control-plane.
- Policy/control-plane.
- DNS records.
- DNS zones.
- DNS cache.
- DNS stats.
- DNS settings.
- DNS access lists.
- Core DNS types/traits/capabilities.
- Vendor runtime/factory.
- Vendor HTTP client.
- Vendor mapping.
- Vendor service implementation.
- Error/secret utility.

Do not rely on current file location for classification.

### 2. Create or update target modules

Update `mod.rs` files so the target modules exist.

At minimum, ensure `src/core/dns/mod.rs` exposes resource modules for every DNS resource currently supported by CLI/MCP:

```rust
pub mod records;
pub mod zones;
pub mod cache;
pub mod stats;
pub mod settings;
pub mod access_lists;
pub mod capabilities;
pub mod service;
```

If existing `records.rs` or `zones.rs` are large, convert them into directories:

```text
records.rs -> records/mod.rs + submodules
zones.rs   -> zones/mod.rs + submodules
```

Preserve public exports where useful to avoid unnecessary breakage.

### 3. Move DNS operations into resource modules

Move operation functions according to resource ownership.

Examples:

- `list_records`, `create_record`, `update_record`, `delete_record`, `normalize_record`, `validate_record`
  - move to `core::dns::records`.

- `list_zones`, `create_zone`, `delete_zone`
  - move to `core::dns::zones`.

- `list_cache`, `flush_cache`
  - move to `core::dns::cache`.

- `get_stats`
  - move to `core::dns::stats`.

- `get_settings`, `update_settings`
  - move to `core::dns::settings`.

- `list_blocked`, `block_domain`, `unblock_domain`, `list_allowed`, `allow_domain`, `remove_allowed_domain`
  - move to `core::dns::access_lists`.

The resource operation functions should accept shared context/service abstractions, not concrete CLI/MCP types.

### 4. Make CLI thin

Update CLI code so it only defines command shapes and interactive prompts.

`main.rs` should pattern-match CLI commands and call the appropriate module:

```rust
match cli.command {
    Command::Record(record_cmd) => {
        // Convert CLI args into core::dns::records request types.
        // Call core::dns::records::*.
    }

    Command::Zone(zone_cmd) => {
        // Convert CLI args into core::dns::zones request types.
        // Call core::dns::zones::*.
    }

    Command::Cache(cache_cmd) => {
        // Convert CLI args into core::dns::cache request types.
        // Call core::dns::cache::*.
    }

    Command::Stats { .. } => {
        // Convert CLI args into core::dns::stats request types.
        // Call core::dns::stats::*.
    }

    Command::Settings => {
        // Call core::dns::settings::*.
    }

    Command::Blocked(blocked_cmd) | Command::Allowed(allowed_cmd) => {
        // Call core::dns::access_lists::*.
    }

    Command::Config(config_cmd) => {
        // Dispatch directly to control_plane::config.
    }

    Command::Mcp => {
        // Start MCP server.
    }

    Command::Completions { shell } => {
        // Generate completions.
    }

    Command::ServerIds => {
        // Use control_plane::config to print server IDs.
    }
}
```

Remove business logic from `cli::runner` and delete `runner.rs` if no longer needed.

### 5. Make MCP thin

Update each MCP tool file so it only:

1. Accepts MCP params.
2. Converts params into `core::dns::<resource>` request types.
3. Calls `core::dns::<resource>` operations.
4. Converts the result into MCP output.

Example target flow:

```rust
mcp::tools::records::list_records(params)
  -> core::dns::records::ListRecordsRequest
  -> core::dns::records::list_records(ctx, request).await
  -> MCP response
```

MCP tools should not:

- Call vendor clients directly.
- Duplicate CLI behaviour.
- Implement record/zone/cache/stats/settings/access-list logic directly.
- Own read-only or allowed-zone policy logic except by calling shared policy/context code.

### 6. Keep vendor logic vendor-specific

Move or keep vendor-specific code under `src/vendors/<vendor>`.

Expected split:

- `client.rs`: raw API/HTTP calls.
- `service.rs`: implements shared DNS traits using the client.
- `mapping.rs`: maps vendor structs to/from core DNS types.
- `responses.rs` or `api.rs`: vendor-specific DTOs.
- `config.rs`: vendor-specific config helpers if needed.
- `mod.rs`: module exports and small construction helpers only.

A vendor `client.rs` may know endpoint paths and JSON payloads.

A vendor `service.rs` may know how to satisfy `DnsService`, `DnsRead`, `DnsWrite`, etc.

A vendor module must not know about CLI or MCP.

### 7. Fix imports and public exports

After moving functions:

- Update `use` statements.
- Update `lib.rs` re-exports if public API compatibility is needed.
- Prefer resource-oriented public exports.

Good public exports:

```rust
pub mod dns {
    pub use crate::core::dns::*;
}
```

or explicit:

```rust
pub mod records {
    pub use crate::core::dns::records::*;
}
```

Avoid exporting misleading compatibility paths if they preserve the old architecture too strongly, unless needed temporarily.

### 8. Remove duplication

After CLI and MCP call shared resource modules:

- Delete duplicated record logic.
- Delete duplicated zone logic.
- Delete duplicated cache/stats/settings/access-list logic.
- Delete unused helper functions.
- Delete unused imports.
- Delete `cli::runner` if no longer needed.

### 9. Enforce layering

These are wrong:

```text
cli/* imports reqwest
cli/* imports rmcp
mcp/* imports clap
mcp/* imports reqwest
core/* imports clap
core/* imports rmcp
core/* imports a concrete vendor module unless behind a deliberate trait/runtime boundary
vendors/* imports clap
vendors/* imports rmcp
vendors/* imports cli
vendors/* imports mcp
control_plane/app.rs contains DNS resource operation bodies
a function gated by a single vendor feature flag lives outside src/vendors/<vendor>/
```

These are acceptable:

```text
main.rs imports cli, mcp, control_plane, core::dns, vendors::runtime
cli/* imports clap
mcp/* imports rmcp
vendors/* imports reqwest
core::dns imports shared traits/types/errors/secrets
control_plane imports config/policy/context types
```

### 10. Run checks

Run:

```bash
cargo fmt --all
cargo check --all-features
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
```

Fix all compile errors, formatting errors, clippy warnings, and tests.

## Desired final outcome

After the refactor:

1. Record operations live under `core::dns::records`.
2. Zone operations live under `core::dns::zones`.
3. Cache operations live under `core::dns::cache`.
4. Stats operations live under `core::dns::stats`.
5. Settings operations live under `core::dns::settings`.
6. Blocked/allowed domain operations live under `core::dns::access_lists`.
7. CLI is only command definitions, completions, and prompts.
8. MCP is only tool definitions, params, server registration, and response formatting.
9. Vendors are only backend clients, mappings, DTOs, and trait implementations.
10. Config commands are dispatched directly from `main.rs` to `control_plane::config`.
11. There is no central CLI runner owning DNS behaviour.
12. CLI and MCP use the same underlying DNS resource operations.
13. `vendors/mod.rs` remains a thin facade.
14. Single-vendor feature-gated code lives in that vendor’s directory unless it is only exposing/registering/selecting that vendor.
15. The project compiles, formats, passes tests, and passes clippy with all features enabled.

## When uncertain

Prefer moving behaviour toward the resource it operates on.

Examples:

- A function that lists records belongs in `core::dns::records`, even if currently used by CLI.
- A function that validates a record belongs in `core::dns::records`.
- A function that lists zones belongs in `core::dns::zones`.
- A function that clears DNS cache belongs in `core::dns::cache`.
- A function that gets DNS server stats belongs in `core::dns::stats`.
- A function that maps a Technitium record response into a core record belongs in `vendors::technitium::mapping`.
- A function that checks whether writes are allowed belongs in `control_plane::policy`.
- A function that loads tokens/base URLs from config/env belongs in `control_plane::config` or `vendors::runtime`, depending on whether it is generic or vendor-construction-specific.
- A function that makes a Technitium HTTP request belongs in `vendors::technitium::client`.
- A function that formats an MCP response belongs in `mcp`.
- A function that formats CLI output should stay CLI/main-adapter side and should not become domain logic.

Do not preserve the old layout just because imports are easier. Refactor toward the responsibility-oriented target structure.
