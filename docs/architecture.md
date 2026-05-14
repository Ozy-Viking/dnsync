# DNS Control Plane Architecture

## Purpose

This document defines the target architecture for moving this repository from a Technitium-specific DNS MCP server into a general DNS control plane with vendor-specific adapters.

The refactor should preserve current CLI and MCP behavior while making the binary's internal model reusable across vendors.

## Design Goals

- Keep DNS domain types shared inside the binary.
- Keep MCP-specific code isolated from vendor API details.
- Keep CLI-specific code isolated from vendor API details.
- Keep Technitium endpoint paths, request encoding, response normalization, and auth in a Technitium vendor area.
- Centralize error handling so CLI, MCP, core logic, and vendors return the same error model.
- Make future vendor support additive instead of requiring changes throughout the control plane.

## Non-Goals

- Do not add a second DNS vendor in the first refactor pass.
- Do not change existing user-facing CLI or MCP behavior during structural moves.
- Do not split into multiple crates until a single-crate module boundary has proven useful.
- Do not introduce compatibility shims for unreleased intermediate structures.


## Crate And Binary Naming

The library crate is named `dnslib` for Rust import compatibility and style. The binary remains `dns` so the command-line surface stays stable.

## Target Directory Layout

```text
src/
  lib.rs
  main.rs

  core/
    mod.rs
    error.rs
    dns/
      mod.rs
      records.rs
      zones.rs
      responses.rs
      service.rs
      capabilities.rs

  control_plane/
    mod.rs
    app.rs
    config.rs
    policy.rs

  mcp/
    mod.rs
    server.rs
    params.rs
    helpers.rs
    tools/
      mod.rs
      zones.rs
      records.rs
      cache.rs
      stats.rs
      access_lists.rs
      settings.rs

  cli/
    mod.rs
    commands.rs
    runner.rs
    records.rs

  vendors/
    mod.rs
    technitium/
      mod.rs
      client.rs
      service.rs
      config.rs
      mapping.rs
      responses.rs
      api/
        mod.rs
        zones.rs
        records.rs
        cache.rs
        stats.rs
        access_lists.rs
        settings.rs
        import.rs
```

## Module Responsibilities

### `core/`

`core/` owns shared domain types and contracts used inside the binary.

It should contain DNS record types, zone models, list response models, centralized errors, and the vendor-neutral DNS operation interface.

It should not contain MCP macros, CLI parsing, Technitium endpoint paths, or HTTP request encoding.

### `control_plane/`

`control_plane/` owns application composition and cross-cutting control-plane concerns.

It should choose the active vendor adapter, construct shared config, apply policy, and expose common wiring used by CLI and MCP entrypoints.

### `mcp/`

`mcp/` owns all `rmcp` concerns.

This includes server state, `ServerHandler`, tool router setup, MCP parameter DTOs, MCP result formatting, MCP error conversion, and tool handlers grouped by domain.

MCP handlers should call vendor-neutral service methods and should not know Technitium endpoint paths or request parameter names.

### `cli/`

`cli/` owns terminal argument parsing and CLI execution.

CLI code should convert user commands into core DNS operations. Vendor-specific flags or environment variables should be minimized and routed through control-plane config.

### `vendors/technitium/`

`vendors/technitium/` owns everything specific to Technitium DNS Server.

This includes HTTP client setup, bearer auth, API response status parsing, endpoint paths, query/form/multipart encoding, Technitium-specific response normalization, and conversions between core DNS types and Technitium API parameters.


## Structure Pass Status

The initial module tree exists. The first behavior-preserving pass moved large modules intact and added scaffold files for future splits. MCP tool handlers and Technitium endpoint groups remain mostly intact inside their current implementation modules until follow-up refactors can split them safely.

## Data Flow

```text
CLI command or MCP tool
  -> control-plane policy/config
  -> core DNS service interface
  -> Technitium vendor implementation
  -> Technitium HTTP API
  -> vendor response normalization
  -> core response type
  -> CLI or MCP output formatting
```


## Vendor Feature Flags

Vendor integrations should be controlled by Cargo features so builds include only the vendor support they need.

Initial features:

- `default = ["technitium"]` keeps current behavior for normal builds.
- `technitium` enables the existing Technitium implementation and its HTTP dependency stack.

Building without a vendor feature is intentionally rejected until a vendor-neutral no-provider mode exists. Future vendors should be added as independent feature flags under the same pattern.

## Error Handling Strategy

`core::error` should define the shared `Error` and `Result` types.

Vendor implementations should map raw HTTP, JSON, API, and parsing failures into this shared error model. MCP and CLI should format errors for their surfaces, but they should not define separate error taxonomies.

## Testing Strategy

- Core unit tests should cover record types, response models, and service contract behavior.
- Technitium adapter tests should cover endpoint paths, auth, query/form/multipart encoding, API error parsing, and response normalization.
- MCP tests should verify tool parameters, policy enforcement, and handler-to-service dispatch.
- CLI tests should verify command parsing and command-to-service dispatch.
- Existing behavior should remain unchanged after each structural phase.

## Open Questions

- Whether `control_plane/app.rs` is needed immediately or can wait until there is more than one vendor.
- Whether vendor capabilities should be a static enum, a runtime structure, or part of the service trait.
- Whether read-only DNSSEC records belong entirely in core response types or partly in Technitium response mapping.
