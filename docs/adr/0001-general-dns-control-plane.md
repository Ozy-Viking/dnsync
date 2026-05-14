# ADR-0001: General DNS Control Plane With Vendor Adapters

## Status

Proposed

## Context

The repository currently implements a Rust CLI and MCP server focused on Technitium DNS Server.

The existing code already has useful seams: CLI and MCP surfaces call shared DNS operation functions, while the Technitium HTTP client and API endpoint mappings are concentrated in a small number of files.

The next goal is to make the binary's internal architecture vendor-neutral so future DNS providers can be added without rewriting MCP tools, CLI commands, shared DNS types, or policy checks.

## Decision

We will move toward a single-crate architecture with these boundaries:

- `core/` for shared DNS types, response models, service contracts, and centralized errors
- `control_plane/` for application wiring, config, and policy
- `mcp/` for all MCP server, tool, parameter, and result formatting code
- `cli/` for command-line parsing and dispatch
- `vendors/technitium/` for Technitium transport, endpoint paths, request encoding, response normalization, and vendor mappings
- vendor integrations are controlled by Cargo features, starting with `technitium` as the default feature
- the importable library crate is named `dnslib` while the binary remains `dns`

Technitium will become the first vendor adapter. Existing behavior should be preserved during the move.

## Consequences

Positive consequences:

- MCP tools and CLI commands can target a shared DNS service interface.
- Technitium API details become easier to test in isolation.
- Future vendors can be added under `vendors/` without duplicating the control plane.
- Centralized errors reduce duplicated error formatting logic.

Negative consequences:

- The refactor introduces more modules before there is a second vendor.
- Some record types and operations may not map cleanly across vendors.
- Tests must become stricter about layer boundaries and adapter contracts.

## Alternatives Considered

### Keep the flat Technitium-focused structure

This is simplest short-term, but it keeps vendor details mixed into shared surfaces and makes future provider support invasive.

### Add future providers ad hoc

This avoids upfront architecture work, but each new provider would likely add conditional logic throughout CLI, MCP, and operation code.

### Split into multiple crates immediately

A workspace could enforce stronger boundaries, but it adds overhead before the single-crate module boundary has proven insufficient.

## Testing Implications

The refactor should be implemented in phases, with tests run after each phase.

Expected test coverage:

- core record and response model tests
- Technitium adapter request/response mapping tests
- MCP handler dispatch and policy tests
- CLI parsing and dispatch tests
- existing client behavior tests preserved under the Technitium vendor area

## Follow-Up Documentation

- `docs/architecture.md` defines the target module layout and ownership rules.
- `docs/vendor-mapping.md` defines how Technitium maps into the shared DNS control plane.
- `TODO.md` tracks implementation phases and validation work.
