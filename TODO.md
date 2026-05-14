# Refactor To Do

Track the planned move from a Technitium-focused MCP server to a general DNS control plane with vendor-specific adapters.

## Architecture

- [ ] Finalize the planned directory tree before code changes.
- [ ] Move centralized error handling into a shared core/control-plane error module.
- [ ] Move MCP-specific code into its own `mcp/` module.
- [ ] Define the shared DNS core types used inside the binary.
- [ ] Define a vendor-neutral DNS operations interface.

## Control Plane

- [ ] Keep MCP tool handling vendor-neutral.
- [ ] Keep CLI command handling vendor-neutral where possible.
- [ ] Keep policy checks centralized and shared by control-plane surfaces.
- [ ] Keep output/result formatting separate from vendor API calls.

## Vendor Areas

- [ ] Create `vendors/technitium/` for the existing Technitium implementation.
- [ ] Move Technitium HTTP client/auth handling into the Technitium vendor area.
- [ ] Move Technitium endpoint paths and request encoding into the Technitium vendor area.
- [ ] Move Technitium response normalization/parsing into the Technitium vendor area.
- [ ] Keep shared record/zone types outside the vendor area unless a type is truly vendor-specific.

## Validation

- [ ] Preserve current CLI behavior after restructuring.
- [ ] Preserve current MCP tool behavior after restructuring.
- [ ] Update tests to match the new module boundaries.
- [ ] Run formatting, tests, and build after each implementation phase.
