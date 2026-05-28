# Refactor To Do

Track the planned move from a Technitium-focused MCP server to a general DNS control plane with vendor-specific adapters.


## Docs First

- [ ] Create `docs/architecture.md` to define module boundaries. _(not yet created — file is missing from `docs/`)_
- [ ] Create `docs/vendor-mapping.md` to document Technitium mapping. _(not yet created — file is missing from `docs/`)_
- [ ] Create `docs/adr/0001-general-dns-control-plane.md` to record the architecture decision. _(not yet created — `docs/adr/` directory does not exist)_
- [x] Use the docs as the source of truth for implementation phases.
- [x] Add initial `technitium` vendor feature flag.
- [x] Rename the importable library crate to `dnslib` while keeping the binary as `dns`.
- [x] Create the initial `core/`, `control_plane/`, `mcp/`, and `vendors/technitium/` module tree.

## Architecture

- [x] Finalize the planned directory tree before code changes.
- [x] Move centralized error handling into a shared core/control-plane error module.
- [x] Move MCP-specific code into its own `mcp/` module.
- [x] Define the shared DNS core types used inside the binary.
- [ ] Define a vendor-neutral DNS operations interface.

## Control Plane

- [ ] Keep MCP tool handling vendor-neutral.
- [ ] Keep CLI command handling vendor-neutral where possible.
- [ ] Keep policy checks centralized and shared by control-plane surfaces.
- [ ] Keep output/result formatting separate from vendor API calls.

## Vendor Areas

- [x] Create `vendors/technitium/` for the existing Technitium implementation.
- [x] Move Technitium HTTP client/auth handling into the Technitium vendor area.
- [x] Move Technitium endpoint paths and request encoding into the Technitium vendor area.
- [ ] Move Technitium response normalization/parsing into the Technitium vendor area.
- [ ] Keep shared record/zone types outside the vendor area unless a type is truly vendor-specific.

## Validation

- [x] Preserve current CLI behavior after restructuring.
- [x] Preserve current MCP tool behavior after restructuring.
- [ ] Update tests to match the new module boundaries.
- [x] Run formatting, tests, and build after each implementation phase.

## Direct DNS resolution (dns query / dns_resolve)

- [x] Plan the `dns query` subcommand (`docs/dns-query-command.md`).
- [x] Add the `doq` Cargo feature gating `hickory-resolver/quic-ring`.
- [x] Add `[servers.doq]` transport block; round-trip + validate.
- [ ] Add provider-level default resolver transports for external providers
  such as Cloudflare, with DNS/DoT/DoH/DoQ defaults that can still be
  overridden per config. Future providers should be able to declare their
  transport defaults in one place instead of requiring every config to repeat
  standard public resolver endpoints.
- [x] Extract resolver builders onto a neutral `ResolverTarget` shared
  between validation and query paths; add DoQ behind `#[cfg]`.
- [x] Ship the `dns query` (alias `q`) CLI subcommand: system / named /
  ad-hoc targets, DoH bootstrap, dig-style table + `--short` + `--json`,
  fan-out with `--all` and per-transport flags.
- [x] Ship the `dns_resolve` MCP tool with the same engine and JSON shape.
- [x] Document `dns query` in the README (examples + `[servers.doq]`).
- [ ] Shell completion for `--server` on `dns query` (currently picks up
  the `_servers` hidden subcommand automatically — verify per shell).
- [ ] Optional: a future `dns query --compare` flag that diffs answers
  across multiple resolvers (extends the existing `record list --all`
  idea to the query side).
- [ ] Wire DoQ (DNS-over-QUIC, port 853) into the validation transport layer
      so all four transports mandated by `agents.md` (DNS, DoT, DoH, DoQ) are
      end-to-end testable.

## CLI / MCP Parity (bugs, per `agents.md`)

- [ ] Add MCP `sync` tool that mirrors the `dns sync` CLI surface
      (profiles, `--from`/`--to`/`--zone`/`--map`, dry-run by default, `--apply`).
- [ ] Add MCP `diff` tool to ship alongside any future `dns diff` CLI command.
