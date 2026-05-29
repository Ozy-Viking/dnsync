# dnsync

dnsync is a Rust CLI and MCP server for managing DNS. It started as a homelab
tool to wrangle my Technitium cluster, but it's grown into something I actually
want to rely on: a single, reliable control point for DNS instead of juggling
five different vendor CLIs and dashboards.

The core job is keeping DNS servers in sync — pulling records from one
nameserver and applying them to another, with the canonical example being an
external authoritative provider (like Cloudflare) feeding an internal cluster
(like Technitium). Everything else (validation, benchmarking, cache management,
the MCP surface) exists to support that mission or to make the tool genuinely
useful as a go-to DNS Swiss Army knife.

## A note from me to you

This is the letter I wish I'd written earlier. Read it before touching anything.

**The vendor-neutral control plane is the whole point.** This codebase is
mid-refactor from a Technitium-specific tool into a proper multi-vendor
architecture. The TODO tracks it. The ADRs explain it. The module boundaries
(`core/`, `control_plane/`, `vendors/<vendor>/`, `mcp/`) are not suggestions —
they're the design. When you add or change something, ask yourself: does this
belong in the control plane, or is it vendor-specific? If it touches Technitium
response shapes, Pangolin auth quirks, or Cloudflare API paths, it belongs in
`vendors/`. If it's a DNS concept that any vendor would have (zones, records,
TTLs), it belongs in `core/` or `control_plane/`. Do not let vendor specifics
leak upward.

**The MCP surface is a full peer to the CLI.** Everything the CLI can do, the
MCP should be able to do. The per-server `access` and `allowed_zones` config
is how the operator throttles what's permitted in their deployment — it is not
a signal that the MCP is meant to be read-mostly or cautious by design. When
adding a new CLI command, the MCP tool comes with it. When the CLI gets a new
flag that changes behaviour, the MCP tool should reflect it. Treat any gap
between CLI and MCP capability as a bug.

**Safety is structural, not optional.** Sync is dry-run by default. Config files
enforce strict permissions. The MCP surface has per-server access controls and
zone allowlists. These are not features you tune — they're the contract with
anyone running this in production. Never erode them. If you think a behaviour
is too restrictive, say so loudly and wait for approval before changing it.

**This runs headlessly.** One of the primary deployment targets is a Docker
container configured entirely through `config.toml`. Any interactive prompts,
TTY assumptions, or "requires a terminal" behaviour in non-config commands is a
bug. The `config add` wizard is fine. Production paths are not.

**DNS transport validation is first-class.** DNS, DoT, DoH, DoQ — all four need
to work and be testable. This isn't a future concern; it's being added now. When
working near validation, treat it with the same care as the sync logic. A tool
that tells you your DNS is working when it isn't is worse than no tool at all.

**The binary is `dns`. The library is `dnslib`.** Keep them appropriately
separated. The binary wires things together and owns the CLI surface. The library
is what you'd import if you were building on top of this. Don't let binary
concerns bleed into library code.

**Keep TODO.md current.** It is the live record of where this refactor is and
what's left. When you complete something tracked there, tick it. When you
discover something that needs tracking, add it. A stale TODO is worse than no
TODO — it means I'm making decisions based on wrong information.

When something seems ambiguous, push back and ask. I'd rather you flag a
conflict than silently pick the wrong path and build on top of it.

## Glossary

| Term | Meaning |
|---|---|
| **you** | the agent reading this and making changes to the codebase |
| **me / I** | Zack, the human building and operating this |
| **operator** | anyone running dnsync in production — via Docker container, as an MCP server, or directly as a CLI tool |
| **internal DNS / cluster** | the Technitium cluster (dns1 + dns2) that we manage and write to |
| **external DNS** | upstream authoritative providers (Cloudflare, etc.) that we read from |
| **vendor** | a DNS server implementation we support: Technitium, Pangolin, Cloudflare |
| **control plane** | the vendor-neutral layer that both CLI and MCP route through |
| **sync** | pulling records from one nameserver and applying them to another |

## General rules

These are defaults, not absolutes. If you think one should be ignored for a
specific change, say so explicitly and get confirmation before proceeding.

- sync is additive and dry-run by default; `--apply` is the only path to writes
- vendor-specific code lives in `vendors/<vendor>/`; it does not belong in `core/` or `control_plane/`
- if you're unsure where code belongs, consult `docs/function-placement-guide.md` first; before asking or guessing on any architectural question, check whether a relevant doc already exists in `docs/` by its filename — don't guess
- CLI and MCP capability must stay in parity; a CLI command with no MCP equivalent is incomplete
- the security model (config permissions, MCP access controls, zone allowlists) is not negotiable
- headless/Docker paths must work without a TTY and without interactive prompts
- `dns` (binary) and `dnslib` (library) have different concerns; keep the boundary clean
- when adding transport or validation, target all four: DNS, DoT, DoH, DoQ
- keep TODO.md current — tick completed items, add newly discovered ones
