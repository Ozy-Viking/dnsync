# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM rust:1.87-bookworm AS builder

WORKDIR /build

# Cache dependencies before copying source.
COPY Cargo.toml Cargo.lock ./
# Create stub libs so cargo can resolve the workspace without full source.
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo fetch

# Copy full source and build release binary.
# libsqlite3-sys uses the "bundled" feature so no system sqlite3-dev needed.
COPY . .
RUN cargo build --release --features "technitium,pangolin,cloudflare,unifi,pihole"

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for the daemon process.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin dnsync

COPY --from=builder /build/target/release/dnsync /usr/local/bin/dnsync

# Default paths — override via environment variables or volume mounts.
# Config:    /etc/dnsync/config.toml   (read-only mount)
# State DB:  /var/lib/dnsync/state.db  (persistent volume)
# Logs:      stdout/stderr (captured by Docker / your log driver)
RUN install -d -o dnsync -g dnsync /etc/dnsync /var/lib/dnsync

USER dnsync

ENV DNSYNC_STATE_DB=/var/lib/dnsync/state.db

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD dnsync healthcheck || exit 1

ENTRYPOINT ["dnsync"]
CMD ["daemon", "--config", "/etc/dnsync/config.toml"]
