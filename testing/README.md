# dnsync Daemon Testing

This folder is for testing the PR #50 daemon runtime in Docker Compose.

## Setup

1. `config.toml` is a symlink to `../.config/dnsync/config.toml` so the daemon uses the repo's active debug config and real test endpoints.
2. Optionally create `testing/.env` if any config entries reference environment variables. Compose does not require this file to exist.
3. Run `docker compose -f testing/docker-compose.yml up --build` for a normal run.
4. Run `docker compose -f testing/docker-compose.yml watch` to rebuild and restart the daemon when code changes.

The compose file expects the daemon Dockerfile from PR #50 at the repository root.
