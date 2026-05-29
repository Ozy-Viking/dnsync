#!/usr/bin/env bash
set -euo pipefail

CRATE_NAME="${CRATE_NAME:-dnsync}"
BIN_NAME="${BIN_NAME:-dns}"

if ! cargo binstall --version >/dev/null 2>&1; then
    echo "error: cargo-binstall is not installed or not available via cargo binstall" >&2
    echo "Install it with:" >&2
    echo "  cargo install cargo-binstall --locked" >&2
    exit 1
fi

export BINSTALL_DISABLE_TELEMETRY="${BINSTALL_DISABLE_TELEMETRY:-true}"

if [[ "$#" -eq 0 ]]; then
    echo "Updating ${CRATE_NAME} using cargo binstall..."
    cargo binstall --no-confirm "${CRATE_NAME}"
else
    echo "Running cargo binstall with passthrough arguments:"
    printf '  %q' cargo binstall --no-confirm "$@"
    echo
    cargo binstall --no-confirm "$@"
fi

echo
echo "Update completed successfully."

if command -v "${BIN_NAME}" >/dev/null 2>&1; then
    echo
    echo "Installed binary:"
    command -v "${BIN_NAME}"

    echo
    echo "Version:"
    "${BIN_NAME}" --version 2>/dev/null || true
else
    echo
    echo "warning: expected binary '${BIN_NAME}' was not found on PATH" >&2
fi

echo
echo "Bash completion note:"
echo "  New shells will load fresh completions from '${BIN_NAME}' via ~/.bashrc."
echo
echo "For the current shell, run:"
echo "  complete -r ${BIN_NAME} 2>/dev/null || true"
echo "  source <(${BIN_NAME} completions bash)"
