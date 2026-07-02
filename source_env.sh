#!/usr/bin/env bash

source_env_main() {
    local env_file="${1:-.env}"

    if [[ ! -f "$env_file" ]]; then
        echo "Missing env file: $env_file" >&2
        return 1
    fi

    local line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Remove Windows CR if present
        line="${line%$'\r'}"

        # Skip blank lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # Allow optional leading "export "
        line="${line#export }"

        # Split KEY=VALUE
        key="${line%%=*}"
        value="${line#*=}"

        # Trim whitespace around key
        key="$(echo "$key" | xargs)"

        # Skip invalid variable names
        if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            echo "Skipping invalid variable name: $key" >&2
            continue
        fi

        # Remove an inline comment only when its # is outside quotes and
        # preceded by whitespace. Leading and attached hashes are literal,
        # so values such as #ffffff and value#suffix remain unchanged.
        local cleaned="" quote="" char previous=""
        local i
        for ((i = 0; i < ${#value}; i++)); do
            char="${value:i:1}"
            if [[ -z "$quote" && ("$char" == "\"" || "$char" == "'") ]]; then
                quote="$char"
            elif [[ "$char" == "$quote" ]]; then
                quote=""
            elif [[ -z "$quote" && "$char" == "#" && "$previous" =~ [[:space:]] ]]; then
                break
            fi
            cleaned+="$char"
            previous="$char"
        done
        value="$cleaned"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"

        # Remove surrounding single or double quotes
        if [[ "$value" =~ ^\".*\"$ || "$value" =~ ^\'.*\'$ ]]; then
            value="${value:1:${#value}-2}"
        fi

        export "$key=$value"
    done <"$env_file"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -euo pipefail
fi

source_env_main "$@"
