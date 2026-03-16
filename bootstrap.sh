#!/usr/bin/env bash
# Quick-Script bootstrap entry point
# This script parses arguments and fetches main.sh from the remote repository to execute

set -euo pipefail

# Logging
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    case "$level" in
        info)
            printf "[\033[32mINFO\033[0m] %s %s\n" "$timestamp" "$message" >&2
            ;;
        warn)
            printf "[\033[33mWARN\033[0m] %s %s\n" "$timestamp" "$message" >&2
            ;;
        error)
            printf "[\033[31mERROR\033[0m] %s %s\n" "$timestamp" "$message" >&2
            ;;
        *)
            printf "[%s] %s %s\n" "$level" "$timestamp" "$message" >&2
            ;;
    esac
}

normalize_channel() {
    local channel
    channel=$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')
    case "${channel}" in
        dev|main)
            echo "${channel}"
            ;;
        *)
            echo "main"
            ;;
    esac
}

parse_channel_args() {
    local channel="${ONE_SCRIPT_CHANNEL:-}"
    local remaining=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --channel)
                if [[ -n "${2:-}" ]]; then
                    channel="$2"
                    shift 2
                    continue
                fi
                shift
                continue
                ;;
            --channel=*)
                channel="${1#*=}"
                shift
                continue
                ;;
            *)
                remaining+=("$1")
                shift
                ;;
        esac
    done

    CHANNEL="$(normalize_channel "${channel}")"
    BASE_URL="https://raw.githubusercontent.com/charleslkx/quick-script/${CHANNEL}"
    REMAINING_ARGS=("${remaining[@]+"${remaining[@]}"}")
}

run_remote_script() {
    local cache_suffix=""
    if [[ "${ONE_SCRIPT_DISABLE_CACHE_BUSTER:-0}" != "1" ]]; then
        cache_suffix="?t=$(date +%s)"
    fi
    local script_url="${BASE_URL}/main.sh${cache_suffix}"
    local temp_script
    local download_success=0

    log "info" "Remote script URL: ${script_url}"

    temp_script=$(mktemp -t quick-script.XXXXXX)
    if [[ -z "$temp_script" ]] || [[ ! -f "$temp_script" ]]; then
        log "error" "Failed to create temporary file"
        return 1
    fi

    log "info" "Downloading remote script to temporary file..."

    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL --max-time 60 "${script_url}" -o "${temp_script}" 2>/dev/null; then
            if [[ -s "${temp_script}" ]]; then
                download_success=1
            fi
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -qO "${temp_script}" "${script_url}" 2>/dev/null; then
            if [[ -s "${temp_script}" ]]; then
                download_success=1
            fi
        fi
    else
        log "error" "Neither wget nor curl found, cannot download remote script"
        rm -f "${temp_script}" 2>/dev/null || true
        return 1
    fi

    if [[ ${download_success} -eq 0 ]]; then
        log "error" "Failed to download remote script, please check network connection or URL"
        rm -f "${temp_script}" 2>/dev/null || true
        return 1
    fi

    if ! bash -n "${temp_script}" 2>/dev/null; then
        log "error" "Downloaded script has syntax errors, possibly due to a network transmission issue"
        rm -f "${temp_script}" 2>/dev/null || true
        return 1
    fi

    log "info" "Script downloaded successfully, starting execution..."

    local script_exit_code=0
    ONE_SCRIPT_CHANNEL="${CHANNEL}" ONE_SCRIPT_BASE_URL="${BASE_URL}" \
        bash "${temp_script}" ${REMAINING_ARGS[@]+"${REMAINING_ARGS[@]}"} || script_exit_code=$?

    rm -f "${temp_script}" 2>/dev/null || true

    if [[ ${script_exit_code} -ne 0 ]]; then
        log "error" "Remote script execution failed (exit code: ${script_exit_code})"
        return 1
    fi

    return 0
}

main() {
    parse_channel_args "$@"
    run_remote_script
}

# Run main only if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]] || [[ -z "${BASH_SOURCE[0]}" ]] || [[ "${BASH_SOURCE[0]}" == "bash" ]]; then
    main "$@"
fi
