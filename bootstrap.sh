#!/usr/bin/env bash
# One-Script 稳定入口脚本
# 本脚本负责解析参数并从远程拉取 main.sh 执行

set -euo pipefail

# 日志输出
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
    REMAINING_ARGS=("${remaining[@]}")
}

run_remote_script() {
    local script_url="${BASE_URL}/main.sh"

    log "info" "远程脚本 URL: ${script_url}"

    if command -v curl >/dev/null 2>&1; then
        log "info" "使用 curl 下载并执行远程脚本..."
        # shellcheck disable=SC1090
        if bash <(curl -fsSL "${script_url}" 2>/dev/null) "${REMAINING_ARGS[@]}"; then
            return 0
        else
            log "error" "远程脚本执行失败"
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        log "info" "使用 wget 下载并执行远程脚本..."
        # shellcheck disable=SC1090
        if bash <(wget -qO- "${script_url}" 2>/dev/null) "${REMAINING_ARGS[@]}"; then
            return 0
        else
            log "error" "远程脚本执行失败"
            return 1
        fi
    else
        log "error" "未找到 wget 或 curl 工具，无法下载远程脚本"
        return 1
    fi
}

main() {
    parse_channel_args "$@"
    run_remote_script
}

# 如果直接执行（非被 source），则运行 main
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
