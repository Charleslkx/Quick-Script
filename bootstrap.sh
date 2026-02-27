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
    REMAINING_ARGS=("${remaining[@]+"${remaining[@]}"}")
}

run_remote_script() {
    local script_url="${BASE_URL}/main.sh"
    local temp_script
    local download_success=0

    log "info" "远程脚本 URL: ${script_url}"

    temp_script=$(mktemp -t quick-script.XXXXXX)
    if [[ -z "$temp_script" ]] || [[ ! -f "$temp_script" ]]; then
        log "error" "创建临时文件失败"
        return 1
    fi

    log "info" "下载远程脚本到临时文件..."

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
        log "error" "未找到 wget 或 curl 工具，无法下载远程脚本"
        rm -f "${temp_script}" 2>/dev/null || true
        return 1
    fi

    if [[ ${download_success} -eq 0 ]]; then
        log "error" "下载远程脚本失败，请检查网络连接或 URL 是否正确"
        rm -f "${temp_script}" 2>/dev/null || true
        return 1
    fi

    if ! bash -n "${temp_script}" 2>/dev/null; then
        log "error" "下载的脚本存在语法错误，可能网络传输异常"
        rm -f "${temp_script}" 2>/dev/null || true
        return 1
    fi

    log "info" "脚本下载成功，开始执行..."

    local script_exit_code=0
    ONE_SCRIPT_CHANNEL="${CHANNEL}" ONE_SCRIPT_BASE_URL="${BASE_URL}" \
        bash "${temp_script}" ${REMAINING_ARGS[@]+"${REMAINING_ARGS[@]}"} || script_exit_code=$?

    rm -f "${temp_script}" 2>/dev/null || true

    if [[ ${script_exit_code} -ne 0 ]]; then
        log "error" "远程脚本执行失败 (退出码: ${script_exit_code})"
        return 1
    fi

    return 0
}

main() {
    parse_channel_args "$@"
    run_remote_script
}

# 如果直接执行（非被 source），则运行 main
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
