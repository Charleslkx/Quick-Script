#!/usr/bin/env bash
set -Eeuo pipefail

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

CHANNEL="main"
DISTRO="unknown"

log() {
    local level=$1
    shift
    case "$level" in
        info) printf "%b[信息]%b %s\n" "$GREEN" "$RESET" "$*" ;;
        warn) printf "%b[警告]%b %s\n" "$YELLOW" "$RESET" "$*" ;;
        error) printf "%b[错误]%b %s\n" "$RED" "$RESET" "$*" ;;
    esac
}

normalize_channel() {
    local channel
    channel=$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')
    case "$channel" in
        dev|main)
            echo "$channel"
            ;;
        *)
            echo "main"
            ;;
    esac
}

init_channel() {
    CHANNEL=$(normalize_channel "${ONE_SCRIPT_CHANNEL:-}")
    log info "当前渠道：${CHANNEL}"
}

cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

is_interactive() {
    [[ -t 0 ]] || [[ -c /dev/tty ]]
}

read_prompt() {
    local prompt="$1"
    local default="${2:-}"
    local answer=""

    if [[ -t 0 ]]; then
        read -r -p "$prompt" answer
    elif [[ -c /dev/tty ]]; then
        read -r -p "$prompt" answer </dev/tty || answer="$default"
    else
        answer="$default"
    fi

    echo "${answer:-$default}"
}

first_ipv4() {
    local timeout=${1:-6}
    local url ip
    for url in "https://api.ipify.org" "https://api.ip.sb/ip" "https://ifconfig.me"; do
        ip=$(curl -4 -s --max-time "$timeout" "$url" || true)
        if [[ -n $ip ]]; then
            printf "%s" "$ip"
            return
        fi
    done
}

setup_locale() {
    log info "检查并设置 locale 为 C.UTF-8..."
    if locale -a | grep -qi "^C.utf8$\|^C.UTF-8$"; then
        log info "C.UTF-8 locale 已存在"
    else
        log info "C.UTF-8 locale 不存在，正在生成..."
        if cmd_exists apt-get; then
            apt-get install -y locales >/dev/null 2>&1 || true
            if ! locale -a | grep -qi "^C.utf8$\|^C.UTF-8$"; then
                localedef -i C -f UTF-8 C.UTF-8 >/dev/null 2>&1 || true
            fi
        elif cmd_exists yum || cmd_exists dnf; then
            if cmd_exists dnf; then
                dnf install -y glibc-langpack-en >/dev/null 2>&1 || true
            else
                yum install -y glibc-common >/dev/null 2>&1 || true
            fi
            if ! locale -a | grep -qi "^C.utf8$\|^C.UTF-8$"; then
                localedef -i C -f UTF-8 C.UTF-8 >/dev/null 2>&1 || true
            fi
        elif cmd_exists apk; then
            apk add --no-cache musl-locales >/dev/null 2>&1 || true
        fi
        log info "locale 生成完成"
    fi

    export LANG=C.UTF-8
    export LC_ALL=C.UTF-8

    if [[ -f /etc/default/locale ]]; then
        cat >/etc/default/locale <<EOF
LANG=C.UTF-8
LC_ALL=C.UTF-8
EOF
    fi
    if [[ -f /etc/environment ]]; then
        if ! grep -q "^LANG=" /etc/environment; then
            echo "LANG=C.UTF-8" >> /etc/environment
        else
            sed -i 's/^LANG=.*/LANG=C.UTF-8/' /etc/environment
        fi
        if ! grep -q "^LC_ALL=" /etc/environment; then
            echo "LC_ALL=C.UTF-8" >> /etc/environment
        else
            sed -i 's/^LC_ALL=.*/LC_ALL=C.UTF-8/' /etc/environment
        fi
    fi
    
    log info "locale 已设置为 C.UTF-8"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log error "请使用root权限运行该脚本"
        exit 1
    fi
}

check_login_shell() {
    if [[ $EUID -ne 0 ]]; then
        return
    fi

    local has_sbin_path=0
    if [[ ":$PATH:" == *":/sbin:"* ]] || [[ ":$PATH:" == *":/usr/sbin:"* ]]; then
        has_sbin_path=1
    fi

    local has_sysctl=0
    if cmd_exists sysctl || [[ -x /sbin/sysctl ]] || [[ -x /usr/sbin/sysctl ]]; then
        has_sysctl=1
    fi

    if [[ $has_sbin_path -eq 1 ]] && [[ $has_sysctl -eq 1 ]]; then
        return
    fi

    log warn "检测到您可能使用 'su' 而非 'su -' 进入 root 用户"
    log warn "这可能导致 PATH 环境变量不完整，影响脚本执行"
    echo "================================================"
    echo "当前 PATH: $PATH"
    echo "建议使用 'su -' 或 'sudo -i' 来获得完整的 root 环境"
    echo "================================================"
    
    printf "是否使用完整登录 shell 重新执行脚本? [Y/n] "
    
    local choice
    # 兼容 curl | bash 模式
    if [[ -t 0 ]]; then
        read -r choice
    elif [[ -c /dev/tty ]]; then
        read -r choice </dev/tty || choice="y"
    else
        choice="y"
    fi

    choice=${choice:-y}
    
    case "$choice" in
        [nN][oO]|[nN])
            log warn "用户选择继续当前环境，可能会遇到命令找不到的问题"
            export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
            log info "已临时添加系统路径到 PATH"
            ;;
        *)
            log info "正在使用完整登录 shell 重新执行脚本..."
            # 重新执行 bootstrap.sh，让 channel 参数可以被正确解析
            exec su - root -c "bash <(curl -fsSL https://raw.githubusercontent.com/charleslkx/one-script/main/bootstrap.sh) --channel=main $*"
            ;;
    esac
}

detect_release() {
    DISTRO="unknown"
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO="${ID:-unknown}"
        if [[ "$DISTRO" != "debian" && "$DISTRO" != "ubuntu" ]]; then
            if [[ "${ID_LIKE:-}" == *debian* ]]; then
                DISTRO="debian"
            fi
        fi
    fi
}

is_debian_family() {
    [[ "$DISTRO" == "debian" || "$DISTRO" == "ubuntu" ]]
}

get_memory_size_mb() {
    local mem_kb
    mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    echo $((mem_kb / 1024))
}

get_disk_available_mb() {
    local available_kb
    available_kb=$(df -k / | awk 'NR==2 {print $4}')
    echo $((available_kb / 1024))
}

systemd_available() {
    [[ -d /run/systemd/system ]] && cmd_exists systemctl
}

set_sysctl_value() {
    local key="$1"
    local value="$2"
    if [[ -f /etc/sysctl.conf ]] && grep -q "^${key}=" /etc/sysctl.conf 2>/dev/null; then
        sed -i "s/^${key}=.*/${key}=${value}/" /etc/sysctl.conf
    else
        echo "${key}=${value}" >> /etc/sysctl.conf
    fi
    sysctl "${key}=${value}" >/dev/null 2>&1 || true
}

apply_memory_tuning() {
    local swappiness="$1"
    local vfs_cache_pressure="$2"
    set_sysctl_value "vm.swappiness" "${swappiness}"
    set_sysctl_value "vm.vfs_cache_pressure" "${vfs_cache_pressure}"
}

ensure_memory_dependencies() {
    if ! is_debian_family; then
        return 0
    fi

    local packages=()
    if ! cmd_exists modprobe; then
        packages+=("kmod")
    fi
    if ! cmd_exists mkswap || ! cmd_exists swapon; then
        packages+=("util-linux")
    fi
    if ! cmd_exists sysctl; then
        packages+=("procps")
    fi

    if [[ ${#packages[@]} -gt 0 ]]; then
        log info "正在安装内存相关依赖: ${packages[*]}"
        eval "$PKG_UPDATE" >/dev/null 2>&1 || true
        eval "$PKG_INSTALL ${packages[*]}" >/dev/null 2>&1 || true
    fi
}

is_zram_active() {
    [[ -f /proc/swaps ]] && grep -q "/dev/zram0" /proc/swaps
}

is_disk_swap_active() {
    if cmd_exists swapon; then
        swapon --show --noheadings 2>/dev/null | awk '{print $1}' | grep -qv "/dev/zram0"
        return $?
    fi
    return 1
}

list_swap_devices() {
    if cmd_exists swapon; then
        swapon --show --noheadings 2>/dev/null | awk '{print $1}'
    fi
}

ZRAM_SERVICE_FILE="/etc/systemd/system/quick-script-zram.service"
ZRAM_SCRIPT_PATH="/usr/local/bin/quick-script-zram"
ZRAM_ENV_FILE="/etc/quick-script/zram.env"

write_zram_runtime_files() {
    local zram_mb="$1"
    local zram_algo="$2"
    local zram_priority="$3"

    mkdir -p /etc/quick-script
    cat >"${ZRAM_ENV_FILE}" <<EOF
ZRAM_SIZE_MB=${zram_mb}
ZRAM_ALGO=${zram_algo}
ZRAM_PRIORITY=${zram_priority}
EOF

    cat >"${ZRAM_SCRIPT_PATH}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ZRAM_ENV="/etc/quick-script/zram.env"
if [[ -f "${ZRAM_ENV}" ]]; then
    # shellcheck disable=SC1090
    source "${ZRAM_ENV}"
fi

ZRAM_SIZE_MB="${ZRAM_SIZE_MB:-512}"
ZRAM_ALGO="${ZRAM_ALGO:-lz4}"
ZRAM_PRIORITY="${ZRAM_PRIORITY:-100}"

start_zram() {
    modprobe zram num_devices=1

    swapoff /dev/zram0 2>/dev/null || true

    if [[ -e /sys/block/zram0/reset ]]; then
        echo 1 > /sys/block/zram0/reset || true
    fi

    if [[ -n "${ZRAM_ALGO}" && -w /sys/block/zram0/comp_algorithm ]]; then
        echo "${ZRAM_ALGO}" > /sys/block/zram0/comp_algorithm || true
    fi

    echo "$((ZRAM_SIZE_MB * 1024 * 1024))" > /sys/block/zram0/disksize

    mkswap /dev/zram0 >/dev/null
    swapon -p "${ZRAM_PRIORITY}" /dev/zram0
}

stop_zram() {
    swapoff /dev/zram0 2>/dev/null || true
    if [[ -e /sys/block/zram0/reset ]]; then
        echo 1 > /sys/block/zram0/reset || true
    fi
}

case "${1:-start}" in
    start)
        start_zram
        ;;
    stop)
        stop_zram
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
EOF

    chmod +x "${ZRAM_SCRIPT_PATH}"
}

enable_zram_service() {
    cat >"${ZRAM_SERVICE_FILE}" <<EOF
[Unit]
Description=Quick-Script ZRAM Swap
DefaultDependencies=no
After=local-fs.target
Before=swap.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${ZRAM_SCRIPT_PATH} start
ExecStop=${ZRAM_SCRIPT_PATH} stop

[Install]
WantedBy=swap.target
EOF

    if systemd_available; then
        systemctl daemon-reload
        systemctl enable --now "$(basename "${ZRAM_SERVICE_FILE}")" >/dev/null 2>&1 || true
    fi
}

configure_zram_swap() {
    local zram_mb="$1"
    local zram_algo="${2:-lz4}"
    local zram_priority="${3:-100}"

    ensure_memory_dependencies

    if ! modprobe zram num_devices=1 >/dev/null 2>&1; then
        log warn "加载 zram 模块失败，跳过 zram 配置"
        return 1
    fi

    if systemd_available; then
        if systemctl list-unit-files 2>/dev/null | grep -q "^zramswap.service"; then
            systemctl disable --now zramswap.service >/dev/null 2>&1 || true
            log warn "检测到 zramswap 服务，已禁用以避免冲突"
        fi
        systemctl stop "$(basename "${ZRAM_SERVICE_FILE}")" >/dev/null 2>&1 || true
    else
        swapoff /dev/zram0 2>/dev/null || true
    fi

    write_zram_runtime_files "${zram_mb}" "${zram_algo}" "${zram_priority}"
    enable_zram_service
    apply_memory_tuning "100" "50"

    if systemd_available; then
        if systemctl is-active --quiet "$(basename "${ZRAM_SERVICE_FILE}")"; then
            log info "ZRAM 已启用并设置开机自启"
        else
            log warn "ZRAM 服务启动失败，请检查 systemd 日志"
        fi
    else
        "${ZRAM_SCRIPT_PATH}" start >/dev/null 2>&1 || true
        log warn "未检测到 systemd，ZRAM 仅在当前会话生效"
    fi
}

recommend_hybrid_sizes() {
    local memory_mb="$1"
    local zram_mb=$((memory_mb / 2))

    if [[ $zram_mb -lt 256 ]]; then
        zram_mb=256
    elif [[ $zram_mb -gt 1024 ]]; then
        zram_mb=1024
    fi

    local swap_mb
    if [[ $memory_mb -le 512 ]]; then
        swap_mb=1024
    elif [[ $memory_mb -le 1024 ]]; then
        swap_mb=2048
    elif [[ $memory_mb -le 2048 ]]; then
        swap_mb=2048
    else
        swap_mb=1024
    fi

    echo "${zram_mb} ${swap_mb}"
}

create_swap_file() {
    local swap_size="$1"
    log info "正在创建 ${swap_size}MB 的 swap 文件..."

    local available_space_mb
    available_space_mb=$(get_disk_available_mb)
    local required_space_mb=$((swap_size + 200))

    if [[ $available_space_mb -lt $required_space_mb ]]; then
        log warn "磁盘空间不足，需要 ${required_space_mb}MB，可用 ${available_space_mb}MB"
        return 1
    fi

    if [[ -f /swapfile ]]; then
        log warn "检测到已存在的 /swapfile，正在移除..."
        swapoff /swapfile 2>/dev/null || true
        rm -f /swapfile
    fi

    if dd if=/dev/zero of=/swapfile bs=1M count="${swap_size}" 2>/dev/null; then
        chmod 600 /swapfile
        if mkswap /swapfile >/dev/null 2>&1; then
            if swapon /swapfile >/dev/null 2>&1; then
                if ! grep -q "/swapfile" /etc/fstab 2>/dev/null; then
                    echo "/swapfile none swap defaults 0 0" >> /etc/fstab
                fi

                local swappiness=10
                local vfs_cache_pressure=50
                if is_zram_active; then
                    swappiness=100
                fi
                apply_memory_tuning "${swappiness}" "${vfs_cache_pressure}"

                log info "swap 创建并启用成功"
                return 0
            fi
        fi
    fi

    log warn "swap 创建失败"
    rm -f /swapfile >/dev/null 2>&1 || true
    return 1
}

setup_hybrid_memory() {
    if ! is_debian_family; then
        log warn "当前系统非 Debian/Ubuntu，跳过混合内存方案"
        return 0
    fi

    if is_zram_active && is_disk_swap_active; then
        log info "检测到 ZRAM 与 Swap 已配置，跳过"
        return 0
    fi

    if is_interactive; then
        local choice
        choice=$(read_prompt "是否配置混合内存方案 (zram + swap)? [Y/n]: " "Y")
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            log info "已跳过混合内存方案"
            return 0
        fi
    fi

    ensure_memory_dependencies

    local memory_mb available_space_mb max_swap_mb
    memory_mb=$(get_memory_size_mb)
    available_space_mb=$(get_disk_available_mb)
    max_swap_mb=$((available_space_mb - 1024))
    if [[ $max_swap_mb -lt 0 ]]; then
        max_swap_mb=0
    fi

    log info "当前内存：${memory_mb}MB"
    log info "根分区可用空间：${available_space_mb}MB"

    local rec_zram rec_swap
    read -r rec_zram rec_swap < <(recommend_hybrid_sizes "${memory_mb}")

    if [[ $max_swap_mb -lt 128 ]]; then
        rec_swap=0
        log warn "磁盘空间不足，将仅配置 zram"
    elif [[ $rec_swap -gt $max_swap_mb ]]; then
        rec_swap=$max_swap_mb
        log warn "根据磁盘空间调整推荐 swap 为 ${rec_swap}MB"
    fi

    local existing_swap
    existing_swap=$(list_swap_devices | tr '\n' ' ')
    if [[ -n "${existing_swap}" ]]; then
        log warn "检测到已有 swap 设备：${existing_swap}"
    fi

    log info "推荐方案：zram ${rec_zram}MB + swap ${rec_swap}MB"

    if [[ $rec_zram -gt 0 ]]; then
        if ! configure_zram_swap "${rec_zram}" "lz4" "100"; then
            log warn "ZRAM 配置失败，继续后续流程"
        fi
    fi

    if [[ $rec_swap -gt 0 ]]; then
        if [[ -n "${existing_swap}" ]]; then
            if is_interactive; then
                local replace_choice
                replace_choice=$(read_prompt "检测到已有 swap，是否仍创建/替换 /swapfile? [y/N]: " "N")
                if [[ "$replace_choice" =~ ^[Yy]$ ]]; then
                    create_swap_file "${rec_swap}" || true
                else
                    log info "保留现有 swap，跳过 /swapfile 创建"
                fi
            else
                log info "检测到已有 swap，跳过 /swapfile 创建"
            fi
        else
            create_swap_file "${rec_swap}" || true
        fi
    else
        log info "未创建新的 swap 文件"
    fi
}

detect_package_manager() {
    if cmd_exists apt-get; then
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update"
        PKG_EXTRA="iproute2 lsb-release procps iputils-ping"
    elif cmd_exists yum; then
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum makecache"
        PKG_EXTRA="iproute procps-ng iputils"
    elif cmd_exists dnf; then
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf makecache"
        PKG_EXTRA="iproute procps-ng iputils"
    elif cmd_exists apk; then
        PKG_INSTALL="apk add --no-cache"
        PKG_UPDATE="apk update"
        PKG_EXTRA="iproute2 shadow procps iputils"
    else
        log error "未找到可用的软件包管理器"
        exit 1
    fi
}

install_dependencies() {
    log info "安装必要依赖..."
    eval "$PKG_UPDATE" >/dev/null 2>&1 || true
    local packages=(curl tar gzip openssl coreutils util-linux $PKG_EXTRA)
    eval "$PKG_INSTALL ${packages[*]}" >/dev/null
}

ensure_network_stack() {
    local ipv4 attempt
    for attempt in 1 2 3; do
        ipv4=$(first_ipv4 4 || true)
        if [[ -n $ipv4 ]]; then
            PUBLIC_IP="$ipv4"
            log info "检测到 IPv4 地址：$ipv4"
            return
        fi
        log warn "第 ${attempt} 次尝试未获取到公网 IPv4，稍后重试..."
        sleep 2
    done
    log error "连续 3 次未检测到公网 IPv4 地址，请检查网络连通性后重试"
    exit 1
}


enable_bbr() {
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr && \
       sysctl net.core.default_qdisc | grep -q fq; then
        log info "BBR+FQ 已启用"
        return
    fi

    log info "正在启用 BBR+FQ..."

    if ! lsmod | grep -q tcp_bbr; then
        modprobe tcp_bbr >/dev/null 2>&1 || true
    fi

    cat >/etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system >/dev/null 2>&1

    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        log info "BBR启动成功"
    else
        log warn "BBR启动失败，您的内核可能太旧。建议升级内核。"
    fi
}

setup_cron_restart() {
    log info "配置每日定时重启任务 (UTC+8 5:00)..."
    
    local cron_cmd="systemctl restart sing-box"
    local cron_file="/var/spool/cron/crontabs/root"
    [ ! -f "$cron_file" ] && cron_file="/var/spool/cron/root"

    local hour=21
    if date +%z | grep -q "+0800"; then
        hour=5
    fi
    
    local cron_job="0 $hour * * * $cron_cmd"
    
    if command -v crontab >/dev/null 2>&1; then
        local current_cron
        current_cron=$(crontab -l 2>/dev/null || true)
        
        if echo "$current_cron" | grep -q "$cron_cmd"; then
            log info "重启任务已存在，跳过"
        else
            (echo "$current_cron"; echo "$cron_job") | crontab -
            log info "已添加定时任务: $cron_job"
        fi
    else
        log warn "未找到 crontab，跳过定时任务设置"
    fi
}

check_existing_installation() {
    local config="/etc/sing-box/config.json"
    local pub_key_file="/etc/sing-box/public.key"
    
    if [[ -f "$config" ]]; then
        log warn "检测到已安装 sing-box 服务"

        local config_content
        config_content=$(tr -d '[:space:]' < "$config")
        
        local port uuid sni server_ip short_id
        
        port=$(echo "$config_content" | sed -n 's/.*"listen_port":\([0-9]*\).*/\1/p')
        uuid=$(echo "$config_content" | sed -n 's/.*"uuid":"\([^"]*\)".*/\1/p')
        sni=$(echo "$config_content" | sed -n 's/.*"server_name":"\([^"]*\)".*/\1/p')
        short_id=$(echo "$config_content" | sed -n 's/.*"short_id":\["\([^"]*\)".*/\1/p')
        
        [[ -z "$port" ]] && port="unknown"
        [[ -z "$uuid" ]] && uuid="unknown"
        [[ -z "$sni" ]] && sni="unknown"
        [[ -z "$short_id" ]] && short_id="unknown"
        
        server_ip=$(get_public_ip)
        
        echo "==============================================="
        echo "当前配置信息:"
        echo "端口: $port"
        echo "UUID: $uuid"
        echo "SNI:  $sni"
        echo "配置路径: $config"
        
        if [[ -f "$pub_key_file" ]]; then
            local pbk
            pbk=$(cat "$pub_key_file")
            local link="vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&type=tcp&headerType=none&alpn=h2&pbk=${pbk}&sid=${short_id}&dest=${sni}%3A443#singbox-existing"
            echo "当前链接: $link"
        else
            echo "当前链接: 无法完全重建 (缺少公钥文件)"
        fi
        echo "==============================================="
        
        printf "是否重新安装? [y/N] "
        if [[ -t 0 ]]; then
            read -r choice
        elif [[ -c /dev/tty ]]; then
            read -r choice </dev/tty || choice="n"
        else
            choice="n"
        fi
        
        case "$choice" in
            [yY][eE][sS]|[yY])
                log info "用户选择重新安装，正在清理旧服务..."
                remove_singbox
                ;;
            *)
                log info "用户取消安装或未检测到输入，脚本退出"
                exit 0
                ;;
        esac
    fi
}


detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) log error "当前架构 $(uname -m) 暂不支持" ; exit 1 ;;
    esac
}

fetch_latest_singbox() {
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local tag
    tag=$(curl -s "$api_url" | grep -oP '"tag_name":\s*"\K[^"]+')
    if [[ -z $tag ]]; then
        log error "无法获取sing-box最新版本信息"
        exit 1
    fi
    SINGBOX_TAG="$tag"
    local version="${tag#v}"
    SINGBOX_FILENAME="sing-box-${version}-linux-${ARCH}.tar.gz"
    SINGBOX_DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/${tag}/${SINGBOX_FILENAME}"
}

install_singbox() {
    if command -v sing-box >/dev/null 2>&1; then
        log info "检测到已安装sing-box，跳过下载"
        return
    fi
    detect_arch
    fetch_latest_singbox
    log info "下载并安装 sing-box ${SINGBOX_TAG}"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    curl -Ls "$SINGBOX_DOWNLOAD_URL" -o "$tmpdir/sing-box.tar.gz"
    tar -xf "$tmpdir/sing-box.tar.gz" -C "$tmpdir"
    local extracted
    extracted=$(find "$tmpdir" -maxdepth 1 -type d -name "sing-box*" | head -n 1)
    if [[ -z $extracted ]]; then
        log error "解压sing-box失败"
        exit 1
    fi

    install -Dm755 "${extracted}/sing-box" /usr/local/bin/sing-box
    if [[ -f "${extracted}/geoip.db" ]]; then
        install -Dm644 "${extracted}/geoip.db" /usr/local/share/sing-box/geoip.db
    fi
    if [[ -f "${extracted}/geosite.db" ]]; then
        install -Dm644 "${extracted}/geosite.db" /usr/local/share/sing-box/geosite.db
    fi

    rm -rf "$tmpdir"
    trap - EXIT
}

ensure_system_user() {
    if ! id -u sing-box >/dev/null 2>&1; then
        useradd --system --home-dir /var/lib/sing-box --create-home --shell /usr/sbin/nologin sing-box
    fi
}

remove_singbox() {
    log info "开始卸载 sing-box..."
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files | grep -q "^sing-box.service"; then
            systemctl stop sing-box.service >/dev/null 2>&1 || true
            systemctl disable sing-box.service >/dev/null 2>&1 || true
        fi
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload >/dev/null 2>&1 || true
    else
        log warn "未检测到systemd，跳过服务停止"
    fi
    rm -rf /etc/sing-box
    rm -f /usr/local/bin/sing-box
    rm -rf /usr/local/share/sing-box
    rm -rf /var/lib/sing-box
    if getent passwd sing-box >/dev/null 2>&1; then
        if command -v pkill >/dev/null 2>&1; then
            pkill -9 -u sing-box >/dev/null 2>&1 || true
        fi
        userdel -r sing-box >/dev/null 2>&1 || userdel sing-box >/dev/null 2>&1 || true
    fi
    log info "卸载 sing-box 完成"
}

debug_singbox() {
    log info "开始收集调试信息"
    if command -v sing-box >/dev/null 2>&1; then
        log info "sing-box 版本：$(sing-box version 2>/dev/null | head -n 1)"
    else
        log warn "未检测到 sing-box 可执行文件"
    fi
    if [[ -f /etc/sing-box/config.json ]]; then
        log info "配置文件存在：/etc/sing-box/config.json"
        local port
        port=$(grep -oE '"listen_port"[[:space:]]*:[[:space:]]*[0-9]+' /etc/sing-box/config.json 2>/dev/null | head -n 1 | grep -oE '[0-9]+')
        if [[ -n $port ]]; then
            log info "监听端口：${port}"
        fi
    else
        log warn "未找到 sing-box 配置文件"
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files | grep -q "^sing-box.service"; then
            local state
            state=$(systemctl is-active sing-box.service 2>/dev/null || echo "unknown")
            log info "systemd 服务状态：${state}"
            if command -v journalctl >/dev/null 2>&1; then
                log info "最近 20 行日志："
                journalctl -u sing-box --no-pager -n 20 2>/dev/null || log warn "暂无日志"
            else
                log warn "无法获取日志：未找到 journalctl"
            fi
        else
            log warn "systemd 中未注册 sing-box.service"
        fi
    else
        log warn "未检测到systemd环境"
    fi
    if command -v ss >/dev/null 2>&1; then
        log info "当前监听端口："
        if ss -ltnp | grep -q sing-box; then
            ss -ltnp | grep sing-box
        else
            log warn "未检测到 sing-box 监听端口"
        fi
    fi
    log info "调试信息收集完成"
}

existing_vless_reality() {
    local config="/etc/sing-box/config.json"
    if [[ -f $config ]]; then
        if grep -Eq '"type"[[:space:]]*:[[:space:]]*"vless"' "$config" && \
           grep -Eq '"flow"[[:space:]]*:[[:space:]]*"xtls-rprx-vision"' "$config" && \
           grep -Eq '"reality"' "$config"; then
            return 0
        fi
    fi
    return 1
}

reset_existing_deployment_if_needed() {
    if existing_vless_reality; then
        log warn "检测到现有 vless+vision+reality 部署，准备重新构建..."
        remove_singbox
    fi
}

generate_port() {
    local port attempt has_ss
    if command -v ss >/dev/null 2>&1; then
        has_ss=1
    else
        has_ss=0
    fi
    for attempt in $(seq 1 30); do
        port=$(shuf -i 20000-60000 -n 1)
        if [[ $has_ss -eq 0 ]] || ! ss -ltn 2>/dev/null | awk '{print $4}' | tr -d '[]' | awk -F':' '{print $NF}' | grep -qw "$port"; then
            printf "%s" "$port"
            return
        fi
    done
    printf "44347"
}

generate_short_id() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 4
    else
        tr -dc 'a-f0-9' </dev/urandom | head -c 8
    fi
}

generate_reality_keys() {
    local output
    output=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(printf "%s\n" "$output" | grep -i "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(printf "%s\n" "$output" | grep -i "PublicKey" | awk '{print $2}')
    if [[ -z $PRIVATE_KEY || -z $PUBLIC_KEY ]]; then
        log error "Reality密钥生成失败"
        exit 1
    fi
}

create_config() {
    local config_dir="/etc/sing-box"
    local port uuid short_id server_name listen_address
    port=$(generate_port)
    uuid=$(cat /proc/sys/kernel/random/uuid)
    short_id=$(generate_short_id)
    local default_server="icloud.com"
    if [[ -n ${VISION_SERVER_NAME:-} ]]; then
        server_name=$VISION_SERVER_NAME
    else
        server_name=$default_server
    fi
    listen_address="0.0.0.0"
    generate_reality_keys
    install -d -m 750 "$config_dir"

    echo "$PUBLIC_KEY" > "${config_dir}/public.key"
    chmod 644 "${config_dir}/public.key"
    
    cat >"${config_dir}/config.json" <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "${listen_address}",
      "listen_port": ${port},
      "users": [
        {
          "uuid": "${uuid}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${server_name}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${server_name}",
            "server_port": 443
          },
          "private_key": "${PRIVATE_KEY}",
          "short_id": [
            "${short_id}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
EOF
    chown -R sing-box:sing-box "$config_dir"
    LISTEN_PORT=$port
    CLIENT_UUID=$uuid
    SHORT_ID=$short_id
    SERVER_NAME=$server_name
}

create_service() {
    if ! command -v systemctl >/dev/null 2>&1; then
        log error "未检测到systemd环境，请手动管理 sing-box 进程"
        exit 1
    fi
    cat >/etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box service
After=network-online.target
Wants=network-online.target

[Service]
User=sing-box
Group=sing-box
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now sing-box.service
}

get_public_ip() {
    if [[ -n ${PUBLIC_IP:-} ]]; then
        printf "%s" "$PUBLIC_IP"
        return
    fi
    local ip
    ip=$(first_ipv4 6 || true)
    if [[ -z $ip ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    printf "%s" "$ip"
}

print_summary() {
    local ip alias vless_url host_part
    ip=$(get_public_ip)
    alias="singbox-reality"
    if [[ $ip == *:* ]]; then
        host_part="[${ip}]"
    else
        host_part="$ip"
    fi
    vless_url="vless://${CLIENT_UUID}@${host_part}:${LISTEN_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SERVER_NAME}&fp=chrome&type=tcp&headerType=none&alpn=h2&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&dest=${SERVER_NAME}%3A443#${alias}"
    printf "\n%b=== 部署完成 ===%b\n" "$GREEN" "$RESET"
    printf "%b监听端口：%b%s\n" "$GREEN" "$RESET" "$LISTEN_PORT"
    printf "%b客户端UUID：%b%s\n" "$GREEN" "$RESET" "$CLIENT_UUID"
    printf "%bReality公钥：%b%s\n" "$GREEN" "$RESET" "$PUBLIC_KEY"
    printf "%bReality短ID：%b%s\n" "$GREEN" "$RESET" "$SHORT_ID"
    printf "%bSNI/回落目标：%b%s\n" "$GREEN" "$RESET" "$SERVER_NAME"
    printf "%b服务器IP：%b%s\n" "$GREEN" "$RESET" "$ip"
    printf "%bVLESS链接：%b\n%s\n" "$GREEN" "$RESET" "$vless_url"
}

install_workflow() {
    check_existing_installation
    detect_package_manager
    setup_locale
    install_dependencies
    detect_release
    setup_hybrid_memory
    ensure_network_stack
    enable_bbr
    install_singbox
    ensure_system_user
    create_config
    create_service
    setup_cron_restart
    print_summary
}

main() {
    require_root
    check_login_shell
    init_channel
    local action=${1:-install}
    case "$action" in
        install|--install)
            install_workflow
            ;;
        uninstall|remove|--remove|--uninstall)
            remove_singbox
            ;;
        reinstall|--reinstall)
            remove_singbox
            install_workflow
            ;;
        debug|--debug)
            debug_singbox
            ;;
        *)
            log error "未知操作：$action"
            log info "支持命令：install（默认）、uninstall、reinstall、debug"
            exit 1
            ;;
    esac
}

main "$@"
