#!/usr/bin/env bash
set -Eeuo pipefail

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

log() {
    local level=$1
    shift
    case "$level" in
        info) printf "%b[信息]%b %s\n" "$GREEN" "$RESET" "$*" ;;
        warn) printf "%b[警告]%b %s\n" "$YELLOW" "$RESET" "$*" ;;
        error) printf "%b[错误]%b %s\n" "$RED" "$RESET" "$*" ;;
    esac
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log error "请使用root权限运行该脚本"
        exit 1
    fi
}

detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update"
    elif command -v yum >/dev/null 2>&1; then
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum makecache"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf makecache"
    elif command -v apk >/dev/null 2>&1; then
        PKG_INSTALL="apk add --no-cache"
        PKG_UPDATE="apk update"
    else
        log error "未找到可用的软件包管理器"
        exit 1
    fi
}

install_dependencies() {
    log info "安装必要依赖..."
    eval "$PKG_UPDATE" >/dev/null 2>&1 || true
    local packages=(curl tar gzip openssl coreutils util-linux)
    # apk与其他发行版命名差异
    if command -v apt-get >/dev/null 2>&1; then
        packages+=(iproute2 lsb-release procps iputils-ping)
    elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
        packages+=(iproute procps-ng iputils)
    elif command -v apk >/dev/null 2>&1; then
        packages+=(iproute2 shadow procps iputils)
    fi
    eval "$PKG_INSTALL ${packages[*]}" >/dev/null
}

ensure_network_stack() {
    local ipv4 ipv6
    ipv4=$(curl -4 -s --max-time 4 https://api.ipify.org || true)
    if [[ -n $ipv4 ]]; then
        ACTIVE_IP_VERSION=4
        PUBLIC_IP="$ipv4"
        log info "检测到 IPv4 地址：$ipv4，将优先使用 IPv4"
        return
    fi
    log warn "未检测到可用的公网 IPv4，尝试使用 IPv6"
    ipv6=$(curl -6 -s --max-time 4 https://api64.ipify.org || true)
    if [[ -n $ipv6 ]]; then
        ACTIVE_IP_VERSION=6
        PUBLIC_IP="$ipv6"
        log info "检测到 IPv6 地址：$ipv6，将使用 IPv6"
        return
    fi
    log error "无法检测到公网 IPv4 或 IPv6 地址，请检查网络连通性"
    exit 1
}

compute_swap_size_mb() {
    local mem_kb mem_mb swap_mb
    mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    mem_mb=$(( (mem_kb + 1023) / 1024 ))
    if (( mem_mb <= 512 )); then
        swap_mb=1024
    elif (( mem_mb <= 2048 )); then
        swap_mb=$(( mem_mb * 2 ))
    elif (( mem_mb <= 4096 )); then
        swap_mb=$mem_mb
    elif (( mem_mb <= 16384 )); then
        swap_mb=8192
    else
        swap_mb=4096
    fi
    printf "%s" "$swap_mb"
}

enable_swap() {
    if swapon --show | grep -q "^/swapfile"; then
        log info "检测到已有swapfile，跳过创建"
        return
    fi
    local swap_mb
    swap_mb=$(compute_swap_size_mb)
    if [[ -z $swap_mb || $swap_mb -le 0 ]]; then
        log warn "无法计算合适的swap大小，跳过"
        return
    fi
    log info "创建 ${swap_mb}MB swapfile..."
    if ! fallocate -l "${swap_mb}M" /swapfile 2>/dev/null; then
        dd if=/dev/zero of=/swapfile bs=1M count="$swap_mb" status=progress
    fi
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    if ! grep -q "^/swapfile" /etc/fstab; then
        echo "/swapfile none swap defaults 0 0" >> /etc/fstab
    fi
    sysctl vm.swappiness=10 >/dev/null
    log info "swap创建完成"
}

enable_bbr() {
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "") == "bbr" ]]; then
        log info "BBR已启用"
        return
    fi
    local available
    available=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || echo "")
    if ! grep -qw "bbr" <<<"$available"; then
        if command -v modprobe >/dev/null 2>&1; then
            log warn "未检测到BBR模块，尝试加载 tcp_bbr..."
            if modprobe tcp_bbr >/dev/null 2>&1; then
                log info "tcp_bbr 模块加载成功"
                available=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || echo "")
                if [[ ! -f /etc/modules-load.d/bbr.conf ]]; then
                    printf "tcp_bbr\n" >/etc/modules-load.d/bbr.conf
                elif ! grep -qw "tcp_bbr" /etc/modules-load.d/bbr.conf 2>/dev/null; then
                    printf "tcp_bbr\n" >>/etc/modules-load.d/bbr.conf
                fi
            else
                log warn "tcp_bbr 模块加载失败"
            fi
        fi
    fi
    if ! grep -qw "bbr" <<<"$available"; then
        log warn "内核暂不支持BBR，跳过该步骤"
        return
    fi
    cat >/etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system >/dev/null
    log info "BBR已开启"
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
        port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/sing-box/config.json 2>/dev/null | head -n 1 | grep -oE '[0-9]+')
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
    if [[ ${ACTIVE_IP_VERSION:-4} -eq 4 ]]; then
        listen_address="0.0.0.0"
    else
        listen_address="::"
    fi
    generate_reality_keys
    install -d -m 750 "$config_dir"
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
    if [[ ${ACTIVE_IP_VERSION:-4} -eq 4 ]]; then
        ip=$(curl -4 -s --max-time 6 https://api.ip.sb/ip || curl -4 -s --max-time 6 https://ifconfig.me || true)
    else
        ip=$(curl -6 -s --max-time 6 https://api64.ipify.org || curl -6 -s --max-time 6 https://ifconfig.co || true)
    fi
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
    reset_existing_deployment_if_needed
    detect_package_manager
install_dependencies
ensure_network_stack
enable_swap
enable_bbr
install_singbox
ensure_system_user
create_config
create_service
print_summary
log info "若需自定义SNI，可在执行前设置环境变量 VISION_SERVER_NAME"
log info "如果希望增加监控/防火墙等功能，可告知以便扩展"
}

main() {
    require_root
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
