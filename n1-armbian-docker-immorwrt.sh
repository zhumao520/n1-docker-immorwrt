#!/bin/bash

# 设置颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置文件路径
CONFIG_FILE="/root/immortalwrt/immortalwrt_config.conf"
LOG_FILE="/root/immortalwrt/immortalwrt_deploy.log"

# 日志函数
log() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

info() {
    log "$1" "INFO"
    echo -e "${GREEN}$1${NC}"
}

warn() {
    log "$1" "WARN"
    echo -e "${YELLOW}$1${NC}"
}

error() {
    log "$1" "ERROR"
    echo -e "${RED}$1${NC}"
}

# 依赖检查函数
check_dependencies() {
    info "检查依赖..."
    local required_tools=("docker" "ip" "ping" "wget" "gzip")
    local missing_tools=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if ! command -v jq &>/dev/null; then
        warn "未安装jq工具，将尝试安装..."
        if command -v apt-get &>/dev/null; then
            apt-get update && apt-get install -y jq
        elif command -v yum &>/dev/null; then
            yum install -y jq
        else
            error "无法自动安装jq，请手动安装后重试"
            missing_tools+=("jq")
        fi

    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        error "缺少必要工具: ${missing_tools[*]}"
        return 1
    fi

    info "所有依赖检查通过"
    return 0
}

# 清理函数
cleanup() {
    local error_message="$1"
    local cleanup_type="$2"

    error "$error_message"

    if [ "$cleanup_type" = "all" ] || [ "$cleanup_type" = "network" ]; then
        warn "正在清理网络配置..."
        ip link show macvlan-shim &>/dev/null && ip link delete macvlan-shim
        docker network inspect macnet &>/dev/null && docker network rm macnet
    fi

    if [ "$cleanup_type" = "all" ] || [ "$cleanup_type" = "container" ]; then
        warn "正在清理容器..."
        docker ps -a -q -f name=immortalwrt &>/dev/null && docker rm -f immortalwrt
    fi

    exit 1
}

# 检查IP地址是否已被使用
is_ip_used() {
    local ip="$1"
    local timeout=1

    ip="${ip%/*}"
    if ip addr | grep -q "$ip"; then
        return 0
    fi
    if ping -c 1 -W $timeout "$ip" &>/dev/null; then
        return 0
    fi
    return 1
}

# 生成一个未被使用的IP地址
generate_unused_ip() {
    local subnet_prefix="$1"
    local gateway="$2"
    local retries=10
    local gateway_last_octet
    gateway_last_octet=$(echo "$gateway" | cut -d '.' -f 4)

    for ((i = 1; i <= retries; i++)); do
        local ip_last_octet=$(( (RANDOM % 248) + 2 ))
        if [ "$ip_last_octet" = "$gateway_last_octet" ]; then
            continue
        fi
        local ip="${subnet_prefix}.${ip_last_octet}"
        if ! is_ip_used "$ip"; then
            echo "$ip"
            return 0
        fi
    done

    error "无法生成未使用的IP地址，请手动指定"
    return 1
}

# 保存配置
save_config() {
    info "保存配置到 $CONFIG_FILE"
    cat >"$CONFIG_FILE" <<EOF
# ImmortalWrt容器配置 - $(date)
INTERFACE=$current_interface
SUBNET=$current_subnet
GATEWAY=$current_gateway
MACVLAN_IP=$new_ip
CONTAINER_IP=$container_ip
IMAGE_VERSION=$image_version
EOF
}

# 加载配置
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        info "从 $CONFIG_FILE 加载配置"
        source "$CONFIG_FILE"
        return 0
    fi
    return 1
}

# 获取网络配置
get_network_config() {
    info "获取当前网络配置..."
    local current_ip_route
    current_ip_route=$(ip route | grep default)
    current_gateway=$(echo "$current_ip_route" | awk '{print $3}')
    current_interface=$(echo "$current_ip_route" | awk '{print $5}')
    current_subnet=$(ip addr show "$current_interface" | grep 'inet ' | awk '{print $2}' | head -n 1)
    if [ -z "$current_subnet" ] || [ -z "$current_gateway" ] || [ -z "$current_interface" ]; then
        error "获取网络配置失败。无法确定子网、网关或接口信息。"
        return 1
    fi
    info "当前网络配置:"
    info "  接口: $current_interface"
    info "  子网: $current_subnet"
    info "  网关: $current_gateway"

    subnet_prefix=$(echo "$current_subnet" | cut -d '/' -f 1 | sed 's/\.[0-9]*$//')
    network_cidr=$(echo "$current_subnet" | cut -d '/' -f 2)
    network_address="${subnet_prefix}.0/${network_cidr}"
    info "  网络地址: $network_address"

    local gateway_prefix subnet_ip_prefix
    gateway_prefix=$(echo "$current_gateway" | cut -d '.' -f 1-3)
    subnet_ip_prefix=$(echo "$subnet_prefix" | cut -d '.' -f 1-3)
    if [ "$gateway_prefix" != "$subnet_ip_prefix" ]; then
        warn "子网 $current_subnet 与网关 $current_gateway 前缀不匹配。使用网关前缀调整子网。"
        subnet_prefix="${gateway_prefix}.0"
        current_subnet="${gateway_prefix}.0/${network_cidr}"
        network_address="${gateway_prefix}.0/${network_cidr}"
        info "  调整后的子网: $current_subnet"
        info "  调整后的网络地址: $network_address"
    fi
    return 0
}

# 创建macvlan网络
create_macvlan_network() {
    info "检查 macnet 网络是否已存在..."
    if docker network inspect macnet &>/dev/null; then
        info "Docker网络 'macnet' 已存在，跳过创建步骤。"
        return 0
    fi
    info "Docker网络 'macnet' 不存在，创建中..."
    info "检查是否有重叠网络..."
    local overlap_found=0
    for net in $(docker network ls --format "{{.Name}}" --filter driver=macvlan); do
        local net_subnet
        net_subnet=$(docker network inspect "$net" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
        if [ -n "$net_subnet" ]; then
            local net_prefix
            net_prefix=$(echo "$net_subnet" | cut -d '/' -f 1 | sed 's/\.[0-9]*$//')
            if [ "$net_prefix" = "$subnet_prefix" ]; then
                warn "警告: 网络 '$net' 已存在，子网前缀 '$net_prefix' 与新网络重叠。"
                overlap_found=1
                break
            fi
        fi
    done
    if [ $overlap_found -eq 1 ]; then
        warn "发现网络重叠，跳过 'macnet' 网络创建。"
        return 0
    fi
    info "创建 macvlan 网络..."
    if ! docker network create -d macvlan \
        --subnet="${network_address}" \
        --gateway="${current_gateway}" \
        -o parent="${current_interface}" \
        macnet; then
        cleanup "创建Docker网络 'macnet' 失败" "network"
        return 1
    fi
    info "Docker网络 'macnet' 创建成功。"
    return 0
}

# 创建macvlan-shim接口
create_macvlan_shim() {
    info "检查 macvlan-shim 接口是否已存在..."
    if ip link show macvlan-shim &>/dev/null; then
        info "macvlan-shim 接口已存在，跳过创建步骤。"
        return 0
    fi
    info "macvlan-shim 接口不存在，创建中..."
    new_ip=$(generate_unused_ip "$subnet_prefix" "$current_gateway")
    if [ -z "$new_ip" ]; then
        cleanup "无法为macvlan-shim分配有效IP地址" "network"
        return 1
    fi
    new_ip="${new_ip}/${network_cidr}"
    info "为macvlan-shim分配IP: $new_ip"
    if ! ip link add macvlan-shim link "$current_interface" type macvlan mode bridge; then
        cleanup "创建macvlan-shim接口失败" "network"
        return 1
    fi
    if ! ip addr add "$new_ip" dev macvlan-shim; then
        ip link delete macvlan-shim
        cleanup "为macvlan-shim分配IP地址失败" "network"
        return 1
    fi
    if ! ip link set macvlan-shim up; then
        ip link delete macvlan-shim
        cleanup "启用macvlan-shim接口失败" "network"
        return 1
    fi
    info "macvlan-shim接口创建并配置成功，IP: $new_ip"
    return 0
}

# 等待容器完全启动
wait_for_container_ready() {
    local container_name="$1"
    local timeout=120  # 等待超时时间(秒)
    local interval=5   # 检查间隔(秒)
    local elapsed=0
    
    info "等待容器 '$container_name' 完全启动..."
    
    # 首先等待容器启动并运行
    while [ $elapsed -lt $timeout ]; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$container_name" 2>/dev/null)" == "true" ]; then
            break
        fi
        sleep $interval
        elapsed=$((elapsed + interval))
        info "等待容器进入运行状态... ($elapsed/$timeout 秒)"
    done
    
    if [ $elapsed -ge $timeout ]; then
        error "容器 '$container_name' 启动超时。"
        return 1
    fi
    
    info "容器已进入运行状态，现在等待内部服务就绪..."
    elapsed=0
    
    # 然后等待关键服务就绪
    while [ $elapsed -lt $timeout ]; do
        # 检查关键进程是否运行
        if docker exec "$container_name" pgrep rpcd &>/dev/null && \
           docker exec "$container_name" pgrep uhttpd &>/dev/null && \
           docker exec "$container_name" pgrep dnsmasq &>/dev/null && \
           docker exec "$container_name" pgrep netifd &>/dev/null; then
            
            # 额外确认uci命令可用
            if docker exec "$container_name" uci -q get system.@system[0] &>/dev/null; then
                info "容器 '$container_name' 内部服务已就绪。"
                sleep 5  # 给予系统额外几秒稳定时间
                return 0
            fi
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
        info "等待容器内部服务就绪... ($elapsed/$timeout 秒)"
    done
    
    warn "容器 '$container_name' 服务就绪等待超时，将尝试继续执行但可能不稳定。"
    return 1
}

# 创建和配置ImmortalWrt容器
setup_immortalwrt_container() {
    local CONTAINER_NEWLY_CREATED=false
    
    info "检查ImmortalWrt容器是否已存在..."
    if [ -n "$(docker ps -a -q -f name=immortalwrt)" ]; then
        info "Docker容器 'immortalwrt' 已存在。"
        
        # 检查容器内部网络配置
        if docker ps -q -f name=immortalwrt &>/dev/null; then
            # 获取容器内部网络配置
            container_lan_ip=$(docker exec immortalwrt uci -q get network.lan.ipaddr)
            container_gateway=$(docker exec immortalwrt uci -q get network.lan.gateway)
            
            # 检查IP段和网关是否一致
            if [ -n "$container_lan_ip" ] && [ -n "$container_gateway" ]; then
                container_ip_prefix=$(echo "$container_lan_ip" | cut -d '.' -f 1-3)
                host_ip_prefix=$(echo "$subnet_prefix" | cut -d '.' -f 1-3)
                
                if [ "$container_ip_prefix" = "$host_ip_prefix" ] && [ "$container_gateway" = "$current_gateway" ]; then
                    info "容器IP段与宿主机IP段一致，保留现有网络配置。"
                    # 记录现有容器IP用于保存配置
                    container_ip="${container_lan_ip}/${network_cidr}"
                    
                    # 测试宿主机与容器通信
                    info "测试宿主机与容器通信..."
                    if ! ping -c 1 -w 2 "$container_lan_ip" &>/dev/null; then
                        warn "宿主机无法ping通容器，添加路由规则"
                        # 添加明确的路由规则以确保通信
                        if ! ip route | grep -q "${container_lan_ip}/32"; then
                            ip route add "${container_lan_ip}/32" dev macvlan-shim
                            info "已添加从宿主机到容器的路由规则"
                        fi
                    else
                        info "宿主机可以与容器通信"
                    fi
                    
                    return 0
                else
                    info "容器IP段与宿主机IP段不一致，将更新网络配置。"
                fi
            fi
        fi
        
        # 检查容器是否处于运行状态
        if [ -z "$(docker ps -q -f name=immortalwrt)" ]; then
            info "容器 'immortalwrt' 未运行，尝试启动..."
            if ! docker start immortalwrt; then
                error "启动容器 'immortalwrt' 失败。"
                return 1
            fi
            info "容器 'immortalwrt' 已启动。"
            # 等待容器完全启动
            wait_for_container_ready "immortalwrt"
        fi
    else
        info "Docker容器 'immortalwrt' 不存在，创建容器..."
        if ! docker run --name immortalwrt -d --restart=unless-stopped --network macnet --privileged immortalwrt-image:latest /sbin/init; then
            cleanup "创建Docker容器 'immortalwrt' 失败" "container"
            return 1
        fi
        info "Docker容器 'immortalwrt' 创建成功。"
        CONTAINER_NEWLY_CREATED=true
        
        # 等待容器完全启动
        if ! wait_for_container_ready "immortalwrt"; then
            warn "容器启动过程可能不完整，将继续尝试配置。"
        fi
    fi

    container_ip=$(generate_unused_ip "$subnet_prefix" "$current_gateway")
    if [ -z "$container_ip" ]; then
        cleanup "无法为容器分配有效IP地址" "container"
        return 1
    fi
    container_ip="${container_ip}/${network_cidr}"
    info "为容器分配IP: $container_ip"

    local subnet_mask
    case "$network_cidr" in
        8) subnet_mask="255.0.0.0" ;;
        16) subnet_mask="255.255.0.0" ;;
        24) subnet_mask="255.255.255.0" ;;
        *)
            local full=0xffffffff
            local mask=$((full << (32 - network_cidr) & full))
            subnet_mask=$(printf "%d.%d.%d.%d" $(($mask >> 24)) $(($mask >> 16 & 0xff)) $(($mask >> 8 & 0xff)) $(($mask & 0xff)))
            ;;
    esac

    info "配置容器网络设置..."
    if [ -z "$(docker exec immortalwrt uci -q get network.lan)" ]; then
        docker exec immortalwrt uci set network.lan=interface
    fi
    docker exec immortalwrt uci set network.lan.proto='static'
    docker exec immortalwrt uci del network.lan.device 2>/dev/null || true
    docker exec immortalwrt uci set network.lan.netmask="$subnet_mask"
    docker exec immortalwrt uci set network.lan.ip6assign='60'
    docker exec immortalwrt uci set network.lan.ipaddr="${container_ip%/*}"
    docker exec immortalwrt uci set network.lan.gateway="$current_gateway"
    docker exec immortalwrt uci set network.lan.dns='223.5.5.5 119.29.29.29'
    docker exec immortalwrt uci set network.lan.device='eth0'
    docker exec immortalwrt uci commit network

    if docker exec immortalwrt /etc/init.d/network restart; then
        info "容器网络服务重启成功。"
    else
        error "容器网络服务重启失败，请检查 /etc/config/network 配置。"
    fi

    info "容器网络配置已修改。"

    # 给网络服务重启一些时间
    sleep 5

    info "测试容器网络连接性..."
    if ! docker exec immortalwrt ping -c 1 "$current_gateway" &>/dev/null; then
        warn "容器无法ping通网关 $current_gateway"
    else
        info "容器可以ping通网关"
    fi
    if ! docker exec immortalwrt ping -c 1 163.com &>/dev/null; then
        warn "容器无法访问互联网 (ping 163.com 失败)"
    else
        info "容器可以访问互联网"
    fi
    
    # 测试宿主机与容器通信
    info "测试宿主机与容器通信..."
    if ! ping -c 1 -w 2 "${container_ip%/*}" &>/dev/null; then
        warn "宿主机无法ping通容器，添加路由规则"
        # 添加明确的路由规则以确保通信
        if ! ip route | grep -q "${container_ip%/*}/32"; then
            ip route add "${container_ip%/*}/32" dev macvlan-shim
            info "已添加从宿主机到容器的路由规则"
        fi
    else
        info "宿主机可以与容器通信"
    fi
    
    # 如果容器是新创建的，设置初始化配置
    if [ "$CONTAINER_NEWLY_CREATED" = "true" ]; then
        info "正在设置容器初始化配置..."
        
        # 确保网络连接可用
        info "检查容器网络连接..."
        local network_check_attempts=0
        while [ $network_check_attempts -lt 3 ]; do
            if docker exec immortalwrt ping -c 1 163.com &>/dev/null; then
                break
            fi
            info "等待网络连接 (尝试 $((network_check_attempts+1))/3)..."
            sleep 10
            network_check_attempts=$((network_check_attempts+1))
        done
        
        if [ $network_check_attempts -eq 3 ]; then
            warn "容器网络连接不可用，可能会影响软件包安装"
        fi
        
        # 运行软件包更新和安装
        info "正在更新软件包列表..."
        docker exec immortalwrt opkg update
        
        info "正在安装必要软件包..."
        # 分开安装以防某些包失败不影响其他包
        docker exec immortalwrt sh -c "opkg install luci-i18n-ttyd-zh-cn || true"
        docker exec immortalwrt sh -c "opkg install luci-i18n-filebrowser-go-zh-cn || true"
        docker exec immortalwrt sh -c "opkg install luci-i18n-argon-config-zh-cn || true"
        docker exec immortalwrt sh -c "opkg install openssh-sftp-server || true"
        docker exec immortalwrt sh -c "opkg install luci-i18n-samba4-zh-cn || true"
        
        # 安装iStore商店
        info "正在安装iStore商店..."
        docker exec immortalwrt sh -c "
            wget -qO imm.sh https://cafe.cpolar.top/wkdaily/zero3/raw/branch/main/zero3/imm.sh && 
            chmod +x imm.sh && 
            ./imm.sh || true
        "
        # 等待iStore安装完成
           sleep 5
           
        # 等待安装nikki插件
        
         docker exec immortalwrt sh -c "
            wget -qO install.sh https://github.com/nikkinikki-org/OpenWrt-nikki/raw/refs/heads/main/install.sh && 
            chmod +x install.sh && 
            ./install.sh || true
        "
        
        # 等待nikki安装完成
        sleep 5
        
        # 安装网络向导和首页
        info "正在安装网络向导和首页..."
        docker exec immortalwrt sh -c "
            command -v is-opkg &>/dev/null && is-opkg install luci-i18n-quickstart-zh-cn || true
        "
        
        info "容器初始化配置完成"
    fi
    
    return 0
}

# 下载和构建ImmortalWrt镜像
build_immortalwrt_image() {
    local image_version="24.10.0"
    info "检查是否已存在 immortalwrt-image 镜像..."
    if docker image inspect immortalwrt-image &>/dev/null; then
        info "Docker镜像 'immortalwrt-image' 已存在，跳过下载和构建。"
        return 0
    fi
    info "Docker镜像 'immortalwrt-image' 不存在，开始下载和构建..."
    mkdir -p /tmp/immortalwrt-build
    cd /tmp/immortalwrt-build
    info "下载 ImmortalWrt rootfs 文件..."
    if ! wget -O rootfs.tar.gz "https://downloads.immortalwrt.org/releases/${image_version}/targets/armsr/armv8/immortalwrt-${image_version}-armsr-armv8-rootfs.tar.gz"; then
        cleanup "下载 rootfs.tar.gz 失败" "none"
        return 1
    fi
    info "解压 rootfs.tar.gz..."
    if ! gzip -d rootfs.tar.gz; then
        cleanup "解压 rootfs.tar.gz 失败" "none"
        return 1
    fi
    info "创建 Dockerfile..."
    cat >Dockerfile <<EOF
FROM scratch
ADD rootfs.tar /
EOF
    info "构建 Docker 镜像..."
    if ! docker build -t immortalwrt-image .; then
        cleanup "构建 Docker 镜像 'immortalwrt-image' 失败" "none"
        return 1
    fi
    info "Docker 镜像 'immortalwrt-image' 构建成功。"
    cd - > /dev/null
    rm -rf /tmp/immortalwrt-build
    return 0
}

# 备份ImmortalWrt配置
backup_immortalwrt() {
    local backup_dir="/root/immortalwrt/backups"
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="${backup_dir}/immortalwrt_backup_${timestamp}.tar.gz"
    info "创建ImmortalWrt配置备份..."
    mkdir -p "$backup_dir"
    if ! docker ps -q -f name=immortalwrt &>/dev/null; then
        warn "ImmortalWrt容器未运行，无法创建备份"
        return 1
    fi
    info "正在备份到 $backup_file"
    docker exec immortalwrt sysupgrade -b /tmp/backup.tar.gz
    docker cp immortalwrt:/tmp/backup.tar.gz "$backup_file"
    docker exec immortalwrt rm /tmp/backup.tar.gz
    if [ -f "$backup_file" ]; then
        info "备份已创建: $backup_file"
        return 0
    else
        error "创建备份失败"
        return 1
    fi
}

# 恢复ImmortalWrt配置
restore_immortalwrt() {
    local backup_dir="/root/immortalwrt/backups"
    if [ ! -d "$backup_dir" ]; then
        error "备份目录不存在"
        return 1
    fi
    local backups
    backups=($(ls -1 "${backup_dir}"/*.tar.gz 2>/dev/null))
    if [ ${#backups[@]} -eq 0 ]; then
        error "没有找到可用备份"
        return 1
    fi
    info "可用备份:"
    for i in "${!backups[@]}"; do
        info "  [$i] $(basename "${backups[$i]}")"
    done
    read -p "输入备份编号或按Ctrl+C取消: " backup_num
    if ! [[ "$backup_num" =~ ^[0-9]+$ ]] || [ "$backup_num" -ge ${#backups[@]} ]; then
        error "无效的备份编号"
        return 1
    fi
    local selected_backup="${backups[$backup_num]}"
    info "正在恢复备份: $(basename "$selected_backup")"
    docker cp "$selected_backup" immortalwrt:/tmp/backup.tar.gz
    docker exec immortalwrt sysupgrade -r /tmp/backup.tar.gz
    docker exec immortalwrt rm /tmp/backup.tar.gz
    docker exec immortalwrt /etc/init.d/network restart
    info "配置已恢复，请检查容器网络设置"
    return 0
}

# 检查容器健康状态
check_container_health() {
    info "检查ImmortalWrt容器健康状态..."
    if ! docker ps -q -f name=immortalwrt &>/dev/null; then
        warn "ImmortalWrt容器未运行"
        return 1
    fi
    info "检查关键进程..."
    local key_processes=("rpcd" "uhttpd" "dnsmasq" "netifd")
    local failed_processes=()
    for proc in "${key_processes[@]}"; do
        if ! docker exec immortalwrt pgrep "$proc" &>/dev/null; then
            failed_processes+=("$proc")
        fi
    done
    if [ ${#failed_processes[@]} -gt 0 ]; then
        warn "以下进程未运行: ${failed_processes[*]}"
    else
        info "所有关键进程运行正常"
    fi
    info "检查网络连接..."
    if ! docker exec immortalwrt ping -c 1 163.com &>/dev/null; then
        warn "网络连接测试失败 (ping 163.com)"
        return 1
    fi
    info "容器网络连接正常"
    return 0
}

# 显示使用方法
show_usage() {
    cat <<EOF
使用方法: $0 [选项]

选项:
  --help                显示此帮助信息
  --backup              创建ImmortalWrt配置备份
  --restore             从备份恢复ImmortalWrt配置
  --status              检查容器状态
  --restart             重启ImmortalWrt容器
  --network-reset       重置网络配置

如果不指定选项，脚本将执行完整的部署过程。
EOF
}

# 主函数
main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    info "=========================================="
    info "开始执行ImmortalWrt容器部署脚本..."
    info "日志文件: $LOG_FILE"

    case "$1" in
        --help)
            show_usage
            exit 0
            ;;
        --backup)
            backup_immortalwrt
            exit $?
            ;;
        --restore)
            restore_immortalwrt
            exit $?
            ;;
        --status)
            check_container_health
            exit $?
            ;;
        --restart)
            info "重启ImmortalWrt容器..."
            docker restart immortalwrt
            exit $?
            ;;
        --network-reset)
            info "重置网络配置..."
            ip link show macvlan-shim &>/dev/null && ip link delete macvlan-shim
            docker network inspect macnet &>/dev/null && docker network rm macnet
            get_network_config && create_macvlan_network && create_macvlan_shim
            exit $?
            ;;
    esac

    info "检查网络连接..."
    if ! ping -c 1 163.com &>/dev/null; then
        error "未检测到网络连接，退出脚本。"
        exit 1
    fi
    info "网络连接正常。"

    check_dependencies || exit 1

    mkdir -p /root/immortalwrt
    cd /root/immortalwrt
    info "已创建并进入目录 /root/immortalwrt"

    get_network_config || exit 1

    load_config

    build_immortalwrt_image || exit 1

    create_macvlan_network || exit 1

    create_macvlan_shim || exit 1

    setup_immortalwrt_container || exit 1

    save_config

    info "Docker网络列表:"
    docker network ls

    info "Docker容器列表:"
    docker ps -a

    info "=========================================="
    info "ImmortalWrt容器部署脚本执行完成"
    info "容器IP地址: ${container_ip%/*}"
    info "容器网关: $current_gateway"
    info "可以通过浏览器访问 http://${container_ip%/*} 进入ImmortalWrt管理界面"
    info "脚本日志保存在: $LOG_FILE"
    info "配置文件保存在: $CONFIG_FILE"
    info "=========================================="
}
main "$@"
