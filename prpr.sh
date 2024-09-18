#!/bin/bash
host="https://prprcheng.com"
key="X9A4rjaAf2rQ5Zgd6WeTB36xcVmJqrx67ZZ2G9ZNT2JKbxZL5k"

green() {
    echo -e "\033[32m\033[01m$1\033[0m"
}

red() {
    echo -e "\033[31m\033[01m$1\033[0m"
}

yellow() {
    echo -e "\033[33m\033[01m$1\033[0m"
}

if [[ $EUID -ne 0 ]]; then
    red "请使用 root 用户运行本脚本"
    exit 1
fi

if [[ -f /etc/redhat-release ]]; then
    release="Centos"
elif cat /etc/issue | grep -q -E -i "debian"; then
    release="Debian"
elif cat /etc/issue | grep -q -E -i "ubuntu"; then
    release="Ubuntu"
elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
    release="Centos"
elif cat /etc/issue | grep -q -E -i "Alpine"; then
    release="Alpine"
else
    red "不支持当前系统 不会自动安装组件"
fi

install_dependency() {
    local package=$1
    if [ "$release" = "Centos" ]; then
        yum -y update && yum install "$package" -y
    elif [ "$release" = "Alpine" ]; then
        apk add "$package"
    else
        apt-get update -y && apt-get install "$package" -y
    fi
}

check_and_install() {
    local command=$1
    local package=$2
    if ! type "$command" >/dev/null 2>&1; then
        yellow "检测到 $package 未安装，安装中"
        install_dependency "$package"
    else
        green "$package 已安装"
    fi
}

check_and_install curl curl
check_and_install wget wget
check_and_install sudo sudo
check_and_install unzip unzip

if [ "$release" = "Alpine" ]; then
    check_and_install nohup nohup
fi

# 询问用户输入NodeID
yellow "在使用本脚本之前请在面板中添加好节点！"
read -p "请输入XrayR的NodeID: " node_id

install_xrayr() {
bash <(curl -Ls https://raw.githubusercontent.com/XrayR-project/XrayR-release/master/install.sh) 0.9.0
}

config_xrayr_normal() {
cat <<EOF > /etc/XrayR/config.yml
Log:
  Level: warning # Log level: none, error, warning, info, debug 
  AccessPath: # /etc/XrayR/access.Log
  ErrorPath: # /etc/XrayR/error.log
DnsConfigPath: # /etc/XrayR/dns.json # Path to dns config, check https://xtls.github.io/config/dns.html for help
RouteConfigPath: # /etc/XrayR/route.json # Path to route config, check https://xtls.github.io/config/routing.html for help
InboundConfigPath: # /etc/XrayR/custom_inbound.json # Path to custom inbound config, check https://xtls.github.io/config/inbound.html for help
OutboundConfigPath: # /etc/XrayR/custom_outbound.json # Path to custom outbound config, check https://xtls.github.io/config/outbound.html for help
ConnectionConfig:
  Handshake: 4 # Handshake time limit, Second
  ConnIdle: 30 # Connection idle time limit, Second
  UplinkOnly: 2 # Time limit when the connection downstream is closed, Second
  DownlinkOnly: 4 # Time limit when the connection is closed after the uplink is closed, Second
  BufferSize: 64 # The internal cache size of each connection, kB
Nodes:
  -
    PanelType: "V2board" # Panel type: SSpanel, V2board, NewV2board, PMpanel, Proxypanel, V2RaySocks
    ApiConfig:
      ApiHost: "$host"
      ApiKey: "$key"
      NodeID: $node_id
      NodeType: Shadowsocks # Node type: V2ray, Shadowsocks, Trojan, Shadowsocks-Plugin
      Timeout: 30 # Timeout for the api request
      EnableVless: false # Enable Vless for V2ray Type
      EnableXTLS: false # Enable XTLS for V2ray and Trojan
      SpeedLimit: 0 # Mbps, Local settings will replace remote settings, 0 means disable
      DeviceLimit: 0 # Local settings will replace remote settings, 0 means disable
      RuleListPath: # /etc/XrayR/rulelist Path to local rulelist file
    ControllerConfig:
      ListenIP: 0.0.0.0 # IP address you want to listen
      SendIP: 0.0.0.0 # IP address you want to send pacakage
      UpdatePeriodic: 60 # Time to update the nodeinfo, how many sec.
      EnableDNS: false # Use custom DNS config, Please ensure that you set the dns.json well
      DNSType: AsIs # AsIs, UseIP, UseIPv4, UseIPv6, DNS strategy
      EnableProxyProtocol: false # Only works for WebSocket and TCP
      AutoSpeedLimitConfig:
        Limit: 0 # Warned speed. Set to 0 to disable AutoSpeedLimit (mbps)
        WarnTimes: 0 # After (WarnTimes) consecutive warnings, the user will be limited. Set to 0 to punish overspeed user immediately.
        LimitSpeed: 0 # The speedlimit of a limited user (unit: mbps)
        LimitDuration: 0 # How many minutes will the limiting last (unit: minute)
      GlobalDeviceLimitConfig:
        Enable: false # Enable the global device limit of a user
        RedisAddr: 127.0.0.1:6379 # The redis server address
        RedisPassword: YOUR PASSWORD # Redis password
        RedisDB: 0 # Redis DB
        Timeout: 5 # Timeout for redis request
        Expiry: 60 # Expiry time (second)
      EnableFallback: false # Only support for Trojan and Vless
      FallBackConfigs:  # Support multiple fallbacks
        -
          SNI: # TLS SNI(Server Name Indication), Empty for any
          Alpn: # Alpn, Empty for any
          Path: # HTTP PATH, Empty for any
          Dest: 80 # Required, Destination of fallback, check https://xtls.github.io/config/features/fallback.html for details.
          ProxyProtocolVer: 0 # Send PROXY protocol version, 0 for dsable
      CertConfig:
        CertMode: dns # Option about how to get certificate: none, file, http, tls, dns. Choose "none" will forcedly disable the tls config.
        CertDomain: "node1.test.com" # Domain to cert
        CertFile: /etc/XrayR/cert/node1.test.com.cert # Provided if the CertMode is file
        KeyFile: /etc/XrayR/cert/node1.test.com.key
        Provider: alidns # DNS cert provider, Get the full support list here: https://go-acme.github.io/lego/dns/
        Email: test@me.com
        DNSEnv: # DNS ENV option used by DNS provider
          ALICLOUD_ACCESS_KEY: aaa
          ALICLOUD_SECRET_KEY: bbb
EOF
}

# 判断是否输入了NodeID
if [ -n "$node_id" ]; then
    install_xrayr
    config_xrayr_normal
    if [ "$release" = "Alpine" ]; then
        /etc/init.d/XrayR restart
    else
        XrayR restart
    fi
    green "XrayR配置已完成并重启。"
else
    red "未输入NodeID，XrayR配置未进行任何更改。"
fi

# TCP优化
cat <<EOF > /etc/sysctl.conf
net.core.rps_sock_flow_entries=32768 #rfs 设置此文件至同时活跃连接数的最大预期值
#net.ipv4.icmp_echo_ignore_all=1 #禁止ping
#net.ipv4.icmp_echo_ignore_broadcasts=1
fs.file-max=1000000 # 系统级别的能够打开的文件句柄的数量
fs.inotify.max_user_instances=65536
#开启路由转发
net.ipv4.conf.all.route_localnet=1
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.rp_filter=0
#ARP回应的级别
#net.ipv4.conf.all.arp_ignore=2
#net.ipv4.conf.default.arp_ignore=2
#net.ipv4.conf.all.arp_announce=2
#net.ipv4.conf.default.arp_announce=2
net.ipv4.neigh.default.gc_stale_time=60 #ARP缓存的存活时间
net.ipv4.tcp_syncookies=1 #开启SYN Cookies。当出现SYN等待队列溢出时，启用cookies来处理
net.ipv4.tcp_retries1=3
net.ipv4.tcp_retries2=8
net.ipv4.tcp_syn_retries=2 #SYN重试次数
net.ipv4.tcp_synack_retries=2 #SYNACK重试次数
net.ipv4.tcp_tw_reuse=1 #开启TIME-WAIT sockets重用
net.ipv4.tcp_fin_timeout=15 #保持在FIN-WAIT-2状态的时间
net.ipv4.tcp_max_tw_buckets=32768 #系统同时保持TIME_WAIT socket的数量
#net.core.busy_poll=50
#net.core.busy_read=50
net.core.dev_weight=4096
net.core.netdev_budget=65536
net.core.netdev_budget_usecs=4096
net.ipv4.tcp_max_syn_backlog=262144 #对于还未获得对方确认的连接请求，可保存在队列中的最大数目
net.core.netdev_max_backlog=32768 #网口接收数据包比内核处理速率快状态队列的数量
net.core.somaxconn=32768 #每个端口最大的监听队列的数量
net.ipv4.tcp_notsent_lowat=16384
net.ipv4_timestamps=0 #TCP时间戳的支持
net.ipv4.tcp_keepalive_time=600 #TCP发送keepalive探测消息的间隔时间（秒）
net.ipv4.tcp_keepalive_probes=5 #TCP发送keepalive探测确定连接已经断开的次数
net.ipv4.tcp_keepalive_intvl=15 #探测消息未获得响应时，重发该消息的间隔时间
vm.swappiness=1
net.ipv4.route.gc_timeout=100
net.ipv4.neigh.default.gc_thresh1=1024 #最小保存条数。当邻居表中的条数小于该数值，则 GC 不会做任何清理
net.ipv4.neigh.default.gc_thresh2=4096 #高于该阈值时，GC 会变得更激进，此时存在时间大于 5s 的条目会被清理
net.ipv4.neigh.default.gc_thresh3=8192 #允许的最大临时条目数。当使用的网卡数很多，或直连了很多其它机器时考虑增大该参数。
net.ipv6.neigh.default.gc_thresh1=1024
net.ipv6.neigh.default.gc_thresh2=4096
net.ipv6.neigh.default.gc_thresh3=8192
net.netfilter.nf_conntrack_max=262144
net.nf_conntrack_max=262144
net.netfilter.nf_conntrack_tcp_timeout_established=36000 #ESTABLISHED状态连接的超时时间
# TCP窗口
net.ipv4.tcp_fastopen=3 # 开启TCP快速打开
net.ipv4.tcp_autocorking=0
net.ipv4.tcp_slow_start_after_idle=0 #关闭TCP的连接传输的慢启动
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_moderate_rcvbuf=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 16384 33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.tcp_mem=262144 1048576 4194304
net.ipv4.udp_mem=262144 524288 1048576
# BBR
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq
#swap优化
vm.swappiness=10
vm.vfs_cache_pressure=50
EOF
sudo sysctl -p
green "TCP已经优化"