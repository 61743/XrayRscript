#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
nginx_conf_dir="/etc/nginx/conf/conf.d"
nginx_conf="${nginx_conf_dir}/zhengshu.conf"
nginx_dir="/etc/nginx"
web_dir="/home/wwwroot"
nginx_openssl_src="/usr/local/src"
nginx_systemd_file="/etc/systemd/system/nginx.service"
amce_sh_file="/root/.acme.sh/acme.sh"
ssl_update_file="/usr/bin/ssl_update.sh"
nginx_version="1.20.1"
openssl_version="1.1.1s"
jemalloc_version="5.3.0"
old_config_status="off"
THREAD=$(grep 'processor' /proc/cpuinfo | sort -u | wc -l)
source '/etc/os-release'
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

is_root() {
    if [ 0 == $UID ]; then
        echo -e "当前用户是root用户，进入安装流程"
        sleep 1
    else
        echo -e "当前用户不是root用户，请切换到root用户后重新执行脚本"
        exit 1
    fi
}
basic_information(){
read -rp "你的面板类型(SSpanel或者V2board): " planetype
read -rp "你的对接域名(以https://或者htt/://开头): " apidomin
read -rp "你的对接密钥: " apikey
read -rp "你的节点域名(例如 sg1.114514.com): " nodedomain
read -rp "你的节点ID: " nodeid
read -rp "当前节点的path(例如 /aaaa/ ): " path
read -rp "用户连接端口(例如443): " outsideport
read -rp "服务段监听端口(例如10086): " insideport
}

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "当前系统为 Centos ${VERSION_ID} ${VERSION}"
        INS="yum"
	    systemctl stop firewalld
        systemctl disable firewalld
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "当前系统为 Debian ${VERSION_ID} ${VERSION}"
        INS="apt"
        $INS update
	    $INS install vim cpufrequtils net-tools -y
	    sed -i 's/ondemand/performance/g' /etc/init.d/cpufrequtils
	    systemctl daemon-reload
	    systemctl stop ufw
        systemctl disable ufw
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
        INS="apt-get"
        rm /var/lib/dpkg/lock
        dpkg --configure -a
        rm /var/lib/apt/lists/lock
        rm /var/cache/apt/archives/lock
        $INS update
	    systemctl stop ufw
        systemctl disable ufw
    else
        echo -e "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断"
        exit 1
    fi
        $INS install dbus -y
}

chrony_install() {
    ${INS} -y install chrony
    timedatectl set-ntp true
    if [[ "${ID}" == "centos" ]]; then
        systemctl enable chronyd && systemctl restart chronyd
    else
        systemctl enable chrony && systemctl restart chrony
    fi
    timedatectl set-timezone Asia/Shanghai
    chronyc sourcestats -v
    chronyc tracking -v
    date
}
dependency_install() {
    ${INS} install wget git lsof -y
    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install crontabs
    else
        ${INS} -y install cron
    fi

    if [[ "${ID}" == "centos" ]]; then
        touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl start crond && systemctl enable crond
    else
        touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl enable cron
    fi
    ${INS} -y install bc unzip curl
    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y groupinstall "Development tools"
    else
        ${INS} -y install build-essential
    fi
    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install pcre pcre-devel zlib-devel epel-release
    else
        ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev dbus
    fi
    ${INS} -y install haveged
    if [[ "${ID}" == "centos" ]]; then
        systemctl start haveged && systemctl enable haveged
    else
        systemctl start haveged && systemctl enable haveged
    fi
}
basic_optimization() {
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf
    # 关闭 Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"80" | grep -i -c "listen") ]]; then
        echo -e " 80 端口未被占用 "
        sleep 1
    else
        echo -e "检测到 80 端口被占用，以下为 80 端口占用信息 "
        lsof -i:"80"
        echo -e " 5s 后将尝试自动 kill 占用进程 "
        sleep 5
        lsof -i:"80" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "kill 完成 "
        sleep 1
    fi
	
	if [[ 0 -eq $(lsof -i:"${outsideport}" | grep -i -c "listen") ]]; then
        echo -e " ${outsideport} 端口未被占用 "
        sleep 1
    else
        echo -e "检测到 ${outsideport} 端口被占用，以下为 ${outsideport} 端口占用信息 "
        lsof -i:"${outsideport}"
        echo -e " 5s 后将尝试自动 kill 占用进程 "
        sleep 5
        lsof -i:"${outsideport}" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "kill 完成 "
        sleep 1
    fi
}

nginx_exist_check() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; then
        echo -e "Nginx已存在，跳过编译安装过程"
        sleep 2
    elif [[ -d "/usr/local/nginx/" ]]; then
        echo -e "检测到其他套件安装的Nginx，继续安装会造成冲突，请处理后安装"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
    cd ${nginx_openssl_src} || exit
    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz
    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz
    [[ -d jemalloc-"${jemalloc_version}" ]] && rm -rf jemalloc-"${jemalloc_version}"
    tar -xvf jemalloc-"${jemalloc_version}".tar.bz2
    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}
    echo -e "即将开始编译安装 jemalloc"
    sleep 1
    cd jemalloc-${jemalloc_version} || exit
    ./configure
    make -j "${THREAD}" && make install
    echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
    ldconfig
    echo -e "即将开始编译安装 Nginx, 过程稍久，请耐心等待"
    sleep 1
    cd ../nginx-${nginx_version} || exit
    ./configure --prefix="${nginx_dir}" \
        --with-stream \
        --with-stream_ssl_preread_module \
        --with-http_ssl_module \
        --with-http_sub_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --with-pcre \
        --with-http_realip_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_secure_link_module \
        --with-http_v2_module \
        --with-cc-opt='-O3' \
        --with-ld-opt="-ljemalloc" \
        --with-openssl=../openssl-"$openssl_version"
    make -j "${THREAD}" && make install
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  4;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
#    sed -i 's/        listen       80;/        listen       4480;/' ${nginx_dir}/conf/nginx.conf
    sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf
    sed -i "8ierror_log /dev/null;" ${nginx_dir}/conf/nginx.conf
    sed -i "27i\    access_log off;" ${nginx_dir}/conf/nginx.conf
    rm -rf ../nginx-"${nginx_version}"
    rm -rf ../openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz
    mkdir ${nginx_dir}/conf/conf.d
}

nginx_conf_add() {
    touch ${nginx_conf_dir}/zhengshu.conf
    cat >${nginx_conf_dir}/zhengshu.conf <<EOF
    server {
        listen ${outsideport} ssl http2;
        listen [::]:${outsideport} ssl http2;
        ssl_certificate       /data/zhengshu.crt;
        ssl_certificate_key   /data/zhengshu.key;
        ssl_protocols         TLSv1.3;
        ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        server_name           ${nodedomain};
        index index.html index.htm;
        root  /home/wwwroot/3DCEList;
        error_page 400 = /400.html;
        # Config for 0-RTT in TLSv1.3
        ssl_early_data on;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security "max-age=31536000";
        location ${path}
        {
        proxy_redirect off;
        proxy_read_timeout 1200s;
        proxy_pass http://127.0.0.1:${insideport};
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header Early-Data \$ssl_early_data;
        }
}
    server {
        listen 80;
        listen [::]:80;
        server_name ${nodedomain};
        return 301 https://${nodedomain}\$request_uri;
    }
	
EOF

}

web_camouflage() {
    ##请注意 这里和LNMP脚本的默认路径冲突，千万不要在安装了LNMP的环境下使用本脚本，否则后果自负
    rm -rf /home/wwwroot
    mkdir -p /home/wwwroot
    cd /home/wwwroot || exit
    git clone https://github.com/wulabing/3DCEList.git
    echo -e "web 站点伪装"
}

ssl_install() {
    if [[ "${ID}" == "centos" ]]; then
        ${INS} install socat nc -y
    else
        ${INS} install socat netcat -y
    fi
    curl https://get.acme.sh | sh
}

acme() {
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    if "$HOME"/.acme.sh/acme.sh --issue -d "${nodedomain}" --standalone -k ec-256 --force --test; then
        echo -e "SSL 证书测试签发成功，开始正式签发"
        rm -rf "$HOME/.acme.sh/${nodedomain}_ecc"
        sleep 1
    else
        echo -e "SSL 证书测试签发失败"
        rm -rf "$HOME/.acme.sh/${nodedomain}_ecc"
        exit 1
    fi
    if "$HOME"/.acme.sh/acme.sh --issue -d "${nodedomain}" --standalone -k ec-256 --force; then
        echo -e "SSL 证书生成成功"
        sleep 1
        mkdir /data
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${nodedomain}" --fullchainpath /data/zhengshu.crt --keypath /data/zhengshu.key --ecc --force; then
            echo -e "证书配置成功"
            sleep 1
        fi
    else
        echo -e "SSL 证书生成失败"
        rm -rf "$HOME/.acme.sh/${nodedomain}_ecc"
        exit 1
    fi
}

#自动更新证书脚本和定时任务
acme_cron_update() {
    cat >${ssl_update_file} <<EOF
#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sslupdate(){
systemctl stop nginx &> /dev/null
sleep 1
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /dev/null
"/root/.acme.sh"/acme.sh --installcert -d ${nodedomain} --fullchainpath /data/zhengshu.crt --keypath /data/zhengshu.key --ecc
sleep 1
systemctl start nginx &> /dev/null
}
sslupdate

EOF
#定时任务
chmod +x ${ssl_update_file}

    if [[ $(crontab -l | grep -c "ssl_update.sh") -lt 1 ]]; then
      if [[ "${ID}" == "centos" ]]; then
          sed -i "/acme.sh/c 0 4 * * 0 bash ${ssl_update_file}" /var/spool/cron/root
      else
          sed -i "/acme.sh/c 0 4 * * 0 bash ${ssl_update_file}" /var/spool/cron/crontabs/root
      fi
    fi
}

nginx_systemd() {
    cat >$nginx_systemd_file <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target

EOF
    systemctl daemon-reload
}

back_end(){
wget -N https://raw.githubusercontent.com/BobCoderS9/XrayR-release/master/install.sh && bash install.sh
rm -rf /etc/XrayR/config.yml
    cat >/etc/XrayR/config.yml <<EOF
Log:
  Level: none # Log level: none, error, warning, info, debug 
  AccessPath: # /etc/XrayR/access.Log
  ErrorPath: # /etc/XrayR/error.log
DnsConfigPath: # /etc/XrayR/dns.json # Path to dns config, check https://xtls.github.io/config/base/dns/ for help
RouteConfigPath: # /etc/XrayR/route.json # Path to route config, check https://xtls.github.io/config/base/route/ for help
OutboundConfigPath: # /etc/XrayR/custom_outbound.json # Path to custom outbound config, check https://xtls.github.io/config/base/outbound/ for help
ConnetionConfig:
  Handshake: 4 # Handshake time limit, Second
  ConnIdle: 30 # Connection idle time limit, Second
  UplinkOnly: 2 # Time limit when the connection downstream is closed, Second
  DownlinkOnly: 4 # Time limit when the connection is closed after the uplink is closed, Second
  BufferSize: 64 # The internal cache size of each connection, kB 
Nodes:
  -
    PanelType: "${planetype}" # Panel type: SSpanel, V2board, PMpanel, , Proxypanel
    ApiConfig:
      ApiHost: "${apidomin}"
      ApiKey: "${apikey}"
      NodeID: ${nodeid}
      NodeType: V2ray # Node type: V2ray, Shadowsocks, Trojan, Shadowsocks-Plugin
      Timeout: 30 # Timeout for the api request
      EnableVless: false # Enable Vless for V2ray Type
      EnableXTLS: false # Enable XTLS for V2ray and Trojan
      SpeedLimit: 0 # Mbps, Local settings will replace remote settings, 0 means disable
      DeviceLimit: 0 # Local settings will replace remote settings, 0 means disable
      RuleListPath: # ./rulelist Path to local rulelist file
    ControllerConfig:
      ListenIP: 127.0.0.1 # IP address you want to listen
      SendIP: 0.0.0.0 # IP address you want to send pacakage
      UpdatePeriodic: 60 # Time to update the nodeinfo, how many sec.
      EnableDNS: false # Use custom DNS config, Please ensure that you set the dns.json well
      DisableSniffing: true 
      DNSType: AsIs # AsIs, UseIP, UseIPv4, UseIPv6, DNS strategy
      EnableProxyProtocol: false # Only works for WebSocket and TCP
      EnableFallback: false # Only support for Trojan and Vless
      FallBackConfigs:  # Support multiple fallbacks
        -
          SNI: # TLS SNI(Server Name Indication), Empty for any
          Path: # HTTP PATH, Empty for any
          Dest: 80 # Required, Destination of fallback, check https://xtls.github.io/config/fallback/ for details.
          ProxyProtocolVer: 0 # Send PROXY protocol version, 0 for dsable
      CertConfig:
        CertMode: none # Option about how to get certificate: none, file, http, dns. Choose "none" will forcedly disable the tls config.
        CertDomain: "node1.test.com" # Domain to cert
        CertFile: ./cert/node1.test.com.cert # Provided if the CertMode is file
        KeyFile: ./cert/node1.test.com.key
        Provider: alidns # DNS cert provider, Get the full support list here: https://go-acme.github.io/lego/dns/
        Email: test@me.com
        DNSEnv: # DNS ENV option used by DNS provider
          ALICLOUD_ACCESS_KEY: aaa
          ALICLOUD_SECRET_KEY: bbb

EOF

    systemctl restart XrayR
	systemctl restart nginx
}

xrayr(){
    is_root
	basic_information
	check_system
	chrony_install
	dependency_install
	basic_optimization
	port_exist_check
	nginx_exist_check
	nginx_conf_add
	web_camouflage
	ssl_install
	acme
	acme_cron_update
	nginx_systemd
	back_end
}

xrayr
