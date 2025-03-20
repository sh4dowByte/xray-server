#!/bin/bash

# Warna untuk output
red='\e[1;31m'
green='\e[0;32m'
cyan='\e[0;36m'
white='\e[037;1m'
grey='\e[1;36m'
NC='\e[0m'

# Tanggal saat ini
MYIP=$(curl -s ifconfig.me)

# Fungsi untuk memeriksa akses root
checkRoot() {
    if [ "$(whoami)" != "root" ]; then
        echo -e "${red}Please run as root user!${NC}"
        exit 1
    fi
}

# Fungsi header untuk Hysteria
script_header() {
    clear
    echo -e "${white}****************************************************"
    echo -e "  Installation & Configuration of ${cyan}Hysteria Protocol"
    echo -e "              (Version 1.3.5)"
    echo -e "****************************************************${NC}"
    echo ""
}

# Mengatur DNS
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 1.0.0.1" >> /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 8.4.8.4" >> /etc/resolv.conf

# Update dan instalasi paket dasar
apt update -y && apt upgrade -y
apt install -y binutils socat ruby wget curl htop speedtest-cli cron figlet zip unzip certbot
gem install lolcat

# Membuat direktori
mkdir -p /funny /rere /etc/slowdns /etc/xray /etc/websocket /etc/funny /etc/funny/limit /etc/funny/limit/xray/ip /etc/funny/limit/xray/quota /etc/funny/limit/ssh/ip /etc/v2ray /var/lib/crot /var/log/xray /etc/noobzvpns
chmod -R +x /var/lib/crot /var/log/xray
touch /var/log/xray/{access.log,error.log,error1.log,akses.log,access{1..6}.log}
touch /etc/funny/.{l2tp,sstp,pptp,ptp,wireguard,socks5}
touch /etc/funny/limit/ssh/ip/{syslog,rere}
echo "9999999" > /etc/funny/limit/ssh/ip/syslog
echo "9999999" > /etc/funny/limit/ssh/ip/rere

# Meminta input domain
read -p "Input Your Domain: " domain
echo "${domain}" > /etc/xray/domain

# Mengatur cron
echo "0 0,6,12,18 * * * root backup" >> /etc/crontab
echo "0,15,30,45 * * * * root /usr/bin/xp" >> /etc/crontab
echo "*/5 * * * * root limit" >> /etc/crontab
systemctl daemon-reload
systemctl restart cron

# Instalasi Dropbear
apt install -y dropbear
rm /etc/default/dropbear /etc/issue.net
cat > /etc/issue.net << END
<p style="text-align:center">
<font color="#00FF00"><b> WELCOME TO XRAY SERVER </b></font><br>
<font color='#FF0059'>▬</font><font color='#F1006F'>▬</font><font color='#E30085'>▬</font><font color='#D6009B'>▬</font><font color='#C800B1'>▬</font><font color='#BB00C7'>ஜ</font><font color='#AD00DD'>۩</font><font color='#9F00F3'>۞</font><font color='#9F00F3'>۩</font><font color='#AD00DD'>ஜ</font><font color='#BB00C7'>▬</font><font color='#C800B1'>▬</font><font color='#D6009B'>▬</font><font color='#E30085'>▬</font><font color='#F1006F'>▬</font><br>
<font color="#F5FE00"><b> THANKS YOU FOR USING OUR SERVICE </b></font><br>
<font color="#FFA500"><b> PLEASE FOLLOW THE SERVER RULES </b></font><br>
<font color='red'>!!! TERM OF SERVICE !!!</font><br>
<font color='#20CDCC'><b>         NO SPAM           </b></font><br>
<font color="#FF00FF"><b> NO CRIMINAL CYBER </b></font><br>
<font color="#FF1493"><b> NO TORRENT FILE </b></font><br>
<font color='#6495ED'><b>         NO DDOS           </b></font><br>
<font color='#BC8F8F'><b>  NO HACKING AND CARDING   </b></font><br>
<font color="#E51369"><b>    MAX LOGIN 1 DEVICE     </b></font><br>
<font color='red'><b> IF YOU VIOLATE YOUR ACCOUNT WE WILL BE BANNED </b></font><br>
<font color='#FF0059'>▬</font><font color='#F1006F'>▬</font><font color='#E30085'>▬</font><font color='#D6009B'>▬</font><font color='#C800B1'>▬</font><font color='#BB00C7'>ஜ</font><font color='#AD00DD'>۩</font><font color='#9F00F3'>۞</font><font color='#9F00F3'>۩</font><font color='#AD00DD'>ஜ</font><font color='#BB00C7'>▬</font><font color='#C800B1'>▬</font><font color='#D6009B'>▬</font><font color='#E30085'>▬</font><font color='#F1006F'>▬</font>
END

if grep -Ei 'ubuntu.*(24|23)' /etc/os-release || grep -Ei 'debian.*12' /etc/os-release; then
    cat > /etc/default/dropbear << END
DROPBEAR_PORT=111
DROPBEAR_RECEIVE_WINDOW=65536
DROPBEAR_EXTRA_ARGS="-b /etc/issue.net -p 109 -p 69"
DROPBEAR_BANNER="/etc/issue.net"
END
else
    cat > /etc/default/dropbear << END
NO_START=0
DROPBEAR_PORT=111
DROPBEAR_EXTRA_ARGS="-p 109 -p 69"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
END
fi

echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
kill $(ps aux | grep dropbear | awk '{print $2}')
systemctl daemon-reload
/etc/init.d/dropbear restart

# Menghapus Apache2
apt autoclean -y
apt -y remove --purge unscd samba* apache2* bind9* sendmail*
apt autoremove -y
systemctl stop apache2
systemctl disable apache2

# Instalasi dan konfigurasi sertifikat SSL
sudo lsof -t -i tcp:80 -s tcp:listen | sudo xargs kill
read -p "Install certificate for IPv4 or IPv6? (4/6): " ip_version
if [ "$ip_version" == "4" ]; then
    systemctl stop nginx
    mkdir -p /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    echo "Cert installed for IPv4."
elif [ "$ip_version" == "6" ]; then
    systemctl stop nginx
    mkdir -p /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --listen-v6
    ~/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    echo "Cert installed for IPv6."
else
    echo "Invalid IP version. Please choose '4' for IPv4 or '6' for IPv6."
fi
chmod 644 /etc/xray/*

# Instalasi Nginx
apt install -y nginx
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default
rm -rf /etc/nginx/conf.d /etc/nginx/nginx.conf
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/sh4dowByte/xray-server/refs/heads/main/nginx/withoutssl.conf"

# Mengunduh file konfigurasi dan biner
cd /usr/bin
wget -O noobzvpns "https://github.com/noobz-id/noobzvpns/raw/master/noobzvpns.x86_64"
wget https://raw.githubusercontent.com/Rerechan02/fn/main/mesinssh
wget -O m.zip "https://raw.githubusercontent.com/sh4dowByte/xray-server/main/menu.zip"
unzip m.zip && rm -f m.zip && chmod +x *
cd /etc/xray
wget -O config.json "https://raw.githubusercontent.com/sh4dowByte/xray-server/main/config.json"
chmod +x config.json
echo "XRAY Server" > /etc/handeling
echo "#00FF00" >> /etc/handeling
echo "${MYIP}" > /usr/bin/.ipvps
cd /etc/noobzvpns
wget -O cert.pem "https://github.com/noobz-id/noobzvpns/raw/master/cert.pem"
wget -O key.pem "https://github.com/noobz-id/noobzvpns/raw/master/key.pem"
chmod +x *

# Instalasi VNSTAT
apt install -y vnstat libsqlite3-dev
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd ..
NET=$(ip -o link show | awk '{print $2}' | grep -v lo | cut -d: -f1 | head -n1)
vnstat -u -i "$NET"
sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -rf vnstat-2.6 vnstat-2.6.tar.gz

# Instalasi Plugin
wget -O plugin.sh https://github.com/praiman99/Plugin-FN/raw/Beginner/plugin.sh
chmod +x plugin.sh && ./plugin.sh && rm -f plugin.sh

# Konfigurasi NoobZVPNS
cat > /etc/noobzvpns/config.json << END
{
    "tcp_std": [8080],
    "tcp_ssl": [9443],
    "ssl_cert": "/etc/noobzvpns/cert.pem",
    "ssl_key": "/etc/noobzvpns/key.pem",
    "ssl_version": "AUTO",
    "conn_timeout": 60,
    "dns_resolver": "/etc/resolv.conf",
    "http_ok": "HTTP/1.1 101 Switching Protocols[crlf]Upgrade: websocket[crlf][crlf]"
}
END

# Membuat layanan systemd
cat > /etc/systemd/system/xray.service << END
[Unit]
Description=Xray by VnzVPN
After=network.target nss-lookup.target
[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/xray -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
[Install]
WantedBy=multi-user.target
END

cat > /etc/systemd/system/badvpn.service << END
[Unit]
Description=BadVPN Gaming Support Port 7300 By VnzVPN
After=syslog.target network-online.target
[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/bin/badvpn --listen-addr 127.0.0.1:7300 --max-clients 500
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
END

cat > /etc/systemd/system/edu.service << END
[Unit]
Description=WebSocket V1 By Newbie Store
After=syslog.target network-online.target
[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/bin/ws -f /usr/bin/config.yaml
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
END

# Instalasi UDP
ip_nat=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n 1p)
interface=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | grep "$ip_nat" | awk '{print $NF}')
public_ip=$(curl 2ip.io)
wget -O /usr/bin/udp-request "https://raw.githubusercontent.com/prjkt-nv404/UDP-Request-Manager/main/bin/bin-urqst" &>/dev/null
chmod +x /usr/bin/udp-request
mkdir -p /etc/req
cat > /etc/req/config.json << END
{
    "listen": ":36711",
    "stream_buffer": 33554432,
    "receive_buffer": 83886080,
    "auth": {"mode": "passwords"}
}
END
chmod +x /etc/req/*
cat > /etc/systemd/system/udp-request.service << END
[Unit]
Description=UDP Request By @VnzVPN
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/etc/req
ExecStart=/usr/bin/udp-request -ip=$public_ip -net=$interface -exclude=80 -mode=system
Restart=always
RestartSec=3s
[Install]
WantedBy=multi-user.target
END
systemctl daemon-reload &>/dev/null
systemctl enable udp-request &>/dev/null
systemctl start udp-request &>/dev/null
wget https://raw.githubusercontent.com/Rerechan02/UDP/main/udp.sh && chmod +x udp.sh && ./udp.sh

# Instalasi Hysteria
checkRoot
script_header
apt update -y && apt install -y curl bc grep wget nano net-tools figlet jq python3 lolcat
export PATH="/usr/games:$PATH"
ln -s /usr/games/lolcat /usr/local/bin/lolcat

# Verifikasi kunci Hysteria (contoh sederhana, sesuaikan dengan kebutuhan)
user_key="YaaDede007"
valid_keys=$(curl -s "https://raw.githubusercontent.com/zac6ix/zac6ix.github.io/master/hys.json")
if [[ $valid_keys == *"$user_key"* ]]; then
    echo -e "${green}Verification successful. Proceeding with installation...${NC}"
    sleep 2
else
    echo -e "${red}Verification failed. Aborting installation.${NC}"
    exit 1
fi

# Konfigurasi Hysteria
HYST_SERVER_IP=$(curl ifconfig.me)
OBFS="VnzVPNSTORE"
PASSWORD="01kso2ksomwsoj29wjsdk29sk920"
mkdir -p /etc/volt /etc/hysteria
PROTOCOL="udp"
UDP_PORT="47912"
UDP_PORT_HP="10000-65000"
remarks="VnzVPNSTOREHysteria"
url="hysteria://${domain}:${UDP_PORT}?mport=10000-65000&protocol=${PROTOCOL}&auth=${PASSWORD}&obfsParam=${OBFS}&peer=${domain}&insecure=0&upmbps=100&downmbps=100&alpn=h3#${remarks}"
echo "$domain" > /etc/volt/DOMAIN
echo "$PROTOCOL" > /etc/volt/PROTOCOL
echo "$UDP_PORT" > /etc/volt/UDP_PORT
echo "$UDP_PORT_HP" > /etc/volt/UDP_PORT_HP
echo "$OBFS" > /etc/volt/OBFS
echo "$PASSWORD" > /etc/volt/PASSWORD

# Instalasi Hysteria Binary
wget -O /usr/local/bin/hysteria "https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-amd64"
chmod +x /usr/local/bin/hysteria
mkdir -p /etc/hysteria
cat > /etc/hysteria/config.json << END
{
    "server": "udp.voltssh.xyz",
    "listen": ":$UDP_PORT",
    "protocol": "$PROTOCOL",
    "cert": "/etc/hysteria/hysteria.server.crt",
    "key": "/etc/hysteria/hysteria.server.key",
    "up": "100 Mbps",
    "down": "100 Mbps",
    "disable_udp": false,
    "obfs": "$OBFS",
    "auth": {"mode": "passwords", "config": ["$PASSWORD"]}
}
END

# Generate SSL untuk Hysteria
openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048
openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt
openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$domain" -out /etc/hysteria/hysteria.server.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:$domain") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -CAcreateserial -out /etc/hysteria/hysteria.server.crt

# Layanan Hysteria
cat > /etc/systemd/system/hysteria.service << END
[Unit]
Description=VNZ-AIO Hysteria Service @VnzVPN
After=network.target
[Service]
User=root
Group=root
WorkingDirectory=/etc/hysteria
Environment="PATH=/usr/local/bin/hysteria"
ExecStart=/usr/local/bin/hysteria -config /etc/hysteria/config.json server
[Install]
WantedBy=multi-user.target
END
systemctl daemon-reload
systemctl enable hysteria.service
systemctl start hysteria.service

# Konfigurasi klien Hysteria
mkdir -p /etc/hysteria/client
cat > /etc/hysteria/client/config.json << END
{
    "server": "udp.voltssh.xyz",
    "listen": ":$UDP_PORT",
    "protocol": "$PROTOCOL",
    "cert": "/etc/xray/xray.crt",
    "key": "/etc/xray/xray.key",
    "up": "100 Mbps",
    "down": "100 Mbps",
    "disable_udp": false,
    "obfs": "$OBFS",
    "auth": {"mode": "passwords", "config": ["$PASSWORD"]}
}
END
cat > /etc/hysteria/client/info.txt << END
----------------------
Client Configuration
----------------------
Hysteria Server Domain: $domain
Hysteria Server IP: $HYST_SERVER_IP
Hysteria Server Port(Single): $UDP_PORT
Hysteria Server Port(Hopping): $UDP_PORT_HP
Obfuscation(OBFS): $OBFS
Authentication(AUTH) password: $PASSWORD
URI(with port hopping): $url
---------------------
(Version 1.3.5)
script by: @VnzVPN
END
chmod +x /etc/hysteria/client/config.json

# Mengatur layanan lainnya
wget -O /etc/systemd/system/noobzvpns.service "https://github.com/noobz-id/noobzvpns/raw/master/noobzvpns.service"
wget -O /usr/bin/.ver "https://raw.githubusercontent.com/sh4dowByte/xray-server/main/versi"
cat > /etc/cron.d/up_otm << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/5 * * * * root /usr/bin/autoup
END

# Mengaktifkan dan memulai layanan
systemctl enable xray nginx edu badvpn limit cron noobzvpns hysteria
systemctl restart xray nginx edu badvpn limit cron noobzvpns hysteria

# Instalasi bot notifikasi Telegram
apt install -y rclone
printf "q\n" | rclone config
wget -qO /root/.config/rclone/rclone.conf "https://raw.githubusercontent.com/diah082/vip/main/install/rclone.conf"
if grep -Ei 'ubuntu.*(24|23)' /etc/os-release || grep -Ei 'debian.*12' /etc/os-release; then
    apt install -y telegram-send
else
    apt install -y python3-pip
    pip3 install telegram-send
fi
echo "LABEL=/boot /boot ext2 default, ro 1 2" >> /etc/fstab
printf "7099310060:AAFLsT7bVpYQISe4u5uev209q0ZS-tXw1xs" | telegram-send --configure

# Membersihkan file instalasi
cd
rm -fr * .bash_history

# Selesai
clear
echo -e "${green}Installasi Telah Selesai${NC}"
sleep 5
reboot
