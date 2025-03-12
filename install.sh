#!/bin/bash

# */
# Credit Autoscript AIO
# [ @bumiayuvpn | Owner     ]
# [ @vpnbumiayu | channel   ]
# ===========================
# Tools Usage:
#             - Termux, MT Manager, Acode
#             - VsCode, Github, Comand Promt
# /*

clear
#rm -fr /etc/resolv.conf
echo "nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 8.8.8.8
nameserver 8.4.8.4
" >> /etc/resolv.conf

# // Clear Data
clear
clear && clear && clear
clear;clear;clear

link="https://raw.githubusercontent.com/bmayu1/scriptvpn/main"
# [ Warna ]
red='\e[1;31m'
green='\e[0;32m'
cyan='\e[0;36m'
white='\e[037;1m'
grey='\e[1;36m'
NC='\e[0m'

MYIP=$(curl -s ifconfig.me)
clear
#IZIN=$( curl https://raw.githubusercontent.com/bmayu1/izin/main/ip | grep $MYIP )
IZIN=$(curl -s https://raw.githubusercontent.com/bmayu1/izin/main/ip | grep "$MYIP" | awk '{ print $4 }')
if [ $MYIP = $IZIN ]; then
echo -e "${green}Permission Accepted...${NC}"
else
clear
echo -e "${red}Permission Denied!${NC}";
echo "Please Contact Admin"
echo "Telegram t.me/bumiayuvpn"
exit 1
fi
clear

# // Melakukan Update Dan Upgrade Data Server
apt update -y
apt upgrade -y
apt install binutils -y
apt install socat -y
apt install ruby -y
gem install lolcat
apt install wget curl -y
#apt install vnstat -y
apt install htop -y
apt install speedtest-cli -y
apt install cron -y
apt install figlet -y
apt install zip unzip -y
clear

# // Melakukan Pembuatan Directory
clear
mkdir -p /funny
sleep 1
mkdir -p /rere
sleep 1
mkdir -p /etc/slowdns
sleep 1
mkdir -p /etc/xray
sleep 1
mkdir -p /etc/websocket
sleep 1
mkdir -p /etc/xray
sleep 1
mkdir -p /etc/funny
sleep 1
mkdir -p /etc/funnt/limit
sleep 1
mkdir -p /etc/funny/limit/xray
sleep 1
mkdir -p /etc/funny/limit/xray/ip
sleep 1
mkdir -p /etc/funny/limit/xray/quota
sleep 1
mkdir -p /etc/funny/limit/ssh
sleep 1
mkdir -p /etc/funny/limit/ssh/ip
sleep 1
mkdir -p /etc/v2ray
sleep 1
mkdir -p /var
mkdir -p /var/lib
mkdir -p /var/lib/crot
chmod /var/lib/crot/*
mkdir -p /var/log
mkdir -p /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/xray/error1.log
touch /var/log/xray/akses.log
touch /var/log/xray/access1.log
touch /var/log/xray/access2.log
touch /var/log/xray/access3.log
touch /var/log/xray/access4.log
touch /var/log/xray/access5.log
touch /var/log/xray/access6.log
touch /etc/funny/.l2tp
touch /etc/funny/.sstp
touch /etc/funny/.pptp
touch /etc/funny/.ptp
touch /etc/funny/.wireguard
touch /etc/funny/.socks5
chmod +x /var/log/xray/*
touch /etc/funny/limit/ssh/ip/syslog
touch /etc/funny/limit/ssh/ip/rere
echo "9999999" >> /etc/funny/limit/ssh/ip/syslog
echo "9999999" >> /etc/funny/limit/ssh/ip/rere
mkdir -p /etc/noobzvpns
clear

# // Meminta Konfigurasi
read -p "Input Your Domain: " domain
echo "${domain}" > /etc/xray/domain
clear

# // Membuat Layanan Selalu Berjalan
echo "0 0,6,12,18 * * * root backup
0,15,30,45 * * * * root /usr/bin/xp
*/5 * * * * root limit" >> /etc/crontab
systemctl daemon-reload
systemctl restart cron

# // Menginstall Dropbear
apt install dropbear -y
rm /etc/default/dropbear
rm /etc/issue.net
cat> /etc/issue.net << END
<p style="text-align:center">
<font color="#00FF00"><b> WELCOME TO BumiayuvpN </b></font><br>
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
<font color="#40E0D0"><b> Join Telegram Channel: https://t.me/vpnbumiayu</br></font><br>
<font color="#6A5ACD"><b> Buy VPN Premium Contact https://t.me/bumiayuvpn</br></font><br>
<font color='#FF0059'>▬</font><font color='#F1006F'>▬</font><font color='#E30085'>▬</font><font color='#D6009B'>▬</font><font color='#C800B1'>▬</font><font color='#BB00C7'>ஜ</font><font color='#AD00DD'>۩</font><font color='#9F00F3'>۞</font><font color='#9F00F3'>۩</font><font color='#AD00DD'>ஜ</font><font color='#BB00C7'>▬</font><font color='#C800B1'>▬</font><font color='#D6009B'>▬</font><font color='#E30085'>▬</font><font color='#F1006F'>▬</font>
END
if grep -Ei 'ubuntu.*(24|23)' /etc/os-release || grep -Ei 'debian.*12' /etc/os-release; then
cat>  /etc/default/dropbear << END
# The TCP port that Dropbear listens on
DROPBEAR_PORT=111

# Receive window size - this is a tradeoff between memory and network performance
DROPBEAR_RECEIVE_WINDOW=65536

# Any additional arguments for Dropbear.  For instead set
#
DROPBEAR_EXTRA_ARGS="-b /etc/issue.net -p 109 -p 69"


#
# to specify an optional banner file containing a message to be sent to
DROPBEAR_BANNER="/etc/issue.net"
# clients before they connect; or
#
#   DROPBEAR_EXTRA_ARGS="-p 109""-r /etc/dropbear/rsa_host_key -r /etc/dropbear/ed25519_host_key"
#
# to specify custom host keys.  See dropbear(8) for possible values.
#DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"""
END
else
cat>  /etc/default/dropbear << END
# disabled because OpenSSH is installed
# change to NO_START=0 to enable Dropbear
NO_START=0
# the TCP port that Dropbear listens on
DROPBEAR_PORT=111

# any additional arguments for Dropbear
DROPBEAR_EXTRA_ARGS="-p 109 -p 69 "

# specify an optional banner file containing a message to be
# sent to clients before they connect, such as "/etc/issue.net"
DROPBEAR_BANNER="/etc/issue.net"

# RSA hostkey file (default: /etc/dropbear/dropbear_rsa_host_key)
#DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"

# DSS hostkey file (default: /etc/dropbear/dropbear_dss_host_key)
#DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"

# ECDSA hostkey file (default: /etc/dropbear/dropbear_ecdsa_host_key)
#DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"

# Receive window size - this is a tradeoff between memory and
# network performance
DROPBEAR_RECEIVE_WINDOW=65536
END
fi
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
dd=$(ps aux | grep dropbear | awk '{print $2}')
kill $dd
clear
systemctl daemon-reload
/etc/init.d/dropbear restart
clear

# // Menghapus Apache2
apt autoclean -y
apt -y remove --purge unscd
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove bind9*;
apt-get -y remove sendmail*
apt autoremove -y
systemctl stop apache2
systemctl disable apache2
apt remove --purge apache2 -y
apt-get autoremove -y
apt-get autoclean -y
clear

# // Melakukan Renew Certificate
apt install certbot -y
sudo lsof -t -i tcp:80 -s tcp:listen | sudo xargs kill
clear
#echo "start"
#cd /root/
#clear
#echo "starting...., Port 80 Akan di Hentikan Saat Proses install Cert"
#certbot certonly --standalone --preferred-challenges http --agree-tos --email uut.mu.ak@gmail.com -d $domain
#cp /etc/letsencrypt/live/$domain/fullchain.pem /etc/xray/xray.crt
#cp /etc/letsencrypt/live/$domain/privkey.pem /etc/xray/xray.key
#chmod 644 /etc/xray/xray.key
#chmod 644 /etc/xray/xray.crt
#rm -fr /etc/xray/xray.*
clear
read -p "Install certificate for IPv4 or IPv6? (4/6): " ip_version
#read -p "Enter domain: " domain
if [[ $ip_version == "4" ]]; then
    systemctl stop nginx
    mkdir /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    echo "Cert installed for IPv4."
elif [[ $ip_version == "6" ]]; then
    systemctl stop nginx
    mkdir /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 --listen-v6
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    echo "Cert installed for IPv6."
else
    echo "Invalid IP version. Please choose '4' for IPv4 or '6' for IPv6."
fi
# // Menginstall Nginx
clear
chmod 644 /etc/xray/*
apt -y install nginx
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
cd /etc/nginx
rm -fr conf.d
rm -fr nginx.conf
wget -O nginx.conf "https://github.com/xhidrolix/cnf/raw/main/.conf"
cd
clear

# // Mengambil File
cd /usr/bin
wget -O /usr/bin/noobzvpns "https://github.com/noobz-id/noobzvpns/raw/master/noobzvpns.x86_64"
wget https://raw.githubusercontent.com/Rerechan02/fn/main/mesinssh
wget -O m.zip "${link}/menu.zip"
unzip m.zip ; rm -fr m.zip ; chmod +x *
clear
cd /etc/xray
wget -O m.zip "${link}/json.zip"
unzip m.zip ; rm -fr m.zip ; chmod +x *
echo "BumiayuvpN Server" > /etc/handeling
echo "#00FF00" >> /etc/handeling
echo "${MYIP}" > /usr/bin/.ipvps
clear
wget -O /etc/noobzvpns/cert.pem "https://github.com/noobz-id/noobzvpns/raw/master/cert.pem"
wget -O /etc/noobzvpns/key.pem "https://github.com/noobz-id/noobzvpns/raw/master/key.pem"
chmod +x /etc/noobzvpns/*
clear

# Menginstall VNSTAT
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
clear

# Menginstall Plugin
wget https://github.com/praiman99/Plugin-FN/raw/Beginner/plugin.sh ; chmod 777 plugin.sh ; ./plugin.sh ; rm -fr plugin.sh

# // Membuat Konfigurasi NoobZVPNS
cat > /etc/noobzvpns/config.json <<-JSON
{
	"tcp_std": [
		8080
	],
	"tcp_ssl": [
		9443
	],
	"ssl_cert": "/etc/noobzvpns/cert.pem",
	"ssl_key": "/etc/noobzvpns/key.pem",
	"ssl_version": "AUTO",
	"conn_timeout": 60,
	"dns_resolver": "/etc/resolv.conf",
	"http_ok": "HTTP/1.1 101 Switching Protocols[crlf]Upgrade: websocket[crlf][crlf]"
}
JSON

# // Membuat Service
cat> /etc/systemd/system/xray.service << END
[Unit]
Description=Xray by VnzVPN
Documentation=https://indo-ssh.com
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

# // Membuat service Lainya
#cat> /etc/systemd/system/limit.service << END
#[Unit]
#Description=Limit All Service By VnzVPN
#Documentation=https://t.me/VnzVPN
#After=syslog.target network-online.target

#[Service]
#User=root
#NoNewPrivileges=true
#ExecStart=/usr/bin/loop

#[Install]
#WantedBy=multi-user.target
#END

cat> /etc/systemd/system/badvpn.service << END
[Unit]
Description=BadVPN Gaming Support Port 7300 By VnzVPN
Documentation=https://t.me/VnzVPN
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

cat> /etc/systemd/system/edu.service << END
[Unit]
Description=WebSocket V1 By Newbie Store
Documentation=https://github.com/Diah082
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

# // Menginstall UDP
clear

# [ Mengecek Alur Network Server ]
ip_nat=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n 1p)
interface=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | grep "$ip_nat" | awk {'print $NF'})
public_ip=$(curl 2ip.io)

# [ Mengambil File UDP Request ]
wget "https://raw.githubusercontent.com/prjkt-nv404/UDP-Request-Manager/main/bin/bin-urqst" -O /usr/bin/udp-request &>/dev/null
chmod +x /usr/bin/udp-request

# [ Membuat Konfigurasi ]
mkdir /etc/req
cat <<EN >/etc/req/config.json
{
  "listen": ":36711",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
EN
chmod +x /etc/req/*

# [ Membuat Service ]
cat <<EOF >/etc/systemd/system/udp-request.service
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
EOF
systemctl daemon-reload &>/dev/null
systemctl enable udp-request &>/dev/null
systemctl start udp-request &>/dev/null

# [ Menginstall UDP Custom ]
wget https://raw.githubusercontent.com/Rerechan02/UDP/main/udp.sh && chmod +x udp.sh && ./udp.sh
clear

checkRoot() {
user=$(whoami)
if [ ! "${user}" = "root" ]; then
echo -e "\e[91mPlease run as root user!\e[0m" # Red text
exit 1
fi
}
T_BOLD=$(tput bold)
T_GREEN=$(tput setaf 2)
T_YELLOW=$(tput setaf 3)
T_RED=$(tput setaf 1)
T_RESET=$(tput sgr0)
script_header() {
clear
echo ""
echo -e "\e[1m\e[34m****************************************************"
echo -e "  Installation & Configuration of \e[1;36mHysteria Protocol"
echo -e "              (Version 1.3.5) - by: BMAYU"
echo -e "\e[1m\e[34m****************************************************\e[0m"
echo ""
}
update_packages() {
echo ""
echo -e "\033[1;32m[\033[1;32mPass ✅\033[1;32m] \033[1;37m ⇢  \033[1;33mCollecting binaries...\033[0m"
echo -e "\033[1;32m      ♻️ \033[1;37m      \033[1;33mPlease wait...\033[0m"
echo -e ""
sudo apt-get update && sudo apt-get upgrade -y
local dependencies=("curl" "bc" "grep" "wget" "nano" "net-tools" "figlet" "jq" "python3")
for dependency in "${dependencies[@]}"; do
if ! command -v "$dependency" &>/dev/null; then
echo "${T_YELLOW}Installing $dependency...${T_RESET}"
apt update && apt install -y "$dependency" >/dev/null 2>&1
fi
done
sudo apt-get install wget nano net-tools figlet lolcat -y
export PATH="/usr/games:$PATH"
sudo ln -s /usr/games/lolcat /usr/local/bin/lolcat
clear
echo ""
echo -e "\033[1;32m[\033[1;32mPass ✅\033[1;32m] \033[1;37m ⇢  \033[1;33mCollecting binaries...\033[0m"
echo -e "\033[1;32m      ♻️ \033[1;37m      \033[1;33mPlease wait...\033[0m"
echo -e ""
}
banner() {
clear
}
verification() {
clear
fetch_valid_keys() {
keys=$(curl -s -H "Cache-Control: no-cache" -H "Pragma: no-cache" "https://raw.githubusercontent.com/zac6ix/zac6ix.github.io/master/hys.json")
echo "$keys"
}
verify_key() {
local key_to_verify="$1"
local valid_keys="$2"
if [[ $valid_keys == *"$key_to_verify"* ]]; then
return 0 # Key is valid
else
return 1 # Key is not valid
fi
}
valid_keys=$(fetch_valid_keys)
echo ""
figlet -k BM-AIO | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1' && figlet -k Hysteria | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1'
echo "───────────────────────────────────────────────────────────────────────•"
echo ""
echo ""
echo -e " 〄 \033[1;37m ⌯  \033[1;33mYou must have purchased a Key\033[0m"
echo -e " 〄 \033[1;37m ⌯  \033[1;33mif you didn't, contact [Volt*V3r!f.y]\033[0m"
echo -e " 〄 \033[1;37m ⌯ ⇢ \033[1;33mhttps://t.me/voltverifybot\033[0m"
echo ""
echo "───────────────────────────────────────────────────────────────────────•"
user_key="YaaDede007"
if verify_key "$user_key" "$valid_keys"; then
sleep 2
echo "${T_GREEN} ⇢ Verification successful.${T_RESET}"
echo "${T_GREEN} ⇢ Proceeding with the installation...${T_RESET}"
echo ""
echo ""
echo -e "\033[1;32m ♻️ Please wait...\033[0m"
find / -type f -name "hys.json" -delete >/dev/null 2>&1
sleep 1
clear
clear
validate_length() {
local input_string="$1"
local min_length="$2"
if [ ${#input_string} -lt $min_length ]; then
echo "Input must be at least $min_length characters long."
return 1
fi
}
figlet -k BM | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1' && figlet -k Hysteria | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1'
echo "───────────────────────────────────────────────────────────────────────•"
echo -e "   Hysteria Server Configuration"
echo -e "*******************************************\e[0m"
echo ""
echo "-------------------------------------------"
HYST_SERVER_IP=$(curl ifconfig.me)
DOMAIN=$domain
while true; do
OBFS="VnzVPNSTORE"
if validate_length "$OBFS" 10; then
break # Break the loop if input is valid
fi
done
echo "-------------------------------------------"
while true; do
echo -e "\nPlease enter Authentication(AUTH): 👇"
PASSWORD="01kso2ksomwsoj29wjsdk29sk920"
if validate_length "$PASSWORD" 20; then
break # Break the loop if input is valid
fi
done
echo ""
mkdir -p /etc/volt
PROTOCOL="udp"
UDP_PORT="47912"
UDP_PORT_HP="10000-65000"
HPStart="10000"
HPEnd="65000"
UDP_QUICC_WINDOW="196608"
remarks="VnzVPNSTOREHysteria"
sec="0"
url=$(echo -e "hysteria://${DOMAIN}:${UDP_PORT}?mport=${HPStart}-${HPEnd}&protocol=${protocol}&auth=${PASSWORD}&obfsParam=${OBFS}&peer=${DOMAIN}&insecure=${sec}&upmbps=100&downmbps=100&alpn=h3#${remarks}" | sed 's/ /%20/g')
echo "$DOMAIN" >/etc/volt/DOMAIN
echo "$PROTOCOL" >/etc/volt/PROTOCOL
echo "$UDP_PORT" >/etc/volt/UDP_PORT
echo "$UDP_PORT_HP" >/etc/volt/UDP_PORT_HP
echo "$OBFS" >/etc/volt/OBFS
echo "$PASSWORD" >/etc/volt/PASSWORD
export DOMAIN
export PROTOCOL
export UDP_PORT
export UDP_PORT_HP
export OBFS
export PASSWORD
SCRIPT_NAME="$(basename "$0")"
SCRIPT_ARGS=("$@")
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
REPO_URL="https://github.com/apernet/hysteria"
API_BASE_URL="https://api.github.com/repos/apernet/hysteria"
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)
PACKAGE_MANAGEMENT_INSTALL="${PACKAGE_MANAGEMENT_INSTALL:-}"
OPERATING_SYSTEM="${OPERATING_SYSTEM:-}"
ARCHITECTURE="${ARCHITECTURE:-}"
HYSTERIA_USER="${HYSTERIA_USER:-}"
HYSTERIA_HOME_DIR="${HYSTERIA_HOME_DIR:-}"
OPERATION=
VERSION=
FORCE=
LOCAL_FILE=
has_command() {
local _command=$1
type -P "$_command" >/dev/null 2>&1
}
curl() {
command curl "${CURL_FLAGS[@]}" "$@"
}
mktemp() {
command mktemp "$@" "hyservinst.XXXXXXXXXX"
}
tput() {
if has_command tput; then
command tput "$@"
fi
}
tred() {
tput setaf 1
}
tgreen() {
tput setaf 2
}
tyellow() {
tput setaf 3
}
tblue() {
tput setaf 4
}
taoi() {
tput setaf 6
}
tbold() {
tput bold
}
treset() {
tput sgr0
}
note() {
local _msg="$1"
echo -e "$SCRIPT_NAME: $(tbold)note: $_msg$(treset)"
}
warning() {
local _msg="$1"
echo -e "$SCRIPT_NAME: $(tyellow)warning: $_msg$(treset)"
}
error() {
local _msg="$1"
echo -e "$SCRIPT_NAME: $(tred)error: $_msg$(treset)"
}
has_prefix() {
local _s="$1"
local _prefix="$2"
if [[ -z "$_prefix" ]]; then
return 0
fi
if [[ -z "$_s" ]]; then
return 1
fi
[[ "x$_s" != "x${_s#"$_prefix"}" ]]
}
systemctl() {
if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]] || ! has_command systemctl; then
return
fi
command systemctl "$@"
}
show_argument_error_and_exit() {
local _error_msg="$1"
error "$_error_msg"
echo "Try \"$0 --help\" for the usage." >&2
exit 22
}
install_content() {
local _install_flags="$1"
local _content="$2"
local _destination="$3"
local _tmpfile="$(mktemp)"
echo -ne "Install $_destination ... "
echo "$_content" >"$_tmpfile"
if install "$_install_flags" "$_tmpfile" "$_destination"; then
echo -e "ok"
fi
rm -f "$_tmpfile"
}
remove_file() {
local _target="$1"
echo -ne "Remove $_target ... "
if rm "$_target"; then
echo -e "ok"
fi
}
exec_sudo() {
local _saved_ifs="$IFS"
IFS=$'\n'
local _preserved_env=(
$(env | grep "^PACKAGE_MANAGEMENT_INSTALL=" || true)
$(env | grep "^OPERATING_SYSTEM=" || true)
$(env | grep "^ARCHITECTURE=" || true)
$(env | grep "^HYSTERIA_\w*=" || true)
$(env | grep "^FORCE_\w*=" || true)
)
IFS="$_saved_ifs"
exec sudo env \
"${_preserved_env[@]}" \
"$@"
}
detect_package_manager() {
if [[ -n "$PACKAGE_MANAGEMENT_INSTALL" ]]; then
return 0
fi
if has_command apt; then
PACKAGE_MANAGEMENT_INSTALL='apt update; apt -y install'
return 0
fi
if has_command dnf; then
PACKAGE_MANAGEMENT_INSTALL='dnf check-update; dnf -y install'
return 0
fi
if has_command yum; then
PACKAGE_MANAGEMENT_INSTALL='yum update; yum -y install'
return 0
fi
if has_command zypper; then
PACKAGE_MANAGEMENT_INSTALL='zypper update; zypper install -y --no-recommends'
return 0
fi
if has_command pacman; then
PACKAGE_MANAGEMENT_INSTALL='pacman -Syu; pacman -Syu --noconfirm'
return 0
fi
return 1
}
install_software() {
local _package_name="$1"
if ! detect_package_manager; then
error "Supported package manager is not detected, please install the following package manually:"
echo
echo -e "\t* $_package_name"
echo
exit 65
fi
echo "Installing missing dependence '$_package_name' with '$PACKAGE_MANAGEMENT_INSTALL' ... "
if $PACKAGE_MANAGEMENT_INSTALL "$_package_name"; then
echo "ok"
else
error "Cannot install '$_package_name' with detected package manager, please install it manually."
exit 65
fi
}
is_user_exists() {
local _user="$1"
id "$_user" >/dev/null 2>&1
}
check_permission() {
if [[ "$UID" -eq '0' ]]; then
return
fi
note "The user currently executing this script is not root."
case "$FORCE_NO_ROOT" in
'1')
warning "FORCE_NO_ROOT=1 is specified, we will process without root and you may encounter the insufficient privilege error."
;;
*)
if has_command sudo; then
note "Re-running this script with sudo, you can also specify FORCE_NO_ROOT=1 to force this script running with current user."
exec_sudo "$0" "${SCRIPT_ARGS[@]}"
else
error "Please run this script with root or specify FORCE_NO_ROOT=1 to force this script running with current user."
exit 13
fi
;;
esac
}
check_environment_operating_system() {
if [[ -n "$OPERATING_SYSTEM" ]]; then
warning "OPERATING_SYSTEM=$OPERATING_SYSTEM is specified, opreating system detection will not be perform."
return
fi
if [[ "x$(uname)" == "xLinux" ]]; then
OPERATING_SYSTEM=linux
return
fi
error "This script only supports Linux."
note "Specify OPERATING_SYSTEM=[linux|darwin|freebsd|windows] to bypass this check and force this script running on this $(uname)."
exit 95
}
check_environment_architecture() {
if [[ -n "$ARCHITECTURE" ]]; then
warning "ARCHITECTURE=$ARCHITECTURE is specified, architecture detection will not be performed."
return
fi
case "$(uname -m)" in
'i386' | 'i686')
ARCHITECTURE='386'
;;
'amd64' | 'x86_64')
ARCHITECTURE='amd64'
;;
'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
ARCHITECTURE='arm'
;;
'armv8' | 'aarch64')
ARCHITECTURE='arm64'
;;
'mips' | 'mipsle' | 'mips64' | 'mips64le')
ARCHITECTURE='mipsle'
;;
's390x')
ARCHITECTURE='s390x'
;;
*)
error "The architecture '$(uname -a)' is not supported."
note "Specify ARCHITECTURE=<architecture> to bypass this check and force this script running on this $(uname -m)."
exit 8
;;
esac
}
check_environment_systemd() {
if [[ -d "/run/systemd/system" ]] || grep -q systemd <(ls -l /sbin/init); then
return
fi
case "$FORCE_NO_SYSTEMD" in
'1')
warning "FORCE_NO_SYSTEMD=1 is specified, we will process as normal even if systemd is not detected by us."
;;
'2')
warning "FORCE_NO_SYSTEMD=2 is specified, we will process but all systemd related command will not be executed."
;;
*)
error "This script only supports Linux distributions with systemd."
note "Specify FORCE_NO_SYSTEMD=1 to disable this check and force this script running as systemd is detected."
note "Specify FORCE_NO_SYSTEMD=2 to disable this check along with all systemd related commands."
;;
esac
}
check_environment_curl() {
if has_command curl; then
return
fi
apt update
apt -y install curl
}
check_environment_grep() {
if has_command grep; then
return
fi
apt update
apt -y install grep
}
check_environment() {
check_environment_operating_system
check_environment_architecture
check_environment_systemd
check_environment_curl
check_environment_grep
}
vercmp_segment() {
local _lhs="$1"
local _rhs="$2"
if [[ "x$_lhs" == "x$_rhs" ]]; then
echo 0
return
fi
if [[ -z "$_lhs" ]]; then
echo -1
return
fi
if [[ -z "$_rhs" ]]; then
echo 1
return
fi
local _lhs_num="${_lhs//[A-Za-z]*/}"
local _rhs_num="${_rhs//[A-Za-z]*/}"
if [[ "x$_lhs_num" == "x$_rhs_num" ]]; then
echo 0
return
fi
if [[ -z "$_lhs_num" ]]; then
echo -1
return
fi
if [[ -z "$_rhs_num" ]]; then
echo 1
return
fi
local _numcmp=$(($_lhs_num - $_rhs_num))
if [[ "$_numcmp" -ne 0 ]]; then
echo "$_numcmp"
return
fi
local _lhs_suffix="${_lhs#"$_lhs_num"}"
local _rhs_suffix="${_rhs#"$_rhs_num"}"
if [[ "x$_lhs_suffix" == "x$_rhs_suffix" ]]; then
echo 0
return
fi
if [[ -z "$_lhs_suffix" ]]; then
echo 1
return
fi
if [[ -z "$_rhs_suffix" ]]; then
echo -1
return
fi
if [[ "$_lhs_suffix" < "$_rhs_suffix" ]]; then
echo -1
return
fi
echo 1
}
vercmp() {
local _lhs=${1#v}
local _rhs=${2#v}
while [[ -n "$_lhs" && -n "$_rhs" ]]; do
local _clhs="${_lhs/.*/}"
local _crhs="${_rhs/.*/}"
local _segcmp="$(vercmp_segment "$_clhs" "$_crhs")"
if [[ "$_segcmp" -ne 0 ]]; then
echo "$_segcmp"
return
fi
_lhs="${_lhs#"$_clhs"}"
_lhs="${_lhs#.}"
_rhs="${_rhs#"$_crhs"}"
_rhs="${_rhs#.}"
done
if [[ "x$_lhs" == "x$_rhs" ]]; then
echo 0
return
fi
if [[ -z "$_lhs" ]]; then
echo -1
return
fi
if [[ -z "$_rhs" ]]; then
echo 1
return
fi
return
}
check_hysteria_user() {
local _default_hysteria_user="$1"
if [[ -n "$HYSTERIA_USER" ]]; then
return
fi
if [[ ! -e "$SYSTEMD_SERVICES_DIR/hysteria.service" ]]; then
HYSTERIA_USER="$_default_hysteria_user"
return
fi
HYSTERIA_USER="$(grep -o '^User=\w*' "$SYSTEMD_SERVICES_DIR/hysteria.service" | tail -1 | cut -d '=' -f 2 || true)"
if [[ -z "$HYSTERIA_USER" ]]; then
HYSTERIA_USER="$_default_hysteria_user"
fi
}
check_hysteria_homedir() {
local _default_hysteria_homedir="$1"
if [[ -n "$HYSTERIA_HOME_DIR" ]]; then
return
fi
if ! is_user_exists "$HYSTERIA_USER"; then
HYSTERIA_HOME_DIR="$_default_hysteria_homedir"
return
fi
HYSTERIA_HOME_DIR="$(eval echo ~"$HYSTERIA_USER")"
}
tpl_hysteria_server_service_base() {
local _config_name="$1"
cat <<EOF
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
EOF
}
tpl_hysteria_server_service() {
tpl_hysteria_server_service_base 'config'
}
tpl_hysteria_server_x_service() {
tpl_hysteria_server_service_base '%i'
}
tpl_etc_hysteria_config_json() {
cat <<EOF
{
"server": "udp.voltssh.xyz",
"listen": ":$UDP_PORT",
"protocol": "$PROTOCOL",
"cert": "/etc/hysteria/hysteria.server.crt",
"key": "/etc/hysteria/hysteria.server.key",
"up": "100 Mbps",
"up_mbps": 100,
"down": "100 Mbps",
"down_mbps": 100,
"disable_udp": false,
"obfs": "$OBFS",
"auth": {
"mode": "passwords",
"config": ["$PASSWORD"]
}
}
EOF
}
get_running_services() {
if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
return
fi
systemctl list-units --state=active --plain --no-legend |
grep -o "hysteria-server@*[^\s]*.service" || true
}
restart_running_services() {
if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
return
fi
echo "Restarting running service ... "
for service in $(get_running_services); do
echo -ne "Restarting $service ... "
systemctl restart "$service"
echo "done"
done
}
stop_running_services() {
if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
return
fi
echo "Stopping running service ... "
for service in $(get_running_services); do
echo -ne "Stopping $service ... "
systemctl stop "$service"
echo "done"
done
}
is_hysteria_installed() {
if [[ -f "$EXECUTABLE_INSTALL_PATH" || -L "$EXECUTABLE_INSTALL_PATH" ]]; then
return 0
fi
return 1
}
get_installed_version() {
if is_hysteria_installed; then
"$EXECUTABLE_INSTALL_PATH" -v | cut -d ' ' -f 3
fi
}
get_latest_version() {
if [[ -n "$VERSION" ]]; then
echo "$VERSION"
return
fi
local _tmpfile=$(mktemp)
if ! curl -sS -H 'Accept: application/vnd.github.v3+json' "$API_BASE_URL/releases/latest" -o "$_tmpfile"; then
error "Failed to get latest release, please check your network."
exit 11
fi
local _latest_version=$(grep 'tag_name' "$_tmpfile" | head -1 | grep -o '"v.*"')
_latest_version=${_latest_version#'"'}
_latest_version=${_latest_version%'"'}
if [[ -n "$_latest_version" ]]; then
echo "$_latest_version"
fi
rm -f "$_tmpfile"
}
download_hysteria() {
local _version="$1"
local _destination="$2"
local _download_url="$REPO_URL/releases/download/v1.3.5/hysteria-$OPERATING_SYSTEM-$ARCHITECTURE"
echo "Downloading hysteria archive: $_download_url ..."
if ! curl -R -H 'Cache-Control: no-cache' "$_download_url" -o "$_destination"; then
error "Download failed! Please check your network and try again."
return 11
fi
return 0
}
perform_install_hysteria_binary() {
if [[ -n "$LOCAL_FILE" ]]; then
note "Performing local initialization of: $LOCAL_FILE"
echo -ne "Initializing hysteria binaries ... "
if install -Dm755 "$LOCAL_FILE" "$EXECUTABLE_INSTALL_PATH"; then
echo "ok"
else
exit 2
fi
return
fi
local _tmpfile=$(mktemp)
if ! download_hysteria "$VERSION" "$_tmpfile"; then
rm -f "$_tmpfile"
exit 11
fi
echo -ne "Initializing hysteria binaries ... "
if install -Dm755 "$_tmpfile" "$EXECUTABLE_INSTALL_PATH"; then
echo "ok"
else
exit 13
fi
rm -f "$_tmpfile"
}
perform_remove_hysteria_binary() {
remove_file "$EXECUTABLE_INSTALL_PATH"
}
perform_install_hysteria_example_config() {
install_content -Dm644 "$(tpl_etc_hysteria_config_json)" "$CONFIG_DIR/config.json" ""
}
perform_install_hysteria_systemd() {
if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
return
fi
install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria.service"
install_content -Dm644 "$(tpl_hysteria_server_x_service)" "$SYSTEMD_SERVICES_DIR/hysteria@.service"
systemctl daemon-reload
}
perform_remove_hysteria_systemd() {
remove_file "$SYSTEMD_SERVICES_DIR/hysteria.service"
remove_file "$SYSTEMD_SERVICES_DIR/hysteria@.service"
systemctl daemon-reload
}
perform_install_hysteria_home_legacy() {
if ! is_user_exists "$HYSTERIA_USER"; then
echo -ne "Creating user $HYSTERIA_USER ... "
useradd -r -d "$HYSTERIA_HOME_DIR" -m "$HYSTERIA_USER"
echo "ok"
fi
}
perform_install() {
local _is_frash_install
if ! is_hysteria_installed; then
_is_frash_install=1
fi
perform_install_hysteria_binary
perform_install_hysteria_example_config
perform_install_hysteria_home_legacy
perform_install_hysteria_systemd
setup_ssl
start_services
}
setup_ssl() {
echo "Generate SSL certificates"
openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048
openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt
openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -CAcreateserial -out /etc/hysteria/hysteria.server.crt
}
start_services() {
apt update
sudo debconf-set-selections <<<"iptables-persistent iptables-persistent/autosave_v4 boolean true"
sudo debconf-set-selections <<<"iptables-persistent iptables-persistent/autosave_v6 boolean true"
apt -y install iptables-persistent
iptables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
ip6tables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
sysctl net.ipv4.conf.all.rp_filter=0
sysctl net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0
echo "net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0" >/etc/sysctl.conf
sysctl -p
sudo iptables-save >/etc/iptables/rules.v4
sudo ip6tables-save >/etc/iptables/rules.v6
systemctl enable hysteria.service
systemctl start hysteria.service
}
volt() {
clear
figlet -k volt-udp | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1' && figlet -k hysteria | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1'
echo "───────────────────────────────────────────────────────────────────────•"
echo ""
echo -e "\033[1;32m[\033[1;32mPass ✅\033[1;32m] \033[1;37m ⇢  \033[1;33mChecking libs...\033[0m"
echo -e "\033[1;32m      ♻️ \033[1;37m      \033[1;33mPlease wait...\033[0m"
echo -e ""
wget -O /etc/volt/cfgupt.py --no-cache 'https://raw.githubusercontent.com/prjkt-nv404/UDP-Hysteria/main/lib/cfgupt.py' &>/dev/null
chmod +x /usr/bin/volt &>/dev/null
chmod +x /etc/volt/cfgupt.py &>/dev/null
echo ""
}
voltx_hysteria_inst() {
check_permission
check_environment
check_hysteria_user "hysteria"
check_hysteria_homedir "/var/lib/$HYSTERIA_USER"
perform_install
volt
}
voltx_hysteria_inst
sleep 2
else
clear
figlet -k volt-udp | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1' && figlet -k hysteria | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1'
echo "───────────────────────────────────────────────────────────────────────•"
echo "${T_RED} ⇢ Verification failed. Aborting installation.${T_RESET}"
exit 1
fi
}
client_config() {
clear
echo ""
figlet -k VNZ-AIO | lolcat && figlet -k Hysteria | lolcat
echo -e "\e[1;34m************************************"
echo -e "   Generating Client configuration"
echo -e "       please wait for 5 seconds..."
echo -e "\e[0m"
sleep 5 # sleep
clear
mkdir -p /etc/hysteria/client
rm -f /etc/hysteria/client/config.json &>/dev/null
cat <<EOF >/etc/hysteria/client/config.json
{
"server": "udp.voltssh.xyz",
"listen": ":$UDP_PORT",
"protocol": "$PROTOCOL",
"cert": "/etc/xray/xray.crt",
"key": "/etc/xray/xray.key",
"up": "100 Mbps",
"up_mbps": 100,
"down": "100 Mbps",
"down_mbps": 100,
"disable_udp": false,
"obfs": "$OBFS",
"auth": {
"mode": "passwords",
"config": ["$PASSWORD"]
}
}
EOF
cat <<EOF >/etc/hysteria/client/info.txt
----------------------
Client Configuration
----------------------
Hysteria Server Domain: $DOMAIN
Hysteria Server IP: $HYST_SERVER_IP
Hysteria Server Port(Single): $UDP_PORT
Hysteria Server Port(Hopping): $UDP_PORT_HP
Obfuscation(OBFS): $OBFS
Authentication(AUTH) password: $PASSWORD
UDP-QUICC Windows: $UDP_QUICC_WINDOW
URI(with port hopping)
$url
---------------------
(Version 1.3.5)
script by: @VnzVPN
EOF
chmod +x /etc/hysteria/client/config.json
echo ""
figlet -k VNZ-AIO | lolcat && figlet -k Hysteria | lolcat
echo -e "\e[1;36m----------------------"
echo -e " Client Configuration"
echo -e "----------------------\e[0m"
echo -e "Remarks: $remarks"
echo -e "Hysteria Server Domain: $DOMAIN"
echo -e "Hysteria Server IP: $HYST_SERVER_IP"
echo -e "Hysteria Server Port(Single): $UDP_PORT"
echo -e "Hysteria Server Port(Hopping): $UDP_PORT_HP"
echo -e "Obfuscation(OBFS) password: $OBFS"
echo -e "Authentication(AUTH) password:  $PASSWORD"
echo -e "UDP-QUICC Windows: $UDP_QUICC_WINDOW"
echo -e ""
echo -e "URI(with port hopping)"
echo -e "$url"
echo -e ""
echo -e "---------------------"
echo -e "(Version 1.3.5)"
echo -e "script by: @VnzVPN"
echo ""
echo ""
echo -e "Client 'config.json' & 'info.txt' file generated in the"
echo -e "'client' directory at \e[1;32m'/etc/hysteria/'\e[0m"
echo -e "*******************************************"
echo ""
echo -e "\n* Check service running or not running, type: '\e[1;33msystemctl status hysteria\e[0m' to see logs"
echo -e "\n* To uninstall, type: '\e[1;91msystemctl stop hysteria; systemctl disable hysteria; rm -rf /etc/hysteria\e[0m' , without quotes"
echo -e "\nEnjoy using Hysteria"
echo ""
}
reload_service() {
systemctl restart hysteria
systemctl restart systemd-journald
}
main() {
clear
checkRoot
script_header
update_packages
banner
verification
client_config
reload_service
}
main
clear
sleep 0.1
clear

# // Mengambil Service NoobzVPNS
wget -O /etc/systemd/system/noobzvpns.service "https://github.com/noobz-id/noobzvpns/raw/master/noobzvpns.service"
wget -O /usr/bin/.ver "${link}/versi"
cat> /etc/cron.d/up_otm << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/5 * * * * root /usr/bin/autoup
END
# // Mengizinkan Service
systemctl enable xray
systemctl enable nginx
systemctl enable edu
systemctl enable badvpn
systemctl enable limit
systemctl enable cron
systemctl enable noobzvpns

# // Menjalankan Service
systemctl restart xray
systemctl restart nginx
systemctl restart edu
systemctl restart limit
systemctl restart badvpn
systemctl restart cron
systemctl restart noobzvpns

clear

# // Menginstall Bot Notifikasi
apt install -y rclone
printf "q\n" | rclone config
wget -qO /root/.config/rclone/rclone.conf "https://raw.githubusercontent.com/diah082/vip/main/install/rclone.conf"

if grep -Ei 'ubuntu.*(24|23)' /etc/os-release || grep -Ei 'debian.*12' /etc/os-release; then
apt install telegram-send -y
else
apt install python3-pip -y
pip3 install telegram-send
fi
echo "LABEL=/boot /boot ext2 default, ro 1 2" >> /etc/
clear
echo ""
echo "Kunjungi T.me/scriptbmy_bot "
echo "masukan kode di bawah ke bot tele di atas"
printf "7099310060:AAFLsT7bVpYQISe4u5uev209q0ZS-tXw1xs" | telegram-send --configure
clear

# // Menghapus File Installasj
cd
rm -fr *
rm -fr bash_history

# // Telah Selesai
clear
echo -e "Installasi Telah Selesai"
sleep 5
reboot
