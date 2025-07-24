#!/bin/bash


#Author: Emmanuel Seyram Buamah
#(c) 2025

set -euo pipefail
echo "[+] Starting full system hardening for Ubuntu 20.04..."

# --- Phase 1: Automated Security Updates ---
echo "[*] Enabling unattended security updates..."
apt update && apt upgrade -y
apt install -y unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades

# --- Phase 2: Kernel and Network Parameter Hardening ---
echo "[*] Applying kernel and network parameter hardening..."
cat >> /etc/sysctl.conf <<EOF
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
EOF
sysctl -p

# --- Phase 3: User & Authentication Hardening ---
echo "[*] Enforcing password and user policy..."
# Apply password aging policies to all human users (UID >= 1000 and not 'nobody')
for USERNAME in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
  echo "Setting password aging for $USERNAME"
  chage --maxdays 90 --mindays 10 --warndays 7 "$USERNAME"
done
awk -F: '($3 == 0) {print}' /etc/passwd
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers

# --- Phase 4: Service, Process, and Logging Hardening ---
echo "[*] Removing unnecessary services..."
apt purge -y xinetd telnet ftp tftp rsync
chmod 600 /etc/crontab
chmod 700 /etc/cron.{daily,hourly,monthly,weekly}
apt install -y rsyslog auditd
systemctl enable --now rsyslog
systemctl enable --now auditd
chmod 700 /boot
chmod 600 /etc/shadow
chmod 644 /etc/passwd

# --- Phase 5: SSH, AppArmor, and Fail2Ban ---
echo "[*] Hardening SSH..."
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
echo "AllowUsers $USERNAME" >> /etc/ssh/sshd_config
systemctl restart sshd

echo "[*] Enabling AppArmor..."
apt install -y apparmor apparmor-profiles apparmor-utils
aa-enforce /etc/apparmor.d/* || true

echo "[*] Configuring Fail2Ban..."
apt install -y fail2ban
systemctl enable --now fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
cat >> /etc/fail2ban/jail.local <<EOF

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
maxretry = 5
EOF

# --- Phase 6: Firewall Configuration with iptables ---
echo "[*] Setting up iptables firewall rules..."
iptables -F
iptables -X
#Set defaults (deny all incomming connections)
iptables -P INPUT DROP
#Set defaults (deny all routing connection through this system)
iptables -P FORWARD DROP
#Allow all outbound traffic
iptables -P OUTPUT ACCEPT
#Allow all traffic on the local host (loopback interface)
iptables -A INPUT -i lo -j ACCEPT
#Allow ssh connection from anywhere
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#Allow htt/https
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#Allow DNS tcp
iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#Allow DNS udp
iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#Log all traffics
iptables -A INPUT -j LOG --log-prefix "iptables-dropped: " --log-level 4
#Save the rules so they do not disappear when the server restarts
apt install -y iptables-persistent
netfilter-persistent save

# --- Phase 7: PostgreSQL Hardening ---
echo "[*] Installing and hardening PostgreSQL..."
apt install -y postgresql postgresql-contrib
PG_CONF="/etc/postgresql/14/main/postgresql.conf"
HBA_CONF="/etc/postgresql/14/main/pg_hba.conf"
sed -i "s/^#*listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF"
echo "ssl = on" >> "$PG_CONF"
cat > "$HBA_CONF" <<EOF
local   all             all                                     peer
host    all             all             127.0.0.1/32            md5
hostssl all             all             ::1/128                 md5
EOF
systemctl restart postgresql
echo " Run the following commands to create user and password....."
echo '
sudo -u postgres psql -c "CREATE USER secure_user WITH PASSWORD '\''StrongPasswordHere'\'';"
sudo -u postgres psql -c "ALTER ROLE secure_user SET client_min_messages TO WARNING;"
sudo -u postgres psql -c "REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;"
'

# --- Phase 8: Vulnerability Scanning with Lynis ---
echo "[*] Installing and running Lynis..."
cd /opt/
git clone https://github.com/CISOfy/lynis.git
cd lynis
ln -s "$(pwd)/lynis" /usr/sbin/lynis
/usr/sbin/lynis audit system | tee /var/log/lynis-audit.log
apt install -y ansi2html
/usr/sbin/lynis audit system | ansi2html -t "System Scan Report - dev" > /var/www/html/system_scan.html

# --- Phase 9: NGINX Web Server Hardening ---
echo "[*] Installing and hardening NGINX..."
apt install -y nginx
sed -i 's/^user .*;/user www-data;/' /etc/nginx/nginx.conf
sed -i 's/^.*server_tokens.*;/server_tokens off;/' /etc/nginx/nginx.conf

cat >> /etc/nginx/nginx.conf <<EOF
location ~ /\. {
    deny all;
}

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

limit_req_zone \$binary_remote_addr zone=req_limit_per_ip:10m rate=1r/s;
client_max_body_size 1M;sudo

access_log /var/log/nginx/access.log;
error_log /var/log/nginx/error.log warn;
EOF

systemctl restart nginx

echo "[✓] Ubuntu 20.04 hardening complete."
