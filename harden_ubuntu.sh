#!/bin/bash


#------------------------------
# Author: Emmanuel Seyram Buamah
# (c) 2025
#------------------------------


echo "[*] Starting system hardening..."

#------------------------------
# Utility: Install if missing
#------------------------------
install_if_missing() {
  if ! dpkg -s "$1" &> /dev/null; then
    echo "[*] Installing $1..."
    apt install -y "$1"
  fi
}

#------------------------------
# Update & Upgrade System
#------------------------------
echo "[*] Updating and upgrading the system..."
apt update && apt upgrade -y

#------------------------------
# Install essential tools
#------------------------------
install_if_missing curl
install_if_missing wget
install_if_missing gnupg
install_if_missing ca-certificates
install_if_missing lsb-release
install_if_missing software-properties-common
install_if_missing net-tools
install_if_missing openssh-server

#------------------------------
# Configure automatic security updates
#------------------------------
echo "[*] Configuring automatic security updates..."
install_if_missing unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades


#------------------------------
# Service, Process, and Logging Hardening
#------------------------------
echo "[*] Removing unnecessary services..."
apt purge -y xinetd telnet ftp tftp rsync || true
chmod 600 /etc/crontab
chmod 700 /etc/cron.{daily,hourly,monthly,weekly}
apt install -y rsyslog auditd
systemctl enable --now rsyslog
chmod 700 /boot
chmod 600 /etc/shadow
chmod 644 /etc/passwd


#------------------------------
# Kernel & Network Hardening
#------------------------------
echo "[*] Applying sysctl hardening settings..."
cat <<EOF >> /etc/sysctl.conf

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Enable IP forwarding protection
net.ipv4.ip_forward = 0
EOF

sysctl -p

#------------------------------
# Set file permission defaults
#------------------------------
echo "[*] Setting umask and permissions..."
sed -i 's/UMASK.*/UMASK 027/' /etc/login.defs
echo 'umask 027' >> /etc/profile

#------------------------------
# SSH & AppArmor
#------------------------------
echo "[*] Hardening SSH..."
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
systemctl restart sshd

install_if_missing apparmor
install_if_missing apparmor-profiles
install_if_missing apparmor-utils
aa-enforce /etc/apparmor.d/* || true

#-------------------------------------------
# Disable UFW to avoid conflict with iptables
#-------------------------------------------
echo "[*] Disabling UFW to prevent conflicts with iptables..."
ufw disable || true
systemctl stop ufw || true
systemctl disable ufw || true


#------------------------------------------------
# User & Authentication Hardening
#-------------------------------------------------------
echo "[*] Enforcing password and user policy..."
# Apply password aging policies to all human users (UID >= 1000 and not 'nobody')
for USERNAME in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
  echo "Setting password aging for $USERNAME"
  chage --maxdays 90 --mindays 10 --warndays 7 "$USERNAME"
done
awk -F: '($3 == 0) {print}' /etc/passwd
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers

#------------------------------
# Configure iptables
#------------------------------
echo "[*] Applying iptables rules..."
iptables -F
iptables -X

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT                         
iptables -A OUTPUT -o lo -j ACCEPT                         

# Drop packets claiming to be from loopback but not on loopback
iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j DROP           

# Allow established and related
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP (ping)
iptables -A INPUT -p icmp -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT              

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT            

# Allow DNS (UDP and TCP)
iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP   

# Log and drop everything else
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A INPUT -j DROP

# Save iptables rules
install_if_missing iptables-persistent
netfilter-persistent save

#------------------------------
# Install and configure Fail2Ban
#------------------------------
echo "[*] Installing and configuring Fail2Ban..."
install_if_missing fail2ban

cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban
systemctl restart fail2ban

#------------------------------
# Install and configure Auditd
#------------------------------
echo "[*] Installing and enabling auditd..."
install_if_missing auditd
install_if_missing audispd-plugins

systemctl enable auditd
systemctl start auditd

#------------------------------
# Install and Harden NGINX
#------------------------------
echo "[*] Installing and hardening NGINX..."
install_if_missing nginx
systemctl enable nginx
systemctl start nginx

# NGINX hardening headers
NGINX_CONF="/etc/nginx/snippets/security-headers.conf"
cat <<EOF > "$NGINX_CONF"
add_header X-Content-Type-Options "nosniff";
add_header X-Frame-Options "SAMEORIGIN";
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "no-referrer-when-downgrade";
add_header Content-Security-Policy "default-src 'self';";
EOF

# Update default server block
DEFAULT_SITE="/etc/nginx/sites-available/default"
sed -i "/server {/a \\    include snippets/security-headers.conf;" "$DEFAULT_SITE"

nginx -t && systemctl reload nginx

#------------------------------
# Harden PostgreSQL configuration
#------------------------------
PG_VERSION=$(psql -V | awk '{print $3}' | cut -d. -f1)
PG_CONF="/etc/postgresql/$PG_VERSION/main/postgresql.conf"
HBA_CONF="/etc/postgresql/$PG_VERSION/main/pg_hba.conf"

# Only modify if config files exist
if [[ -f "$PG_CONF" && -f "$HBA_CONF" ]]; then
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/g" "$PG_CONF"
    sed -i "s/^host.*all.*all.*127.0.0.1\/32.*md5/host all all 127.0.0.1\/32 scram-sha-256/" "$HBA_CONF"
    sed -i "s/^host.*all.*all.*::1\/128.*md5/host all all ::1\/128 scram-sha-256/" "$HBA_CONF"
    systemctl restart postgresql
else
    echo "PostgreSQL config files not found for version $PG_VERSION"
fi


#------------------------------
# Install system scan tools
#------------------------------
echo "[*] Installing Lynis and ansi2html..."
install_if_missing git
install_if_missing python3-pip
pip3 install ansi2html

# Clone Lynis if not already installed
if [ ! -d /opt/lynis ]; then
  git clone https://github.com/CISOfy/lynis /opt/lynis
fi

#------------------------------
# Run system scan (final step)
#------------------------------
echo "[*] Running system scan..."
cd /opt/lynis
./lynis audit system | tee /var/log/lynis-report.txt | ansi2html -t "System Scan Report - dev" > /var/www/html/system_scan.html

echo "[✓] Hardening complete. Review scan at: /var/www/html/system_scan.html"
