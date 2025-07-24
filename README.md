# Ubuntu Server Hardening and Secure CI/CD Base Image

## Overview

This repository contains an automated Bash script that performs **comprehensive hardening of Ubuntu 20.04/22.04** systems. It is developed as part of a **DevSecOps Officer assignment** to demonstrate best practices in server security, audit configuration, and secure CI/CD foundation using GitLab Runner.

The hardened system serves as a secure base for hosting services like:
- GitLab Runner for CI/CD pipelines
- Lightweight NGINX reverse proxy
- PostgreSQL for secure app data storage

> Fully tested in a VirtualBox VM running **Ubuntu 20.04 LTS** with manual validation steps included.

---

## Features

### System & Package Hardening
- Removes unnecessary packages and updates all installed software
- Disables uncommon filesystems (cramfs, udf, squashfs)

### Network & Kernel Hardening
- Applies strict `sysctl` settings for IP spoofing, redirect denial, and buffer protection
- Disables packet forwarding and IPv6

### User Access & Authentication
- Enforces password aging policy globally (max age: 90 days, min: 10, warn: 7)
- Restricts use of `su` to the `sudo` group only
- Disables root login and enforces SSH key-based authentication

### File & Filesystem Security
- Secures permissions on sensitive files (`/etc/shadow`, `/etc/crontab`, `/boot`)
- Sets global `umask` to `027`
- Protects `/tmp` and `/var/tmp` with `noexec`, `nosuid`, `nodev` (if using separate partitions)

### AppArmor & Intrusion Detection
- Enables AppArmor profiles for enhanced LSM-based control
- Installs and configures `Fail2Ban` for SSH brute-force protection
- Installs and configures `auditd` for system activity auditing

### Firewall Configuration
- Uses `iptables` to allow only essential traffic:
  - TCP 22 (SSH)
  - TCP 80 & 443 (HTTP/HTTPS)
  - TCP/UDP 53 (DNS)
- Includes custom log rules for visibility

### Service Hardening
- **NGINX**: Configured with secure headers (HSTS, XSS, CSP, Referrer Policy)
- **PostgreSQL**:
  - Authentication via `scram-sha-256`
  - Listens only on `localhost`
  - Strong `pg_hba.conf` policy

### Audit & Compliance Tools
- **Lynis**: Runs a full system audit and saves report in HTML
- **Log validation**: Verifies logs from Fail2Ban, Auditd, and iptables

---

## Use Case: GitLab Runner on a Secure Host

This script prepares the system as a **security-hardened CI/CD runner host**. Benefits include:
- Reduced attack surface in CI/CD environments
- Enforced auditing for pipeline execution and service logs
- Secure communication via hardened NGINX proxy
- PostgreSQL secured with strong authentication

---

## How to Use

### 1. Clone Repository
    ```bash
    git clone https://github.com/yourusername/ubuntu-hardening.git
    cd ubuntu-hardening

## 2. Make Script Executable
    chmod +x harden.sh

## 3. Run the Script (as root)
    sudo ./harden.sh

--- 

## Post-Hardening Validation

    ## Lynis Audit Report
    sudo lynis audit system --quiet --auditor "DevSecOps Officer" --report-file /var/www/html/system_scan.html

    Open /var/www/html/system_scan.html in your browser to view full security scan results.

    ## Check Logs
    Auditd: /var/log/audit/audit.log

    Fail2Ban: /var/log/fail2ban.log

    Authentication: /var/log/auth.log

    iptables: journalctl -xe | grep IPTables

    # Simulate Failed Logins
    ssh wronguser@localhost
    # Check if Fail2Ban triggers after several failed attempts

    #Check Firewall Rules
    sudo iptables -L -v
---

(c) 2025 Emmanuel Seyram Buamah