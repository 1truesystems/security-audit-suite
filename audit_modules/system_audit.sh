#!/usr/bin/env bash
# =============================================================================
# System / Host Security Audit Module
# SSH, firewall, ports, services, permissions, users, cron, processes,
# logs, kernel security parameters
# =============================================================================

# =============================================================================
# SSH Configuration Audit
# =============================================================================
ssh_config_audit() {
    separator
    echo -e "${BOLD}${WHITE}  SSH Configuration Audit${NC}"
    separator

    local ssh_config="/etc/ssh/sshd_config"
    local ssh_dir="/etc/ssh/sshd_config.d"

    if [[ ! -f "$ssh_config" ]]; then
        log WARN "SSH config not found at $ssh_config"
        add_finding "INFO" "System" "SSH not installed" \
            "sshd_config not found - SSH server may not be installed" "N/A"
        return
    fi

    log INFO "Auditing SSH configuration"

    # Collect all config (main + includes)
    local all_config
    all_config="$(cat "$ssh_config" 2>/dev/null)"
    if [[ -d "$ssh_dir" ]]; then
        for f in "$ssh_dir"/*.conf; do
            [[ -f "$f" ]] && all_config+=$'\n'"$(cat "$f" 2>/dev/null)"
        done
    fi

    # Check PermitRootLogin
    local root_login
    root_login="$(echo "$all_config" | grep -i '^PermitRootLogin' | tail -1 | awk '{print $2}' || true)"
    if [[ -z "$root_login" || "$root_login" == "yes" || "$root_login" == "prohibit-password" ]]; then
        local severity="HIGH"
        [[ "$root_login" == "prohibit-password" ]] && severity="MEDIUM"
        add_finding "$severity" "System" "SSH root login permitted" \
            "PermitRootLogin is '${root_login:-yes (default)}'" \
            "Set 'PermitRootLogin no' in sshd_config"
        echo -e "  ${RED}[✗]${NC} PermitRootLogin: ${root_login:-yes (default)}"
    else
        echo -e "  ${GREEN}[✓]${NC} PermitRootLogin: $root_login"
    fi

    # Check PasswordAuthentication
    local pass_auth
    pass_auth="$(echo "$all_config" | grep -i '^PasswordAuthentication' | tail -1 | awk '{print $2}' || true)"
    if [[ -z "$pass_auth" || "$pass_auth" == "yes" ]]; then
        add_finding "MEDIUM" "System" "SSH password authentication enabled" \
            "PasswordAuthentication is '${pass_auth:-yes (default)}'" \
            "Set 'PasswordAuthentication no' and use key-based auth"
        echo -e "  ${YELLOW}[⚠]${NC} PasswordAuthentication: ${pass_auth:-yes (default)}"
    else
        echo -e "  ${GREEN}[✓]${NC} PasswordAuthentication: $pass_auth"
    fi

    # Check Protocol (legacy check)
    local protocol
    protocol="$(echo "$all_config" | grep -i '^Protocol' | tail -1 | awk '{print $2}' || true)"
    if [[ "$protocol" == "1" ]]; then
        add_finding "CRITICAL" "System" "SSH Protocol 1 enabled" \
            "SSH Protocol 1 is insecure and deprecated" \
            "Remove 'Protocol 1' or set 'Protocol 2'"
        echo -e "  ${RED}[✗]${NC} Protocol: 1 (INSECURE)"
    else
        echo -e "  ${GREEN}[✓]${NC} Protocol: ${protocol:-2 (default)}"
    fi

    # Check X11Forwarding
    local x11
    x11="$(echo "$all_config" | grep -i '^X11Forwarding' | tail -1 | awk '{print $2}' || true)"
    if [[ "$x11" == "yes" ]]; then
        add_finding "LOW" "System" "SSH X11 forwarding enabled" \
            "X11Forwarding is enabled" \
            "Set 'X11Forwarding no' unless required"
        echo -e "  ${YELLOW}[⚠]${NC} X11Forwarding: yes"
    else
        echo -e "  ${GREEN}[✓]${NC} X11Forwarding: ${x11:-no (default)}"
    fi

    # Check MaxAuthTries
    local max_auth
    max_auth="$(echo "$all_config" | grep -i '^MaxAuthTries' | tail -1 | awk '{print $2}' || true)"
    local max_auth_val="${max_auth:-6}"
    if (( max_auth_val > 4 )); then
        add_finding "LOW" "System" "SSH MaxAuthTries is high" \
            "MaxAuthTries is ${max_auth_val}" \
            "Set 'MaxAuthTries 3' to limit brute-force attempts"
        echo -e "  ${YELLOW}[⚠]${NC} MaxAuthTries: $max_auth_val"
    else
        echo -e "  ${GREEN}[✓]${NC} MaxAuthTries: $max_auth_val"
    fi

    # Check empty passwords
    local empty_pw
    empty_pw="$(echo "$all_config" | grep -i '^PermitEmptyPasswords' | tail -1 | awk '{print $2}' || true)"
    if [[ "$empty_pw" == "yes" ]]; then
        add_finding "CRITICAL" "System" "SSH allows empty passwords" \
            "PermitEmptyPasswords is yes" \
            "Set 'PermitEmptyPasswords no'"
        echo -e "  ${RED}[✗]${NC} PermitEmptyPasswords: yes"
    else
        echo -e "  ${GREEN}[✓]${NC} PermitEmptyPasswords: ${empty_pw:-no (default)}"
    fi

    # Check LoginGraceTime
    local grace
    grace="$(echo "$all_config" | grep -i '^LoginGraceTime' | tail -1 | awk '{print $2}' || true)"
    echo -e "  ${DIM}[•]${NC} LoginGraceTime: ${grace:-120 (default)}"

    # Check log level
    local loglevel
    loglevel="$(echo "$all_config" | grep -i '^LogLevel' | tail -1 | awk '{print $2}' || true)"
    if [[ "$loglevel" == "QUIET" ]]; then
        add_finding "MEDIUM" "System" "SSH logging is QUIET" \
            "SSH LogLevel is QUIET - security events not logged" \
            "Set 'LogLevel VERBOSE' for better audit trail"
        echo -e "  ${YELLOW}[⚠]${NC} LogLevel: QUIET"
    else
        echo -e "  ${GREEN}[✓]${NC} LogLevel: ${loglevel:-INFO (default)}"
    fi

    save_scan "ssh_config" "$all_config"
    log SUCCESS "SSH configuration audit complete"
}

# =============================================================================
# Firewall Rules Audit
# =============================================================================
firewall_rules_audit() {
    separator
    echo -e "${BOLD}${WHITE}  Firewall Rules Audit${NC}"
    separator

    local fw_found=0

    # Check UFW
    if command -v ufw &>/dev/null; then
        fw_found=1
        echo -e "\n${WHITE}UFW Status:${NC}"
        local ufw_status
        ufw_status="$(sudo ufw status verbose 2>/dev/null)" || \
            ufw_status="$(ufw status 2>/dev/null)" || \
            ufw_status="Unable to query UFW (needs root)"
        echo "$ufw_status"
        save_scan "ufw_status" "$ufw_status"

        if echo "$ufw_status" | grep -qi "inactive\|disabled"; then
            add_finding "HIGH" "System" "UFW firewall is inactive" \
                "UFW is installed but not enabled" \
                "Enable UFW: sudo ufw enable"
        else
            add_finding "INFO" "System" "UFW firewall is active" \
                "UFW is enabled and configured" "N/A"
        fi
    fi

    # Check iptables
    if command -v iptables &>/dev/null; then
        fw_found=1
        echo -e "\n${WHITE}iptables Rules:${NC}"
        local ipt_rules
        if [[ $EUID -eq 0 ]]; then
            ipt_rules="$(iptables -L -n -v --line-numbers 2>/dev/null)" || true
        else
            ipt_rules="$(sudo iptables -L -n -v --line-numbers 2>/dev/null)" || \
                ipt_rules="iptables requires root"
        fi
        echo "$ipt_rules"
        save_scan "iptables_rules" "$ipt_rules"

        local rule_count
        rule_count="$(echo "$ipt_rules" | grep -cE '^\s*[0-9]+' || true)"
        if [[ $rule_count -eq 0 ]]; then
            add_finding "HIGH" "System" "No iptables rules configured" \
                "iptables has no custom rules - all traffic allowed" \
                "Configure iptables rules or enable UFW/firewalld"
        fi
    fi

    # Check nftables
    if command -v nft &>/dev/null; then
        fw_found=1
        echo -e "\n${WHITE}nftables Ruleset:${NC}"
        local nft_rules
        if [[ $EUID -eq 0 ]]; then
            nft_rules="$(nft list ruleset 2>/dev/null)" || true
        else
            nft_rules="$(sudo nft list ruleset 2>/dev/null)" || \
                nft_rules="nftables requires root"
        fi
        echo "$nft_rules" | head -50
        save_scan "nftables_rules" "$nft_rules"
    fi

    if [[ $fw_found -eq 0 ]]; then
        add_finding "HIGH" "System" "No firewall software detected" \
            "No UFW, iptables, or nftables found" \
            "Install and configure a host-based firewall"
    fi

    log SUCCESS "Firewall rules audit complete"
}

# =============================================================================
# Open Ports Audit
# =============================================================================
open_ports_audit() {
    separator
    echo -e "${BOLD}${WHITE}  Open Ports Audit${NC}"
    separator

    log INFO "Enumerating listening ports"

    local ports_output
    if command -v ss &>/dev/null; then
        ports_output="$(ss -tulnp 2>/dev/null)" || true
    elif command -v netstat &>/dev/null; then
        ports_output="$(netstat -tulnp 2>/dev/null)" || true
    else
        log ERROR "Neither ss nor netstat available"
        return 1
    fi

    echo "$ports_output"
    save_scan "open_ports" "$ports_output"

    # Check for common risky ports
    local risky_ports=("21:FTP" "23:Telnet" "25:SMTP" "69:TFTP" "111:RPCbind" \
        "135:MSRPC" "139:NetBIOS" "445:SMB" "512:rexec" "513:rlogin" \
        "514:rsh" "1099:RMI" "3389:RDP" "5900:VNC" "6667:IRC")

    for entry in "${risky_ports[@]}"; do
        local port="${entry%%:*}"
        local name="${entry##*:}"
        if echo "$ports_output" | grep -qE ":${port}\s"; then
            add_finding "MEDIUM" "System" "Risky port open: $port ($name)" \
                "Port $port ($name) is listening on this host" \
                "Disable $name service if not required, or restrict access with firewall rules."
        fi
    done

    # Count total listening ports
    local listen_count
    listen_count="$(echo "$ports_output" | grep -c 'LISTEN\|UNCONN' || true)"
    echo -e "\n${WHITE}Total listening ports: ${listen_count}${NC}"

    if (( listen_count > 20 )); then
        add_finding "MEDIUM" "System" "High number of listening ports" \
            "${listen_count} ports are listening" \
            "Review and close unnecessary listening services."
    fi

    add_finding "INFO" "System" "Open Ports Audit Complete" \
        "${listen_count} listening ports enumerated" "N/A"

    log SUCCESS "Open ports audit complete"
}

# =============================================================================
# Running Services Audit
# =============================================================================
running_services_audit() {
    separator
    echo -e "${BOLD}${WHITE}  Running Services Audit${NC}"
    separator

    if ! command -v systemctl &>/dev/null; then
        log WARN "systemctl not available - cannot audit services"
        return 1
    fi

    log INFO "Enumerating active services"

    local services
    services="$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null)" || true
    echo "$services"
    save_scan "running_services" "$services"

    # Check for potentially unnecessary services
    local unnecessary=("avahi-daemon" "cups" "bluetooth" "rpcbind" \
        "telnet" "vsftpd" "xinetd" "inetd" "nfs-server" "smbd")

    echo -e "\n${WHITE}Checking for potentially unnecessary services:${NC}"
    for svc in "${unnecessary[@]}"; do
        if echo "$services" | grep -q "$svc"; then
            add_finding "LOW" "System" "Potentially unnecessary service: $svc" \
                "$svc is running on this system" \
                "Disable if not needed: sudo systemctl disable --now $svc"
            echo -e "  ${YELLOW}[⚠]${NC} $svc is running"
        fi
    done

    local svc_count
    svc_count="$(echo "$services" | grep -c '\.service' || true)"
    add_finding "INFO" "System" "Running Services Audit" \
        "${svc_count} services are running" "N/A"

    log SUCCESS "Running services audit complete"
}

# =============================================================================
# File Permission Audit
# =============================================================================
file_permission_audit() {
    separator
    echo -e "${BOLD}${WHITE}  File Permission Audit${NC}"
    separator

    # SUID files
    echo -e "\n${WHITE}SUID Files:${NC}"
    local suid_files
    suid_files="$(find / -perm -4000 -type f 2>/dev/null | head -50)" || true
    echo "$suid_files"
    save_scan "suid_files" "$suid_files"

    local suid_count
    suid_count="$(echo "$suid_files" | grep -c '/' || true)"
    if (( suid_count > 20 )); then
        add_finding "MEDIUM" "System" "High number of SUID binaries" \
            "${suid_count} SUID files found" \
            "Review SUID files and remove unnecessary SUID bits: chmod u-s <file>"
    fi

    # Check for unusual SUID binaries
    local known_suid=("passwd" "sudo" "su" "ping" "mount" "umount" "chsh" "chfn" \
        "newgrp" "gpasswd" "pkexec" "crontab" "ssh-agent" "fusermount")
    while IFS= read -r sfile; do
        [[ -z "$sfile" ]] && continue
        local basename_f
        basename_f="$(basename "$sfile")"
        local is_known=0
        for k in "${known_suid[@]}"; do
            [[ "$basename_f" == "$k" || "$basename_f" == "${k}3" ]] && is_known=1 && break
        done
        if [[ $is_known -eq 0 ]]; then
            add_finding "MEDIUM" "System" "Unusual SUID binary: $sfile" \
                "SUID bit set on non-standard binary" \
                "Investigate and remove SUID if not required: chmod u-s $sfile"
        fi
    done <<< "$suid_files"

    # SGID files
    echo -e "\n${WHITE}SGID Files:${NC}"
    local sgid_files
    sgid_files="$(find / -perm -2000 -type f 2>/dev/null | head -30)" || true
    echo "$sgid_files"

    # World-writable files (excluding /tmp, /var/tmp, /proc, /sys)
    echo -e "\n${WHITE}World-Writable Files (excluding temp dirs):${NC}"
    local ww_files
    ww_files="$(find / -xdev -perm -o+w -type f \
        ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/proc/*' \
        ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null | head -30)" || true
    if [[ -n "$ww_files" ]]; then
        echo "$ww_files"
        local ww_count
        ww_count="$(echo "$ww_files" | grep -c '/' || true)"
        add_finding "MEDIUM" "System" "World-writable files found" \
            "${ww_count} world-writable files detected" \
            "Remove world-writable permission: chmod o-w <file>"
    else
        echo -e "  ${GREEN}[✓]${NC} No world-writable files found"
    fi

    # Files with no owner
    echo -e "\n${WHITE}Files with No Owner:${NC}"
    local noowner
    noowner="$(find / -xdev -nouser -o -nogroup 2>/dev/null | head -20)" || true
    if [[ -n "$noowner" ]]; then
        echo "$noowner"
        add_finding "LOW" "System" "Files with no owner/group found" \
            "Orphaned files may indicate deleted user accounts" \
            "Assign proper ownership: chown user:group <file>"
    else
        echo -e "  ${GREEN}[✓]${NC} No orphaned files found"
    fi

    log SUCCESS "File permission audit complete"
}

# =============================================================================
# User Account Audit
# =============================================================================
user_account_audit() {
    separator
    echo -e "${BOLD}${WHITE}  User Account Audit${NC}"
    separator

    # Check for empty passwords
    echo -e "\n${WHITE}Checking for empty passwords:${NC}"
    local empty_pw
    empty_pw="$(awk -F: '($2 == "" || $2 == "!") && $1 != "root" {print $1}' /etc/shadow 2>/dev/null)" || \
        empty_pw="Cannot read /etc/shadow (needs root)"
    if [[ -n "$empty_pw" && "$empty_pw" != *"Cannot read"* ]]; then
        echo -e "  ${RED}[✗]${NC} Users with empty/no password: $empty_pw"
        add_finding "CRITICAL" "System" "Users with empty passwords" \
            "Accounts without passwords: $empty_pw" \
            "Set passwords for these accounts or lock them: passwd -l <user>"
    else
        echo -e "  ${GREEN}[✓]${NC} No empty passwords found"
    fi

    # Check for UID 0 accounts besides root
    echo -e "\n${WHITE}Checking for UID 0 accounts:${NC}"
    local uid0
    uid0="$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)" || true
    if [[ -n "$uid0" ]]; then
        echo -e "  ${RED}[✗]${NC} Non-root UID 0 accounts: $uid0"
        add_finding "CRITICAL" "System" "Non-root UID 0 accounts found" \
            "Accounts with UID 0: $uid0" \
            "Remove or change UID of non-root superuser accounts."
    else
        echo -e "  ${GREEN}[✓]${NC} No non-root UID 0 accounts"
    fi

    # Check password aging
    echo -e "\n${WHITE}Password Aging Policy:${NC}"
    local pass_max pass_min pass_warn
    pass_max="$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' || true)"
    pass_min="$(grep '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' || true)"
    pass_warn="$(grep '^PASS_WARN_AGE' /etc/login.defs 2>/dev/null | awk '{print $2}' || true)"

    echo -e "  Max password age: ${pass_max:-N/A} days"
    echo -e "  Min password age: ${pass_min:-N/A} days"
    echo -e "  Warning before expiry: ${pass_warn:-N/A} days"

    if [[ -n "$pass_max" ]] && (( pass_max > 90 || pass_max == 99999 )); then
        add_finding "MEDIUM" "System" "Weak password aging policy" \
            "PASS_MAX_DAYS is ${pass_max} (should be <= 90)" \
            "Set PASS_MAX_DAYS to 90 in /etc/login.defs"
    fi

    # Check sudoers for NOPASSWD
    echo -e "\n${WHITE}Checking sudoers for NOPASSWD:${NC}"
    local nopasswd
    nopasswd="$(grep -rI 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | \
        grep -v '^#\|^$' || true)"
    if [[ -n "$nopasswd" ]]; then
        echo -e "  ${YELLOW}[⚠]${NC} NOPASSWD entries found:"
        echo "$nopasswd" | while IFS= read -r line; do
            echo -e "      ${DIM}$line${NC}"
        done
        add_finding "MEDIUM" "System" "NOPASSWD sudo entries found" \
            "Sudo rules allow password-less privilege escalation" \
            "Remove NOPASSWD from sudoers unless absolutely required."
    else
        echo -e "  ${GREEN}[✓]${NC} No NOPASSWD entries"
    fi

    # List human users
    echo -e "\n${WHITE}User Accounts (UID >= 1000):${NC}"
    awk -F: '$3 >= 1000 && $3 < 65534 {printf "  %-20s UID:%-6s Shell:%s\n", $1, $3, $7}' \
        /etc/passwd 2>/dev/null || true

    log SUCCESS "User account audit complete"
}

# =============================================================================
# Cron Job Audit
# =============================================================================
cron_job_audit() {
    separator
    echo -e "${BOLD}${WHITE}  Cron Job Audit${NC}"
    separator

    log INFO "Auditing cron jobs"

    # System cron directories
    local cron_dirs=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" \
        "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")

    for cdir in "${cron_dirs[@]}"; do
        if [[ -f "$cdir" ]]; then
            echo -e "\n${WHITE}$cdir:${NC}"
            grep -v '^#\|^$\|^SHELL\|^PATH\|^MAILTO' "$cdir" 2>/dev/null || true
        elif [[ -d "$cdir" ]]; then
            echo -e "\n${WHITE}$cdir/:${NC}"
            ls -la "$cdir"/ 2>/dev/null || true
        fi
    done

    # User crontabs
    echo -e "\n${WHITE}User Crontabs:${NC}"
    local cron_spool="/var/spool/cron/crontabs"
    if [[ -d "$cron_spool" ]]; then
        for cf in "$cron_spool"/*; do
            if [[ -f "$cf" ]]; then
                local cuser
                cuser="$(basename "$cf")"
                echo -e "  ${CYAN}User: $cuser${NC}"
                cat "$cf" 2>/dev/null | grep -v '^#' || true
            fi
        done
    else
        # Try crontab -l for current user
        echo -e "  Current user crontab:"
        crontab -l 2>/dev/null || echo "  No crontab for current user"
    fi

    # Check for world-writable cron files
    local ww_cron
    ww_cron="$(find /etc/cron* /var/spool/cron -perm -o+w -type f 2>/dev/null)" || true
    if [[ -n "$ww_cron" ]]; then
        add_finding "HIGH" "System" "World-writable cron files" \
            "Cron files writable by anyone: $ww_cron" \
            "Fix permissions: chmod 644 on cron files"
        echo -e "  ${RED}[✗]${NC} World-writable cron files found!"
    fi

    add_finding "INFO" "System" "Cron Job Audit Complete" \
        "Reviewed system and user crontabs" "N/A"
    log SUCCESS "Cron job audit complete"
}

# =============================================================================
# Process Audit
# =============================================================================
process_audit() {
    separator
    echo -e "${BOLD}${WHITE}  Process Audit${NC}"
    separator

    log INFO "Auditing running processes"

    # Top resource consumers
    echo -e "\n${WHITE}Top CPU Consumers:${NC}"
    ps aux --sort=-%cpu 2>/dev/null | head -11 || true

    echo -e "\n${WHITE}Top Memory Consumers:${NC}"
    ps aux --sort=-%mem 2>/dev/null | head -11 || true

    # Processes running as root
    echo -e "\n${WHITE}Processes running as root:${NC}"
    local root_procs
    root_procs="$(ps aux 2>/dev/null | awk '$1 == "root" {print}' | wc -l)" || true
    echo -e "  Root processes: $root_procs"

    # Check for processes with suspicious names
    local suspicious=("nc " "ncat " "netcat " "socat " "msfconsole" "meterpreter" \
        "reverse" "bind.*shell" "cryptominer" "xmrig" "minerd")
    echo -e "\n${WHITE}Checking for suspicious processes:${NC}"
    local found_suspicious=0
    for pattern in "${suspicious[@]}"; do
        local match
        match="$(ps aux 2>/dev/null | grep -i "$pattern" | grep -v grep)" || true
        if [[ -n "$match" ]]; then
            echo -e "  ${RED}[✗]${NC} Suspicious process: $match"
            add_finding "HIGH" "System" "Suspicious process detected" \
                "Process matching '$pattern' found running" \
                "Investigate and terminate if unauthorized."
            found_suspicious=1
        fi
    done
    [[ $found_suspicious -eq 0 ]] && echo -e "  ${GREEN}[✓]${NC} No obvious suspicious processes"

    # Processes listening on network
    echo -e "\n${WHITE}Network-listening processes:${NC}"
    ss -tulnp 2>/dev/null | grep LISTEN || true

    save_scan "process_audit" "$(ps auxf 2>/dev/null)"
    log SUCCESS "Process audit complete"
}

# =============================================================================
# Log Analysis
# =============================================================================
log_analysis() {
    separator
    echo -e "${BOLD}${WHITE}  System Log Analysis${NC}"
    separator

    log INFO "Analyzing system logs"

    # Failed SSH logins
    echo -e "\n${WHITE}Failed SSH Login Attempts (last 50):${NC}"
    local auth_log="/var/log/auth.log"
    [[ ! -f "$auth_log" ]] && auth_log="/var/log/secure"

    if [[ -f "$auth_log" ]]; then
        local failed_logins
        failed_logins="$(grep -i 'failed password\|authentication failure' "$auth_log" 2>/dev/null | tail -50)" || true
        local fail_count
        fail_count="$(echo "$failed_logins" | grep -c 'Failed\|failure' || true)"
        echo -e "  Failed login attempts found: $fail_count"

        if (( fail_count > 100 )); then
            add_finding "HIGH" "System" "High number of failed logins" \
                "${fail_count} failed authentication attempts in auth.log" \
                "Investigate source IPs, consider fail2ban or IP blocking."
        elif (( fail_count > 20 )); then
            add_finding "MEDIUM" "System" "Multiple failed login attempts" \
                "${fail_count} failed authentication attempts" \
                "Monitor and consider implementing fail2ban."
        fi

        # Top source IPs for failed logins
        echo -e "\n${WHITE}Top failed login source IPs:${NC}"
        grep -i 'failed password' "$auth_log" 2>/dev/null | \
            grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
            sort | uniq -c | sort -rn | head -10 || true
        save_scan "failed_logins" "$failed_logins"
    else
        echo -e "  ${YELLOW}[⚠]${NC} Auth log not found"
    fi

    # Last logins
    echo -e "\n${WHITE}Last Logins:${NC}"
    last -n 15 2>/dev/null || true

    # Last failed logins
    echo -e "\n${WHITE}Last Failed Logins:${NC}"
    lastb -n 10 2>/dev/null || echo -e "  ${DIM}lastb requires root${NC}"

    # Kernel messages (errors/warnings)
    echo -e "\n${WHITE}Recent Kernel Warnings/Errors:${NC}"
    dmesg 2>/dev/null | grep -iE 'error|warn|fail|panic|oom' | tail -10 || \
        echo -e "  ${DIM}dmesg requires root or appropriate permissions${NC}"

    log SUCCESS "Log analysis complete"
}

# =============================================================================
# Kernel Security Audit
# =============================================================================
kernel_security_audit() {
    separator
    echo -e "${BOLD}${WHITE}  Kernel Security Parameters${NC}"
    separator

    log INFO "Checking kernel hardening parameters"

    # Define checks: param, expected, description
    local -a checks=(
        "net.ipv4.ip_forward|0|IP forwarding disabled"
        "net.ipv4.conf.all.send_redirects|0|ICMP redirects disabled"
        "net.ipv4.conf.all.accept_redirects|0|ICMP redirect acceptance disabled"
        "net.ipv4.conf.all.accept_source_route|0|Source routing disabled"
        "net.ipv4.conf.all.log_martians|1|Martian packet logging enabled"
        "net.ipv4.tcp_syncookies|1|SYN cookies enabled"
        "net.ipv4.icmp_echo_ignore_broadcasts|1|Broadcast ICMP ignored"
        "net.ipv4.conf.all.rp_filter|1|Reverse path filtering enabled"
        "net.ipv6.conf.all.accept_redirects|0|IPv6 redirects disabled"
        "kernel.randomize_va_space|2|Full ASLR enabled"
        "kernel.exec-shield|1|Exec-shield enabled"
        "kernel.dmesg_restrict|1|dmesg restricted to root"
        "kernel.kptr_restrict|1|Kernel pointer hiding enabled"
        "fs.suid_dumpable|0|SUID core dumps disabled"
        "fs.protected_hardlinks|1|Hardlink protection enabled"
        "fs.protected_symlinks|1|Symlink protection enabled"
    )

    local result_text=""
    for check in "${checks[@]}"; do
        IFS='|' read -r param expected desc <<< "$check"
        local actual
        actual="$(sysctl -n "$param" 2>/dev/null)" || actual="N/A"

        if [[ "$actual" == "N/A" ]]; then
            echo -e "  ${DIM}[−]${NC} $param = N/A (not available)"
        elif [[ "$actual" == "$expected" ]]; then
            echo -e "  ${GREEN}[✓]${NC} $param = $actual ($desc)"
        else
            echo -e "  ${RED}[✗]${NC} $param = $actual (expected: $expected - $desc)"
            add_finding "MEDIUM" "System" "Kernel hardening: $param" \
                "$param is $actual, expected $expected ($desc)" \
                "Set via: sysctl -w $param=$expected (persist in /etc/sysctl.d/)"
        fi
        result_text+="$param = $actual (expected: $expected)"$'\n'
    done

    save_scan "kernel_params" "$result_text"
    log SUCCESS "Kernel security audit complete"
}

# =============================================================================
# Full System Audit
# =============================================================================
full_system_audit() {
    log INFO "Starting full system/host security audit (LOCAL machine)"
    separator
    echo -e "${BOLD}${MAGENTA}  Running Full System Audit${NC}"
    if [[ "$AUDIT_MODE" == "remote" ]]; then
        echo -e "  ${YELLOW}[⚠] NOTE: System checks audit YOUR LOCAL machine, not the remote target.${NC}"
        echo -e "  ${YELLOW}    Findings below are about this host, not ${AUDIT_TARGET}.${NC}"
    fi
    separator

    ssh_config_audit;        echo ""
    firewall_rules_audit;    echo ""
    open_ports_audit;        echo ""
    running_services_audit;  echo ""
    file_permission_audit;   echo ""
    user_account_audit;      echo ""
    cron_job_audit;          echo ""
    process_audit;           echo ""
    log_analysis;            echo ""
    kernel_security_audit

    log SUCCESS "Full system audit complete"
    show_findings_summary
}

# =============================================================================
# System Audit Menu
# =============================================================================
system_audit_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}${WHITE}  System / Host Security Audit${NC}"
        echo -e "  ${DIM}(Audits YOUR LOCAL machine - not the remote target)${NC}"
        separator
        echo -e "  ${CYAN}[1]${NC}   SSH Configuration Audit"
        echo -e "  ${CYAN}[2]${NC}   Firewall Rules Audit"
        echo -e "  ${CYAN}[3]${NC}   Open Ports Audit"
        echo -e "  ${CYAN}[4]${NC}   Running Services Audit"
        echo -e "  ${CYAN}[5]${NC}   File Permission Audit (SUID/SGID)"
        echo -e "  ${CYAN}[6]${NC}   User Account Audit"
        echo -e "  ${CYAN}[7]${NC}   Cron Job Audit"
        echo -e "  ${CYAN}[8]${NC}   Process Audit"
        echo -e "  ${CYAN}[9]${NC}   Log Analysis"
        echo -e "  ${CYAN}[10]${NC}  Kernel Security Parameters"
        echo -e "  ${CYAN}[11]${NC}  Full System Audit (all above)"
        separator
        echo -e "  ${CYAN}[0]${NC}   Back to Main Menu"
        separator
        echo -e "${YELLOW}Select option [0-11]: ${NC}"
        read -r choice
        case "$choice" in
            1)  ssh_config_audit; press_enter ;;
            2)  firewall_rules_audit; press_enter ;;
            3)  open_ports_audit; press_enter ;;
            4)  running_services_audit; press_enter ;;
            5)  file_permission_audit; press_enter ;;
            6)  user_account_audit; press_enter ;;
            7)  cron_job_audit; press_enter ;;
            8)  process_audit; press_enter ;;
            9)  log_analysis; press_enter ;;
            10) kernel_security_audit; press_enter ;;
            11) full_system_audit; press_enter ;;
            0)  return ;;
            *)  log WARN "Invalid option"; sleep 1 ;;
        esac
    done
}
