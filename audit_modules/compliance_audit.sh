#!/usr/bin/env bash
# =============================================================================
# Compliance & CIS Benchmark Audit Module
# CIS Level 1 & 2 checks: filesystem, services, network, firewall,
# logging, access control, authentication, banners, file integrity
# =============================================================================

# CIS check counters
declare -i CIS_PASS=0
declare -i CIS_FAIL=0
declare -i CIS_WARN=0
declare -i CIS_TOTAL=0

cis_result() {
    local status="$1"  # PASS, FAIL, WARN
    local id="$2"
    local description="$3"
    local detail="${4:-}"
    local remediation="${5:-}"

    CIS_TOTAL+=1

    case "$status" in
        PASS)
            CIS_PASS+=1
            echo -e "  ${GREEN}[PASS]${NC} $id - $description"
            ;;
        FAIL)
            CIS_FAIL+=1
            echo -e "  ${RED}[FAIL]${NC} $id - $description"
            [[ -n "$detail" ]] && echo -e "         ${DIM}$detail${NC}"
            add_finding "MEDIUM" "CIS" "$id: $description" "$detail" "$remediation"
            ;;
        WARN)
            CIS_WARN+=1
            echo -e "  ${YELLOW}[WARN]${NC} $id - $description"
            [[ -n "$detail" ]] && echo -e "         ${DIM}$detail${NC}"
            add_finding "LOW" "CIS" "$id: $description" "$detail" "$remediation"
            ;;
    esac
}

# =============================================================================
# CIS 1 - Filesystem Configuration
# =============================================================================
cis_filesystem() {
    separator
    echo -e "${BOLD}${WHITE}  CIS Section 1: Filesystem Configuration${NC}"
    separator

    # 1.1.1 - Disable cramfs
    if lsmod 2>/dev/null | grep -q cramfs; then
        cis_result "FAIL" "1.1.1" "Disable cramfs" \
            "cramfs module is loaded" \
            "Add 'install cramfs /bin/true' to /etc/modprobe.d/cramfs.conf"
    else
        cis_result "PASS" "1.1.1" "cramfs disabled"
    fi

    # 1.1.2 - Disable freevxfs
    if lsmod 2>/dev/null | grep -q freevxfs; then
        cis_result "FAIL" "1.1.2" "Disable freevxfs" \
            "freevxfs module is loaded" \
            "Add 'install freevxfs /bin/true' to /etc/modprobe.d/"
    else
        cis_result "PASS" "1.1.2" "freevxfs disabled"
    fi

    # 1.1.3 - Disable hfs
    if lsmod 2>/dev/null | grep -q hfs; then
        cis_result "FAIL" "1.1.3" "Disable hfs" \
            "hfs module is loaded" \
            "Add 'install hfs /bin/true' to /etc/modprobe.d/"
    else
        cis_result "PASS" "1.1.3" "hfs disabled"
    fi

    # 1.1.4 - Disable hfsplus
    if lsmod 2>/dev/null | grep -q hfsplus; then
        cis_result "FAIL" "1.1.4" "Disable hfsplus" \
            "hfsplus module is loaded" \
            "Add 'install hfsplus /bin/true' to /etc/modprobe.d/"
    else
        cis_result "PASS" "1.1.4" "hfsplus disabled"
    fi

    # 1.1.5 - Disable udf
    if lsmod 2>/dev/null | grep -q udf; then
        cis_result "FAIL" "1.1.5" "Disable udf" \
            "udf module is loaded" \
            "Add 'install udf /bin/true' to /etc/modprobe.d/"
    else
        cis_result "PASS" "1.1.5" "udf disabled"
    fi

    # 1.1.6 - /tmp separate partition
    if mount 2>/dev/null | grep -q ' /tmp '; then
        cis_result "PASS" "1.1.6" "/tmp is a separate partition"
    else
        cis_result "WARN" "1.1.6" "/tmp is not a separate partition" \
            "/tmp should be on a separate partition" \
            "Create a separate partition or use tmpfs for /tmp"
    fi

    # 1.1.7 - /tmp nodev
    if mount 2>/dev/null | grep ' /tmp ' | grep -q 'nodev'; then
        cis_result "PASS" "1.1.7" "/tmp has nodev option"
    elif mount 2>/dev/null | grep -q ' /tmp '; then
        cis_result "FAIL" "1.1.7" "/tmp missing nodev option" \
            "nodev not set on /tmp mount" \
            "Add nodev to /tmp mount options in /etc/fstab"
    else
        cis_result "WARN" "1.1.7" "/tmp nodev - N/A (not separate partition)"
    fi

    # 1.1.8 - /tmp nosuid
    if mount 2>/dev/null | grep ' /tmp ' | grep -q 'nosuid'; then
        cis_result "PASS" "1.1.8" "/tmp has nosuid option"
    elif mount 2>/dev/null | grep -q ' /tmp '; then
        cis_result "FAIL" "1.1.8" "/tmp missing nosuid option" \
            "nosuid not set on /tmp mount" \
            "Add nosuid to /tmp mount options in /etc/fstab"
    else
        cis_result "WARN" "1.1.8" "/tmp nosuid - N/A (not separate partition)"
    fi

    # 1.1.14 - /home separate partition
    if mount 2>/dev/null | grep -q ' /home '; then
        cis_result "PASS" "1.1.14" "/home is a separate partition"
    else
        cis_result "WARN" "1.1.14" "/home is not a separate partition" \
            "/home should ideally be on a separate partition" \
            "Consider creating a separate partition for /home"
    fi

    # 1.1.15 - /var separate partition
    if mount 2>/dev/null | grep -q ' /var '; then
        cis_result "PASS" "1.1.15" "/var is a separate partition"
    else
        cis_result "WARN" "1.1.15" "/var is not a separate partition" \
            "/var should be on a separate partition" \
            "Create a separate partition for /var"
    fi

    # 1.1.16 - /var/log separate partition
    if mount 2>/dev/null | grep -q ' /var/log '; then
        cis_result "PASS" "1.1.16" "/var/log is a separate partition"
    else
        cis_result "WARN" "1.1.16" "/var/log is not a separate partition" \
            "/var/log should be on a separate partition to prevent log flooding DoS" \
            "Create a separate partition for /var/log"
    fi

    # 1.4.1 - Permissions on bootloader config
    local grub_cfg="/boot/grub/grub.cfg"
    [[ ! -f "$grub_cfg" ]] && grub_cfg="/boot/grub2/grub.cfg"
    if [[ -f "$grub_cfg" ]]; then
        local grub_perm
        grub_perm="$(stat -c '%a' "$grub_cfg" 2>/dev/null)" || true
        if [[ "$grub_perm" == "400" || "$grub_perm" == "600" ]]; then
            cis_result "PASS" "1.4.1" "Bootloader config permissions: $grub_perm"
        else
            cis_result "FAIL" "1.4.1" "Bootloader config permissions too open" \
                "grub.cfg permissions: $grub_perm (should be 400 or 600)" \
                "chmod 600 $grub_cfg"
        fi
    fi

    log SUCCESS "CIS Filesystem checks complete"
}

# =============================================================================
# CIS 2 - Services
# =============================================================================
cis_services() {
    separator
    echo -e "${BOLD}${WHITE}  CIS Section 2: Services${NC}"
    separator

    # Check for unnecessary services
    local services_to_check=(
        "xinetd:2.1.1:Ensure xinetd is not installed"
        "openbsd-inetd:2.1.2:Ensure inetd is not installed"
        "avahi-daemon:2.2.3:Ensure Avahi is not enabled"
        "cups:2.2.4:Ensure CUPS is not enabled"
        "rpcbind:2.2.6:Ensure RPC is not enabled"
        "slapd:2.2.7:Ensure LDAP server is not enabled"
        "nfs-kernel-server:2.2.8:Ensure NFS is not enabled"
        "bind9:2.2.9:Ensure DNS server is not enabled"
        "vsftpd:2.2.10:Ensure FTP server is not enabled"
        "apache2:2.2.11:Ensure HTTP server is not enabled"
        "dovecot:2.2.12:Ensure IMAP/POP3 is not enabled"
        "smbd:2.2.13:Ensure Samba is not enabled"
        "squid:2.2.14:Ensure HTTP Proxy is not enabled"
        "snmpd:2.2.15:Ensure SNMP is not enabled"
    )

    for entry in "${services_to_check[@]}"; do
        IFS=: read -r svc cis_id desc <<< "$entry"
        if systemctl is-active "$svc" &>/dev/null; then
            cis_result "FAIL" "$cis_id" "$desc" \
                "$svc is running" \
                "Disable: sudo systemctl disable --now $svc"
        elif systemctl is-enabled "$svc" &>/dev/null 2>&1; then
            cis_result "WARN" "$cis_id" "$desc" \
                "$svc is enabled but not running" \
                "Disable: sudo systemctl disable $svc"
        else
            cis_result "PASS" "$cis_id" "$desc"
        fi
    done

    # 2.3 - Ensure telnet client is not installed
    if dpkg -l 2>/dev/null | grep -q 'telnet ' || rpm -q telnet &>/dev/null; then
        cis_result "FAIL" "2.3.1" "Ensure telnet client is not installed" \
            "telnet client package is installed" \
            "Remove: sudo apt remove telnet"
    else
        cis_result "PASS" "2.3.1" "telnet client not installed"
    fi

    # 2.3.2 - Ensure rsh client is not installed
    if dpkg -l 2>/dev/null | grep -qE 'rsh-client|rsh ' || rpm -q rsh &>/dev/null; then
        cis_result "FAIL" "2.3.2" "Ensure rsh client is not installed" \
            "rsh client package is installed" \
            "Remove: sudo apt remove rsh-client"
    else
        cis_result "PASS" "2.3.2" "rsh client not installed"
    fi

    log SUCCESS "CIS Services checks complete"
}

# =============================================================================
# CIS 3 - Network Parameters
# =============================================================================
cis_network_params() {
    separator
    echo -e "${BOLD}${WHITE}  CIS Section 3: Network Parameters${NC}"
    separator

    local -a net_checks=(
        "net.ipv4.ip_forward|0|3.1.1|Ensure IP forwarding is disabled"
        "net.ipv4.conf.all.send_redirects|0|3.1.2|Ensure ICMP redirects are not sent"
        "net.ipv4.conf.default.send_redirects|0|3.1.2|Ensure default ICMP redirects are not sent"
        "net.ipv4.conf.all.accept_source_route|0|3.2.1|Ensure source routed packets not accepted"
        "net.ipv4.conf.default.accept_source_route|0|3.2.1|Ensure default source route disabled"
        "net.ipv4.conf.all.accept_redirects|0|3.2.2|Ensure ICMP redirects not accepted"
        "net.ipv4.conf.default.accept_redirects|0|3.2.2|Ensure default ICMP redirects not accepted"
        "net.ipv4.conf.all.secure_redirects|0|3.2.3|Ensure secure ICMP redirects not accepted"
        "net.ipv4.conf.all.log_martians|1|3.2.4|Ensure suspicious packets are logged"
        "net.ipv4.conf.default.log_martians|1|3.2.4|Ensure default martian logging enabled"
        "net.ipv4.icmp_echo_ignore_broadcasts|1|3.2.5|Ensure broadcast ICMP requests ignored"
        "net.ipv4.icmp_ignore_bogus_error_responses|1|3.2.6|Ensure bogus ICMP responses ignored"
        "net.ipv4.conf.all.rp_filter|1|3.2.7|Ensure reverse path filtering enabled"
        "net.ipv4.tcp_syncookies|1|3.2.8|Ensure TCP SYN cookies enabled"
        "net.ipv6.conf.all.accept_redirects|0|3.3.2|Ensure IPv6 redirects not accepted"
        "net.ipv6.conf.all.accept_ra|0|3.3.1|Ensure IPv6 router advertisements not accepted"
    )

    for check in "${net_checks[@]}"; do
        IFS='|' read -r param expected cis_id desc <<< "$check"
        local actual
        actual="$(sysctl -n "$param" 2>/dev/null)" || actual="N/A"

        if [[ "$actual" == "N/A" ]]; then
            cis_result "WARN" "$cis_id" "$desc" \
                "$param not available" ""
        elif [[ "$actual" == "$expected" ]]; then
            cis_result "PASS" "$cis_id" "$desc"
        else
            cis_result "FAIL" "$cis_id" "$desc" \
                "$param = $actual (expected $expected)" \
                "sysctl -w $param=$expected && echo '$param = $expected' >> /etc/sysctl.d/99-cis.conf"
        fi
    done

    log SUCCESS "CIS Network Parameters checks complete"
}

# =============================================================================
# CIS 3.5 - Firewall
# =============================================================================
cis_firewall() {
    separator
    echo -e "${BOLD}${WHITE}  CIS Section 3.5: Firewall Configuration${NC}"
    separator

    # 3.5.1 - Ensure firewall is installed
    local fw_installed=0
    if command -v ufw &>/dev/null; then
        cis_result "PASS" "3.5.1.1" "UFW is installed"
        fw_installed=1

        # Check if enabled
        if ufw status 2>/dev/null | grep -qi 'active'; then
            cis_result "PASS" "3.5.1.2" "UFW is enabled"
        else
            cis_result "FAIL" "3.5.1.2" "UFW is not enabled" \
                "UFW is installed but inactive" \
                "Enable: sudo ufw enable"
        fi

        # Check default deny
        local ufw_default
        ufw_default="$(ufw status verbose 2>/dev/null | grep 'Default:' || true)"
        if echo "$ufw_default" | grep -qi 'deny (incoming)'; then
            cis_result "PASS" "3.5.1.3" "UFW default deny incoming"
        else
            cis_result "FAIL" "3.5.1.3" "UFW default not deny incoming" \
                "Default incoming policy should be deny" \
                "sudo ufw default deny incoming"
        fi
    elif command -v nft &>/dev/null; then
        cis_result "PASS" "3.5.1.1" "nftables is installed"
        fw_installed=1
    elif command -v iptables &>/dev/null; then
        cis_result "PASS" "3.5.1.1" "iptables is installed"
        fw_installed=1

        # Check default policies
        local input_policy
        input_policy="$(iptables -L INPUT 2>/dev/null | head -1 | awk '{print $NF}' | tr -d '()' || true)"
        if [[ "$input_policy" == "DROP" || "$input_policy" == "REJECT" ]]; then
            cis_result "PASS" "3.5.1.3" "iptables INPUT default DROP/REJECT"
        else
            cis_result "FAIL" "3.5.1.3" "iptables INPUT default not DROP" \
                "INPUT chain policy is $input_policy" \
                "iptables -P INPUT DROP"
        fi
    fi

    if [[ $fw_installed -eq 0 ]]; then
        cis_result "FAIL" "3.5.1.1" "No firewall software installed" \
            "No UFW, nftables, or iptables found" \
            "Install and configure a firewall: sudo apt install ufw"
    fi

    log SUCCESS "CIS Firewall checks complete"
}

# =============================================================================
# CIS 4 - Logging
# =============================================================================
cis_logging() {
    separator
    echo -e "${BOLD}${WHITE}  CIS Section 4: Logging & Auditing${NC}"
    separator

    # 4.1.1 - Ensure auditd is installed
    if command -v auditd &>/dev/null || dpkg -l 2>/dev/null | grep -q auditd; then
        cis_result "PASS" "4.1.1" "auditd is installed"

        if systemctl is-active auditd &>/dev/null; then
            cis_result "PASS" "4.1.2" "auditd is running"
        else
            cis_result "FAIL" "4.1.2" "auditd is not running" \
                "auditd installed but not active" \
                "sudo systemctl enable --now auditd"
        fi
    else
        cis_result "WARN" "4.1.1" "auditd is not installed" \
            "auditd provides detailed system auditing" \
            "sudo apt install auditd"
    fi

    # 4.2.1 - Ensure rsyslog or journald is configured
    if systemctl is-active rsyslog &>/dev/null; then
        cis_result "PASS" "4.2.1.1" "rsyslog is running"
    elif systemctl is-active systemd-journald &>/dev/null; then
        cis_result "PASS" "4.2.1.1" "systemd-journald is running"
    else
        cis_result "FAIL" "4.2.1.1" "No logging service active" \
            "Neither rsyslog nor journald is running" \
            "Enable logging: sudo systemctl enable --now rsyslog"
    fi

    # 4.2.1.3 - Ensure rsyslog default file permissions
    if [[ -f "/etc/rsyslog.conf" ]]; then
        local file_create_mode
        file_create_mode="$(grep '^\$FileCreateMode' /etc/rsyslog.conf 2>/dev/null | \
            awk '{print $2}' || true)"
        if [[ "$file_create_mode" == "0640" || "$file_create_mode" == "0600" ]]; then
            cis_result "PASS" "4.2.1.3" "rsyslog file permissions: $file_create_mode"
        elif [[ -n "$file_create_mode" ]]; then
            cis_result "FAIL" "4.2.1.3" "rsyslog file permissions too open" \
                "FileCreateMode is $file_create_mode (should be 0640)" \
                "Set \$FileCreateMode 0640 in /etc/rsyslog.conf"
        else
            cis_result "WARN" "4.2.1.3" "rsyslog FileCreateMode not explicitly set"
        fi
    fi

    # 4.2.2.1 - Ensure journald configured to send to rsyslog
    if [[ -f "/etc/systemd/journald.conf" ]]; then
        if grep -qE '^ForwardToSyslog=yes' /etc/systemd/journald.conf 2>/dev/null; then
            cis_result "PASS" "4.2.2.1" "journald forwards to syslog"
        else
            cis_result "WARN" "4.2.2.1" "journald not forwarding to syslog" \
                "Set ForwardToSyslog=yes for persistent logging" \
                "Set ForwardToSyslog=yes in /etc/systemd/journald.conf"
        fi

        # 4.2.2.2 - Ensure journald configured to compress
        if grep -qE '^Compress=yes' /etc/systemd/journald.conf 2>/dev/null; then
            cis_result "PASS" "4.2.2.2" "journald compression enabled"
        else
            cis_result "WARN" "4.2.2.2" "journald compression not enabled" \
                "Set Compress=yes for disk space savings" \
                "Set Compress=yes in /etc/systemd/journald.conf"
        fi

        # 4.2.2.3 - Ensure journald configured for persistent storage
        if grep -qE '^Storage=persistent' /etc/systemd/journald.conf 2>/dev/null; then
            cis_result "PASS" "4.2.2.3" "journald persistent storage enabled"
        else
            cis_result "WARN" "4.2.2.3" "journald not configured for persistent storage" \
                "Logs may be lost on reboot" \
                "Set Storage=persistent in /etc/systemd/journald.conf"
        fi
    fi

    # Check log rotation
    if [[ -f "/etc/logrotate.conf" ]]; then
        cis_result "PASS" "4.3" "logrotate is configured"
    else
        cis_result "WARN" "4.3" "logrotate not configured" \
            "Log rotation prevents disk space exhaustion" \
            "Install and configure logrotate"
    fi

    log SUCCESS "CIS Logging checks complete"
}

# =============================================================================
# CIS 5 - Access Control
# =============================================================================
cis_access_control() {
    separator
    echo -e "${BOLD}${WHITE}  CIS Section 5: Access, Auth & Authorization${NC}"
    separator

    # 5.2.1 - Ensure permissions on /etc/ssh/sshd_config
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        local ssh_perm
        ssh_perm="$(stat -c '%a' /etc/ssh/sshd_config 2>/dev/null)" || true
        if [[ "$ssh_perm" == "600" || "$ssh_perm" == "644" ]]; then
            cis_result "PASS" "5.2.1" "sshd_config permissions: $ssh_perm"
        else
            cis_result "FAIL" "5.2.1" "sshd_config permissions too open" \
                "Permissions: $ssh_perm (should be 600)" \
                "chmod 600 /etc/ssh/sshd_config"
        fi
    fi

    # 5.2.2 - Ensure SSH Protocol is 2
    local ssh_protocol
    ssh_protocol="$(grep '^Protocol' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)"
    if [[ "$ssh_protocol" == "1" ]]; then
        cis_result "FAIL" "5.2.2" "SSH Protocol 1 enabled" \
            "SSH Protocol version 1 is insecure" \
            "Set Protocol 2 in sshd_config"
    else
        cis_result "PASS" "5.2.2" "SSH Protocol 2 (or default)"
    fi

    # 5.2.5 - Ensure SSH MaxAuthTries <= 4
    local max_auth
    max_auth="$(grep '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)"
    local max_auth_val="${max_auth:-6}"
    if (( max_auth_val <= 4 )); then
        cis_result "PASS" "5.2.5" "SSH MaxAuthTries: $max_auth_val"
    else
        cis_result "FAIL" "5.2.5" "SSH MaxAuthTries too high: $max_auth_val" \
            "Should be 4 or less" \
            "Set MaxAuthTries 4 in sshd_config"
    fi

    # 5.2.8 - Ensure SSH root login is disabled
    local root_login
    root_login="$(grep '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)"
    if [[ "$root_login" == "no" ]]; then
        cis_result "PASS" "5.2.8" "SSH root login disabled"
    else
        cis_result "FAIL" "5.2.8" "SSH root login not disabled" \
            "PermitRootLogin is ${root_login:-yes (default)}" \
            "Set PermitRootLogin no in sshd_config"
    fi

    # 5.2.10 - Ensure SSH PermitEmptyPasswords is disabled
    local empty_pw
    empty_pw="$(grep '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)"
    if [[ "$empty_pw" == "yes" ]]; then
        cis_result "FAIL" "5.2.10" "SSH permits empty passwords" \
            "PermitEmptyPasswords is yes" \
            "Set PermitEmptyPasswords no in sshd_config"
    else
        cis_result "PASS" "5.2.10" "SSH empty passwords disabled"
    fi

    # 5.2.11 - Ensure SSH PermitUserEnvironment is disabled
    local user_env
    user_env="$(grep '^PermitUserEnvironment' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)"
    if [[ "$user_env" == "yes" ]]; then
        cis_result "FAIL" "5.2.11" "SSH PermitUserEnvironment enabled" \
            "Users can set environment variables via SSH" \
            "Set PermitUserEnvironment no in sshd_config"
    else
        cis_result "PASS" "5.2.11" "SSH PermitUserEnvironment disabled"
    fi

    # 5.2.13 - Ensure SSH LoginGraceTime is set
    local grace
    grace="$(grep '^LoginGraceTime' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)"
    if [[ -n "$grace" && "$grace" != "0" ]]; then
        cis_result "PASS" "5.2.13" "SSH LoginGraceTime: $grace"
    else
        cis_result "WARN" "5.2.13" "SSH LoginGraceTime not set" \
            "Should be set to 60 or less" \
            "Set LoginGraceTime 60 in sshd_config"
    fi

    # 5.3 - Ensure su command access is restricted
    if grep -qE '^auth\s+required\s+pam_wheel.so' /etc/pam.d/su 2>/dev/null; then
        cis_result "PASS" "5.3" "su restricted to wheel group"
    else
        cis_result "WARN" "5.3" "su not restricted to wheel group" \
            "Any user can attempt su" \
            "Add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su"
    fi

    # 5.4.1.1 - Ensure password expiration <= 365 days
    local pass_max
    pass_max="$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' || true)"
    if [[ -n "$pass_max" && "$pass_max" -le 365 && "$pass_max" -gt 0 ]]; then
        cis_result "PASS" "5.4.1.1" "Password expiration: $pass_max days"
    else
        cis_result "FAIL" "5.4.1.1" "Password expiration too long or not set" \
            "PASS_MAX_DAYS is ${pass_max:-not set}" \
            "Set PASS_MAX_DAYS 365 in /etc/login.defs"
    fi

    # 5.4.1.4 - Ensure inactive password lock <= 30 days
    local inactive
    inactive="$(useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 || true)"
    if [[ -n "$inactive" && "$inactive" -le 30 && "$inactive" -ge 0 ]]; then
        cis_result "PASS" "5.4.1.4" "Inactive password lock: $inactive days"
    else
        cis_result "WARN" "5.4.1.4" "Inactive password lock not configured" \
            "INACTIVE is ${inactive:--1 (disabled)}" \
            "useradd -D -f 30"
    fi

    # 5.4.4 - Ensure default umask is 027 or more restrictive
    local umask_val
    umask_val="$(grep -E '^UMASK' /etc/login.defs 2>/dev/null | awk '{print $2}' || true)"
    if [[ "$umask_val" == "027" || "$umask_val" == "077" ]]; then
        cis_result "PASS" "5.4.4" "Default umask: $umask_val"
    else
        cis_result "WARN" "5.4.4" "Default umask: ${umask_val:-022}" \
            "Umask should be 027 or 077" \
            "Set UMASK 027 in /etc/login.defs"
    fi

    log SUCCESS "CIS Access Control checks complete"
}

# =============================================================================
# CIS 5.2 - Authentication (password quality)
# =============================================================================
cis_authentication() {
    separator
    echo -e "${BOLD}${WHITE}  CIS Section 5.3: Authentication (PAM)${NC}"
    separator

    # Check pam_pwquality
    if grep -rq 'pam_pwquality' /etc/pam.d/ 2>/dev/null; then
        cis_result "PASS" "5.3.1" "pam_pwquality is configured"

        if [[ -f "/etc/security/pwquality.conf" ]]; then
            local minlen
            minlen="$(grep '^minlen' /etc/security/pwquality.conf 2>/dev/null | \
                awk -F= '{print $2}' | tr -d ' ' || true)"
            if [[ -n "$minlen" && "$minlen" -ge 14 ]]; then
                cis_result "PASS" "5.3.1.1" "Password min length: $minlen"
            else
                cis_result "FAIL" "5.3.1.1" "Password min length too short" \
                    "minlen is ${minlen:-not set} (should be >= 14)" \
                    "Set minlen = 14 in /etc/security/pwquality.conf"
            fi

            local minclass
            minclass="$(grep '^minclass' /etc/security/pwquality.conf 2>/dev/null | \
                awk -F= '{print $2}' | tr -d ' ' || true)"
            if [[ -n "$minclass" && "$minclass" -ge 3 ]]; then
                cis_result "PASS" "5.3.1.2" "Password complexity (minclass): $minclass"
            else
                cis_result "WARN" "5.3.1.2" "Password complexity not enforced" \
                    "minclass is ${minclass:-not set} (should be >= 3)" \
                    "Set minclass = 3 in /etc/security/pwquality.conf"
            fi
        fi
    else
        cis_result "FAIL" "5.3.1" "pam_pwquality not configured" \
            "Password complexity not enforced" \
            "Install libpam-pwquality and configure in /etc/pam.d/common-password"
    fi

    # Check password hashing algorithm
    local hash_algo
    hash_algo="$(grep '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}' || true)"
    if [[ "$hash_algo" == "SHA512" || "$hash_algo" == "YESCRYPT" ]]; then
        cis_result "PASS" "5.3.4" "Password hashing: $hash_algo"
    else
        cis_result "FAIL" "5.3.4" "Weak password hashing algorithm" \
            "ENCRYPT_METHOD is ${hash_algo:-not set}" \
            "Set ENCRYPT_METHOD SHA512 in /etc/login.defs"
    fi

    log SUCCESS "CIS Authentication checks complete"
}

# =============================================================================
# CIS 1.7 - Warning Banners
# =============================================================================
cis_banners() {
    separator
    echo -e "${BOLD}${WHITE}  CIS Section 1.7: Warning Banners${NC}"
    separator

    # 1.7.1 - Ensure /etc/motd is configured properly
    if [[ -f "/etc/motd" ]]; then
        local motd_content
        motd_content="$(cat /etc/motd 2>/dev/null)" || true
        if echo "$motd_content" | grep -qiE 'ubuntu|debian|raspberry|\\\\'; then
            cis_result "WARN" "1.7.1" "MOTD contains OS information" \
                "MOTD reveals system details" \
                "Remove OS identification from /etc/motd"
        else
            cis_result "PASS" "1.7.1" "MOTD configured"
        fi
    else
        cis_result "PASS" "1.7.1" "No MOTD file (acceptable)"
    fi

    # 1.7.2 - Ensure /etc/issue is configured
    if [[ -f "/etc/issue" ]]; then
        local issue_content
        issue_content="$(cat /etc/issue 2>/dev/null)" || true
        if echo "$issue_content" | grep -qE '\\\\[lmnrsv]'; then
            cis_result "FAIL" "1.7.2" "/etc/issue contains system information" \
                "Login banner reveals system details (\\l, \\m, \\n, etc.)" \
                "Replace /etc/issue content with authorized use warning"
        else
            cis_result "PASS" "1.7.2" "/etc/issue configured"
        fi
    else
        cis_result "WARN" "1.7.2" "/etc/issue not present" \
            "Login banner should warn unauthorized users" \
            "Create /etc/issue with an authorized-use-only warning"
    fi

    # 1.7.3 - Ensure /etc/issue.net is configured
    if [[ -f "/etc/issue.net" ]]; then
        local issuenet_content
        issuenet_content="$(cat /etc/issue.net 2>/dev/null)" || true
        if echo "$issuenet_content" | grep -qE '\\\\[lmnrsv]'; then
            cis_result "FAIL" "1.7.3" "/etc/issue.net contains system information" \
                "Remote login banner reveals system details" \
                "Replace /etc/issue.net content with authorized use warning"
        else
            cis_result "PASS" "1.7.3" "/etc/issue.net configured"
        fi
    fi

    # 1.7.4 - Permissions on /etc/motd
    if [[ -f "/etc/motd" ]]; then
        local motd_perm
        motd_perm="$(stat -c '%a' /etc/motd 2>/dev/null)" || true
        if [[ "$motd_perm" == "644" ]]; then
            cis_result "PASS" "1.7.4" "/etc/motd permissions: $motd_perm"
        else
            cis_result "FAIL" "1.7.4" "/etc/motd permissions: $motd_perm" \
                "Should be 644" \
                "chmod 644 /etc/motd"
        fi
    fi

    log SUCCESS "CIS Banner checks complete"
}

# =============================================================================
# CIS - File Integrity
# =============================================================================
cis_file_integrity() {
    separator
    echo -e "${BOLD}${WHITE}  CIS Section 1.3: File Integrity Monitoring${NC}"
    separator

    # Check AIDE
    if command -v aide &>/dev/null; then
        cis_result "PASS" "1.3.1" "AIDE is installed"

        # Check if AIDE DB exists
        if [[ -f "/var/lib/aide/aide.db" || -f "/var/lib/aide/aide.db.gz" ]]; then
            cis_result "PASS" "1.3.2" "AIDE database exists"
        else
            cis_result "WARN" "1.3.2" "AIDE database not initialized" \
                "Run: sudo aideinit" \
                "Initialize AIDE database: sudo aideinit"
        fi

        # Check AIDE cron
        if crontab -l 2>/dev/null | grep -q aide || \
           ls /etc/cron.daily/aide* &>/dev/null; then
            cis_result "PASS" "1.3.3" "AIDE scheduled check configured"
        else
            cis_result "WARN" "1.3.3" "AIDE not scheduled" \
                "AIDE should run daily" \
                "Add daily cron: 0 5 * * * /usr/bin/aide --check"
        fi
    elif command -v tripwire &>/dev/null; then
        cis_result "PASS" "1.3.1" "Tripwire is installed"
    else
        cis_result "FAIL" "1.3.1" "No file integrity monitoring tool installed" \
            "Neither AIDE nor Tripwire found" \
            "Install AIDE: sudo apt install aide"
    fi

    log SUCCESS "CIS File Integrity checks complete"
}

# =============================================================================
# Full CIS Benchmark Audit
# =============================================================================
run_full_cis_audit() {
    # Reset counters
    CIS_PASS=0; CIS_FAIL=0; CIS_WARN=0; CIS_TOTAL=0

    log INFO "Starting full CIS benchmark audit (LOCAL machine)"
    separator
    echo -e "${BOLD}${MAGENTA}  Running Full CIS Benchmark Audit${NC}"
    if [[ "${AUDIT_MODE:-}" == "remote" ]]; then
        echo -e "  ${YELLOW}[⚠] NOTE: CIS checks audit YOUR LOCAL machine, not the remote target.${NC}"
    fi
    separator

    cis_filesystem;      echo ""
    cis_services;        echo ""
    cis_network_params;  echo ""
    cis_firewall;        echo ""
    cis_logging;         echo ""
    cis_access_control;  echo ""
    cis_authentication;  echo ""
    cis_banners;         echo ""
    cis_file_integrity

    # CIS Summary
    separator
    echo -e "${BOLD}${WHITE}  CIS Benchmark Summary${NC}"
    separator
    echo -e "  ${GREEN}PASS${NC}: $CIS_PASS"
    echo -e "  ${RED}FAIL${NC}: $CIS_FAIL"
    echo -e "  ${YELLOW}WARN${NC}: $CIS_WARN"
    echo -e "  ${WHITE}──────────────────${NC}"
    echo -e "  ${BOLD}TOTAL${NC}: $CIS_TOTAL"

    if (( CIS_TOTAL > 0 )); then
        local pct=$(( (CIS_PASS * 100) / CIS_TOTAL ))
        echo -e "\n  ${BOLD}Compliance Rate: ${pct}%${NC}"
        if (( pct >= 80 )); then
            echo -e "  ${GREEN}Good compliance posture${NC}"
        elif (( pct >= 60 )); then
            echo -e "  ${YELLOW}Moderate - improvements needed${NC}"
        else
            echo -e "  ${RED}Poor - significant hardening required${NC}"
        fi
    fi
    separator

    # Save summary
    if [[ -n "$SESSION_DIR" ]]; then
        cat > "$SESSION_DIR/scans/cis_summary.txt" << EOF
CIS Benchmark Audit Summary
============================
Date: $(date)
PASS: $CIS_PASS
FAIL: $CIS_FAIL
WARN: $CIS_WARN
TOTAL: $CIS_TOTAL
Compliance: $(( CIS_TOTAL > 0 ? (CIS_PASS * 100) / CIS_TOTAL : 0 ))%
EOF
    fi

    log SUCCESS "Full CIS benchmark audit complete"
    show_findings_summary
}

# =============================================================================
# Compliance Audit Menu
# =============================================================================
compliance_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}${WHITE}  Compliance & CIS Benchmark Audit${NC}"
        echo -e "  ${DIM}(Audits YOUR LOCAL machine - not the remote target)${NC}"
        separator
        echo -e "  ${CYAN}[1]${NC}   Filesystem Configuration"
        echo -e "  ${CYAN}[2]${NC}   Unnecessary Services"
        echo -e "  ${CYAN}[3]${NC}   Network Parameters"
        echo -e "  ${CYAN}[4]${NC}   Firewall Configuration"
        echo -e "  ${CYAN}[5]${NC}   Logging & Auditing"
        echo -e "  ${CYAN}[6]${NC}   Access Control & SSH"
        echo -e "  ${CYAN}[7]${NC}   Authentication & PAM"
        echo -e "  ${CYAN}[8]${NC}   Warning Banners"
        echo -e "  ${CYAN}[9]${NC}   File Integrity Monitoring"
        echo -e "  ${CYAN}[10]${NC}  Full CIS Benchmark Audit (all above)"
        separator
        echo -e "  ${CYAN}[0]${NC}   Back to Main Menu"
        separator
        echo -e "${YELLOW}Select option [0-10]: ${NC}"
        read -r choice
        case "$choice" in
            1)  cis_filesystem; press_enter ;;
            2)  cis_services; press_enter ;;
            3)  cis_network_params; press_enter ;;
            4)  cis_firewall; press_enter ;;
            5)  cis_logging; press_enter ;;
            6)  cis_access_control; press_enter ;;
            7)  cis_authentication; press_enter ;;
            8)  cis_banners; press_enter ;;
            9)  cis_file_integrity; press_enter ;;
            10) run_full_cis_audit; press_enter ;;
            0)  return ;;
            *)  log WARN "Invalid option"; sleep 1 ;;
        esac
    done
}
