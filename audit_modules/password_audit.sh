#!/usr/bin/env bash
# =============================================================================
# Password & Authentication Audit Module
# Default credentials, SSH keys, password policy, brute-force testing,
# FTP anonymous, SMB null sessions
# =============================================================================

# =============================================================================
# Default Credentials Check
# =============================================================================
default_creds_check() {
    require_target || return
    separator
    echo -e "${BOLD}${WHITE}  Default Credentials Check${NC}"
    separator

    local host="$AUDIT_TARGET"
    log INFO "Testing default credentials on $host"

    # Common default credential pairs
    local -a creds=(
        "admin:admin"
        "admin:password"
        "admin:1234"
        "root:root"
        "root:toor"
        "root:password"
        "user:user"
        "test:test"
        "pi:raspberry"
        "ubuntu:ubuntu"
    )

    # Test SSH default creds (only if SSH is open)
    local ssh_open
    ssh_open="$(nmap -p 22 --open -T4 "$host" 2>/dev/null | grep '22/tcp.*open')" || true

    if [[ -n "$ssh_open" ]]; then
        echo -e "\n${WHITE}SSH Default Credential Test:${NC}"
        if command -v sshpass &>/dev/null; then
            for cred in "${creds[@]}"; do
                local user="${cred%%:*}"
                local pass="${cred##*:}"
                local result
                result="$(sshpass -p "$pass" ssh -o StrictHostKeyChecking=no \
                    -o ConnectTimeout=5 -o BatchMode=no \
                    "${user}@${host}" 'echo AUTHENTICATED' 2>/dev/null)" || true
                if [[ "$result" == *"AUTHENTICATED"* ]]; then
                    echo -e "  ${RED}[✗]${NC} SSH login succeeded: ${user}:${pass}"
                    add_finding "CRITICAL" "Password" "Default SSH credentials: ${user}:${pass}" \
                        "Logged in to ${host} via SSH with default credentials ${user}:${pass}" \
                        "Change the default password immediately."
                fi
            done
            echo -e "  ${DIM}Tested ${#creds[@]} credential pairs${NC}"
        else
            echo -e "  ${YELLOW}[⚠]${NC} sshpass not installed - skipping automated SSH test"
            echo -e "  ${DIM}Install: sudo apt install sshpass${NC}"
        fi
    fi

    # Test HTTP default creds (common admin panels)
    echo -e "\n${WHITE}HTTP Admin Panel Default Credential Test:${NC}"
    local http_paths=("/" "/admin" "/login" "/admin/login" "/manager/html" "/wp-admin" "/phpmyadmin")
    local http_open
    http_open="$(nmap -p 80,443,8080,8443 --open -T4 "$host" 2>/dev/null | \
        grep -oE '[0-9]+/tcp.*open')" || true

    if [[ -n "$http_open" ]]; then
        for path in "${http_paths[@]}"; do
            for port in 80 443 8080; do
                local proto="http"
                [[ "$port" == "443" ]] && proto="https"
                local url="${proto}://${host}:${port}${path}"
                local response_code
                response_code="$(curl -s -o /dev/null -w '%{http_code}' \
                    -m 5 "$url" 2>/dev/null)" || true
                if [[ "$response_code" == "200" || "$response_code" == "401" ]]; then
                    if [[ "$response_code" == "401" ]]; then
                        # Test basic auth defaults
                        for cred in "${creds[@]}"; do
                            local user="${cred%%:*}"
                            local pass="${cred##*:}"
                            local auth_result
                            auth_result="$(curl -s -o /dev/null -w '%{http_code}' \
                                -u "${user}:${pass}" -m 5 "$url" 2>/dev/null)" || true
                            if [[ "$auth_result" == "200" ]]; then
                                echo -e "  ${RED}[✗]${NC} HTTP auth succeeded: ${url} (${user}:${pass})"
                                add_finding "CRITICAL" "Password" "Default HTTP credentials on $path" \
                                    "Default credentials ${user}:${pass} work on $url" \
                                    "Change default credentials immediately."
                            fi
                        done
                    fi
                fi
            done
        done
        echo -e "  ${DIM}Tested admin panel paths${NC}"
    else
        echo -e "  ${DIM}No HTTP services detected${NC}"
    fi

    add_finding "INFO" "Password" "Default Credentials Check Complete" \
        "Tested common default credentials against available services" "N/A"
    log SUCCESS "Default credentials check complete"
}

# =============================================================================
# SSH Key Audit
# =============================================================================
ssh_key_audit() {
    separator
    echo -e "${BOLD}${WHITE}  SSH Key Audit${NC}"
    if [[ "${AUDIT_MODE:-}" == "remote" ]]; then
        echo -e "  ${DIM}(Audits YOUR LOCAL machine's SSH keys)${NC}"
    fi
    separator

    log INFO "Auditing SSH keys"

    # System host keys
    echo -e "\n${WHITE}SSH Host Keys:${NC}"
    for keyfile in /etc/ssh/ssh_host_*_key.pub; do
        [[ ! -f "$keyfile" ]] && continue
        local key_info
        key_info="$(ssh-keygen -l -f "$keyfile" 2>/dev/null)" || true
        if [[ -n "$key_info" ]]; then
            local bits
            bits="$(echo "$key_info" | awk '{print $1}')"
            local ktype
            ktype="$(echo "$key_info" | awk '{print $NF}' | tr -d '()')"
            echo -e "  $key_info"

            if [[ "$ktype" == "DSA" ]]; then
                add_finding "HIGH" "Password" "DSA host key found" \
                    "DSA SSH host key ($keyfile) is deprecated and weak" \
                    "Remove DSA host key and use Ed25519 or RSA 4096."
            elif [[ "$ktype" == "RSA" && "$bits" -lt 2048 ]]; then
                add_finding "HIGH" "Password" "Weak RSA host key: ${bits} bits" \
                    "RSA host key is only ${bits} bits" \
                    "Regenerate with at least 4096 bits: ssh-keygen -t rsa -b 4096"
            fi
        fi
    done

    # User authorized_keys
    echo -e "\n${WHITE}Authorized Keys Files:${NC}"
    local user_homes
    user_homes="$(awk -F: '$3 >= 1000 || $1 == "root" {print $1":"$6}' /etc/passwd 2>/dev/null)" || true

    while IFS=: read -r user home; do
        [[ -z "$user" || -z "$home" ]] && continue
        local auth_keys="$home/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            local key_count
            key_count="$(grep -c '^ssh-\|^ecdsa-\|^sk-' "$auth_keys" 2>/dev/null || true)"
            echo -e "  ${CYAN}$user${NC}: $auth_keys (${key_count} keys)"

            # Check key types
            while IFS= read -r keyline; do
                [[ -z "$keyline" || "$keyline" == \#* ]] && continue
                local kt
                kt="$(echo "$keyline" | awk '{print $1}')"
                case "$kt" in
                    ssh-dss)
                        add_finding "HIGH" "Password" "DSA authorized key for $user" \
                            "DSA key in authorized_keys is deprecated" \
                            "Replace with Ed25519 or RSA 4096 key."
                        ;;
                    ssh-rsa)
                        echo -e "    ${DIM}RSA key found (check bit length with ssh-keygen -l)${NC}"
                        ;;
                    ssh-ed25519)
                        echo -e "    ${GREEN}[✓]${NC} Ed25519 key (recommended)"
                        ;;
                esac
            done < "$auth_keys"

            # Check permissions
            local perm
            perm="$(stat -c '%a' "$auth_keys" 2>/dev/null)" || true
            if [[ "$perm" != "600" && "$perm" != "644" && "$perm" != "400" ]]; then
                add_finding "MEDIUM" "Password" "Weak authorized_keys permissions for $user" \
                    "authorized_keys has permissions $perm (should be 600)" \
                    "Fix: chmod 600 $auth_keys"
                echo -e "    ${YELLOW}[⚠]${NC} Permissions: $perm (should be 600)"
            fi
        fi
    done <<< "$user_homes"

    # Check .ssh directory permissions
    echo -e "\n${WHITE}SSH Directory Permissions:${NC}"
    while IFS=: read -r user home; do
        [[ -z "$user" || -z "$home" ]] && continue
        local ssh_dir="$home/.ssh"
        if [[ -d "$ssh_dir" ]]; then
            local dir_perm
            dir_perm="$(stat -c '%a' "$ssh_dir" 2>/dev/null)" || true
            if [[ "$dir_perm" != "700" ]]; then
                echo -e "  ${YELLOW}[⚠]${NC} $user: $ssh_dir permissions: $dir_perm (should be 700)"
                add_finding "MEDIUM" "Password" "Weak .ssh directory permissions for $user" \
                    ".ssh directory has permissions $dir_perm" \
                    "Fix: chmod 700 $ssh_dir"
            else
                echo -e "  ${GREEN}[✓]${NC} $user: $ssh_dir permissions: 700"
            fi
        fi
    done <<< "$user_homes"

    log SUCCESS "SSH key audit complete"
}

# =============================================================================
# Password Policy Check
# =============================================================================
password_policy_check() {
    separator
    echo -e "${BOLD}${WHITE}  Password Policy Audit${NC}"
    if [[ "${AUDIT_MODE:-}" == "remote" ]]; then
        echo -e "  ${DIM}(Audits YOUR LOCAL machine's password policy)${NC}"
    fi
    separator

    log INFO "Checking password policy configuration"

    # PAM configuration
    echo -e "\n${WHITE}PAM Password Configuration:${NC}"
    local pam_files=("/etc/pam.d/common-password" "/etc/pam.d/system-auth" \
        "/etc/pam.d/password-auth" "/etc/security/pwquality.conf")

    for pf in "${pam_files[@]}"; do
        if [[ -f "$pf" ]]; then
            echo -e "  ${CYAN}$pf:${NC}"
            grep -v '^#\|^$' "$pf" 2>/dev/null | head -15
            echo ""
        fi
    done

    # Check pwquality settings
    if [[ -f "/etc/security/pwquality.conf" ]]; then
        echo -e "${WHITE}Password Quality Settings:${NC}"
        local minlen dcredit ucredit lcredit ocredit
        minlen="$(grep '^minlen' /etc/security/pwquality.conf 2>/dev/null | \
            awk '{print $NF}' || true)"
        dcredit="$(grep '^dcredit' /etc/security/pwquality.conf 2>/dev/null | \
            awk '{print $NF}' || true)"
        ucredit="$(grep '^ucredit' /etc/security/pwquality.conf 2>/dev/null | \
            awk '{print $NF}' || true)"

        if [[ -n "$minlen" ]]; then
            echo -e "  Minimum length: $minlen"
            if (( minlen < 8 )); then
                add_finding "MEDIUM" "Password" "Weak minimum password length" \
                    "Minimum password length is $minlen (should be >= 12)" \
                    "Set minlen=12 in /etc/security/pwquality.conf"
            fi
        else
            add_finding "MEDIUM" "Password" "No minimum password length configured" \
                "pwquality minlen not set" \
                "Set minlen=12 in /etc/security/pwquality.conf"
        fi
    else
        echo -e "  ${YELLOW}[⚠]${NC} pwquality.conf not found"
        add_finding "MEDIUM" "Password" "No password quality configuration" \
            "pwquality.conf not found - password complexity not enforced" \
            "Install libpam-pwquality and configure /etc/security/pwquality.conf"
    fi

    # Check login.defs
    echo -e "\n${WHITE}Login Defaults (/etc/login.defs):${NC}"
    if [[ -f "/etc/login.defs" ]]; then
        local params=("PASS_MAX_DAYS" "PASS_MIN_DAYS" "PASS_MIN_LEN" "PASS_WARN_AGE" \
            "LOGIN_RETRIES" "LOGIN_TIMEOUT" "ENCRYPT_METHOD")
        for param in "${params[@]}"; do
            local val
            val="$(grep "^${param}" /etc/login.defs 2>/dev/null | awk '{print $2}' || true)"
            echo -e "  $param: ${val:-not set}"
        done

        local encrypt
        encrypt="$(grep '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}' || true)"
        if [[ "$encrypt" == "MD5" || "$encrypt" == "DES" ]]; then
            add_finding "HIGH" "Password" "Weak password hashing: $encrypt" \
                "Password hashing uses $encrypt which is weak" \
                "Set ENCRYPT_METHOD to SHA512 or YESCRYPT in /etc/login.defs"
        fi
    fi

    # Check for password lockout
    echo -e "\n${WHITE}Account Lockout Policy:${NC}"
    local faillock
    faillock="$(grep -r 'pam_faillock\|pam_tally2' /etc/pam.d/ 2>/dev/null | \
        grep -v '^#' || true)"
    if [[ -n "$faillock" ]]; then
        echo -e "  ${GREEN}[✓]${NC} Account lockout configured"
        echo "$faillock" | head -5
    else
        echo -e "  ${RED}[✗]${NC} No account lockout policy"
        add_finding "MEDIUM" "Password" "No account lockout policy" \
            "No pam_faillock or pam_tally2 configured" \
            "Configure account lockout in PAM with pam_faillock."
    fi

    log SUCCESS "Password policy check complete"
}

# =============================================================================
# SSH Brute-Force Test
# =============================================================================
ssh_bruteforce_test() {
    require_target || return
    require_tool hydra "SSH brute-force" || return
    separator
    echo -e "${BOLD}${WHITE}  SSH Brute-Force Test${NC}"
    separator

    local host="$AUDIT_TARGET"

    echo -e "${RED}[!] This test will attempt SSH logins against $host${NC}"
    echo -e "${YELLOW}Continue? (yes/no):${NC}"
    read -r confirm
    [[ "${confirm,,}" != "yes" ]] && return

    echo -e "${YELLOW}Username to test (default: root):${NC}"
    read -r test_user
    [[ -z "$test_user" ]] && test_user="root"

    log INFO "Running SSH brute-force test on $host (user: $test_user)"

    # Use a small built-in password list
    local passfile
    passfile="$(mktemp)"
    cat > "$passfile" << 'PASSWORDS'
password
123456
admin
root
toor
raspberry
letmein
changeme
welcome
qwerty
test
12345678
abc123
password1
master
PASSWORDS

    local result
    result="$(hydra -l "$test_user" -P "$passfile" -t 4 -w 15 -f \
        "ssh://${host}" 2>&1)" || true
    rm -f "$passfile"

    echo "$result"
    save_scan "ssh_bruteforce" "$result"

    if echo "$result" | grep -qi "valid password\|successfully completed\|login:"; then
        local found_cred
        found_cred="$(echo "$result" | grep -i 'login:.*password:' | head -1)" || true
        add_finding "CRITICAL" "Password" "SSH brute-force succeeded" \
            "Hydra found valid SSH credentials: $found_cred" \
            "Change the password immediately and implement fail2ban."
    else
        echo -e "  ${GREEN}[✓]${NC} No default passwords found"
        add_finding "INFO" "Password" "SSH brute-force test passed" \
            "No common passwords found for $test_user on $host" "N/A"
    fi

    log SUCCESS "SSH brute-force test complete"
}

# =============================================================================
# HTTP Authentication Test
# =============================================================================
http_auth_test() {
    require_target || return
    require_tool hydra "HTTP auth test" || return
    separator
    echo -e "${BOLD}${WHITE}  HTTP Authentication Test${NC}"
    separator

    local host="$AUDIT_TARGET"

    echo -e "${RED}[!] This test will attempt HTTP logins against $host${NC}"
    echo -e "${YELLOW}Continue? (yes/no):${NC}"
    read -r confirm
    [[ "${confirm,,}" != "yes" ]] && return

    echo -e "${YELLOW}HTTP path (default: /):${NC}"
    read -r http_path
    [[ -z "$http_path" ]] && http_path="/"

    echo -e "${YELLOW}Port (default: 80):${NC}"
    read -r http_port
    [[ -z "$http_port" ]] && http_port=80

    log INFO "Running HTTP auth test on ${host}:${http_port}${http_path}"

    local passfile
    passfile="$(mktemp)"
    cat > "$passfile" << 'PASSWORDS'
password
admin
123456
root
changeme
test
PASSWORDS

    local result
    result="$(hydra -l admin -P "$passfile" -t 4 -f \
        "${host}" http-get "${http_path}" -s "$http_port" 2>&1)" || true
    rm -f "$passfile"

    echo "$result"
    save_scan "http_auth" "$result"

    if echo "$result" | grep -qi "valid password\|login:.*password:"; then
        add_finding "CRITICAL" "Password" "HTTP auth brute-force succeeded" \
            "Default credentials found on ${host}:${http_port}${http_path}" \
            "Change default HTTP credentials immediately."
    else
        echo -e "  ${GREEN}[✓]${NC} No default HTTP credentials found"
    fi

    log SUCCESS "HTTP auth test complete"
}

# =============================================================================
# FTP Anonymous Check
# =============================================================================
ftp_anonymous_check() {
    require_target || return
    separator
    echo -e "${BOLD}${WHITE}  FTP Anonymous Access Check${NC}"
    separator

    local host="$AUDIT_TARGET"
    log INFO "Testing FTP anonymous access on $host"

    # Check if FTP is open first
    local ftp_open
    ftp_open="$(nmap -p 21 --open -T4 "$host" 2>/dev/null | grep '21/tcp.*open')" || true

    if [[ -z "$ftp_open" ]]; then
        echo -e "  ${DIM}FTP port 21 not open${NC}"
        add_finding "INFO" "Password" "FTP not available" \
            "Port 21 not open on $host" "N/A"
        return
    fi

    # Test anonymous login
    local ftp_result
    ftp_result="$(curl -s -m 10 --user "anonymous:anonymous@test.com" \
        "ftp://${host}/" 2>&1)" || true

    if [[ -n "$ftp_result" && "$ftp_result" != *"Access denied"* && \
          "$ftp_result" != *"Login incorrect"* && "$ftp_result" != *"530"* ]]; then
        echo -e "  ${RED}[✗]${NC} Anonymous FTP access ALLOWED"
        echo "$ftp_result" | head -20
        add_finding "HIGH" "Password" "FTP anonymous access enabled" \
            "Anonymous FTP login successful on $host" \
            "Disable anonymous FTP access in FTP server configuration."
    else
        echo -e "  ${GREEN}[✓]${NC} Anonymous FTP access denied"
        add_finding "INFO" "Password" "FTP anonymous access denied" \
            "Anonymous FTP properly restricted on $host" "N/A"
    fi

    # Also test with nmap script
    if command -v nmap &>/dev/null; then
        local nmap_ftp
        nmap_ftp="$(nmap -p 21 --script ftp-anon "$host" 2>/dev/null)" || true
        if echo "$nmap_ftp" | grep -qi "Anonymous FTP login allowed"; then
            echo -e "  ${RED}[✗]${NC} Nmap confirms anonymous FTP access"
        fi
    fi

    log SUCCESS "FTP anonymous check complete"
}

# =============================================================================
# SMB Null Session Test
# =============================================================================
smb_null_session() {
    require_target || return
    separator
    echo -e "${BOLD}${WHITE}  SMB Null Session Enumeration${NC}"
    separator

    local host="$AUDIT_TARGET"
    log INFO "Testing SMB null session on $host"

    # Check if SMB is open
    local smb_open
    smb_open="$(nmap -p 445,139 --open -T4 "$host" 2>/dev/null | \
        grep -E '445/tcp.*open|139/tcp.*open')" || true

    if [[ -z "$smb_open" ]]; then
        echo -e "  ${DIM}SMB ports not open${NC}"
        add_finding "INFO" "Password" "SMB not available" \
            "Ports 445/139 not open on $host" "N/A"
        return
    fi

    # Test with enum4linux if available
    if command -v enum4linux &>/dev/null; then
        echo -e "\n${WHITE}enum4linux null session test:${NC}"
        local enum_result
        enum_result="$(timeout 60 enum4linux -a "$host" 2>/dev/null)" || true
        echo "$enum_result" | head -50
        save_scan "smb_enum4linux" "$enum_result"

        if echo "$enum_result" | grep -qi "session setup.*ok\|share enumeration\|user.*list"; then
            add_finding "HIGH" "Password" "SMB null session allowed" \
                "SMB null session enumeration possible on $host" \
                "Disable null sessions: set 'restrict anonymous = 2' in smb.conf"
        fi
    fi

    # Test with smbclient if available
    if command -v smbclient &>/dev/null; then
        echo -e "\n${WHITE}smbclient null session test:${NC}"
        local smb_result
        smb_result="$(smbclient -L "$host" -N 2>&1)" || true
        echo "$smb_result" | head -20

        if echo "$smb_result" | grep -qi "Sharename\|IPC\$\|Disk"; then
            echo -e "  ${YELLOW}[⚠]${NC} Share listing accessible via null session"
            add_finding "MEDIUM" "Password" "SMB shares visible via null session" \
                "Share listing accessible without credentials on $host" \
                "Restrict anonymous share enumeration."
        else
            echo -e "  ${GREEN}[✓]${NC} Null session denied"
        fi
    fi

    # Nmap SMB scripts
    if command -v nmap &>/dev/null; then
        echo -e "\n${WHITE}Nmap SMB scripts:${NC}"
        local nmap_smb
        nmap_smb="$(nmap -p 445 --script smb-security-mode,smb-enum-shares \
            "$host" 2>/dev/null)" || true
        echo "$nmap_smb" | head -30

        if echo "$nmap_smb" | grep -qi "message_signing: disabled"; then
            add_finding "MEDIUM" "Password" "SMB signing disabled" \
                "SMB message signing is disabled on $host" \
                "Enable SMB signing to prevent relay attacks."
        fi
    fi

    log SUCCESS "SMB null session test complete"
}

# =============================================================================
# Full Password Audit
# =============================================================================
full_password_audit() {
    log INFO "Starting full password & authentication audit"
    separator
    echo -e "${BOLD}${MAGENTA}  Running Full Password & Auth Audit${NC}"
    separator

    default_creds_check;     echo ""
    ssh_key_audit;           echo ""
    password_policy_check;   echo ""
    ftp_anonymous_check;     echo ""
    smb_null_session

    # Only run brute-force tests in full audit if confirmed
    echo -e "\n${YELLOW}Run brute-force tests (SSH/HTTP)? These are aggressive. (yes/no):${NC}"
    read -r run_brute
    if [[ "${run_brute,,}" == "yes" ]]; then
        echo ""
        ssh_bruteforce_test
        echo ""
        http_auth_test
    fi

    log SUCCESS "Full password audit complete"
    show_findings_summary
}

# =============================================================================
# Password Audit Menu
# =============================================================================
password_audit_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}${WHITE}  Password & Authentication Audit${NC}"
        separator
        echo -e "  ${CYAN}[1]${NC}  Default Credentials Check"
        echo -e "  ${CYAN}[2]${NC}  SSH Key Audit"
        echo -e "  ${CYAN}[3]${NC}  Password Policy Check"
        echo -e "  ${CYAN}[4]${NC}  SSH Brute-Force Test"
        echo -e "  ${CYAN}[5]${NC}  HTTP Authentication Test"
        echo -e "  ${CYAN}[6]${NC}  FTP Anonymous Access Check"
        echo -e "  ${CYAN}[7]${NC}  SMB Null Session Test"
        echo -e "  ${CYAN}[8]${NC}  Full Password Audit (all above)"
        separator
        echo -e "  ${CYAN}[0]${NC}  Back to Main Menu"
        separator
        echo -e "${YELLOW}Select option [0-8]: ${NC}"
        read -r choice
        case "$choice" in
            1) default_creds_check; press_enter ;;
            2) ssh_key_audit; press_enter ;;
            3) password_policy_check; press_enter ;;
            4) ssh_bruteforce_test; press_enter ;;
            5) http_auth_test; press_enter ;;
            6) ftp_anonymous_check; press_enter ;;
            7) smb_null_session; press_enter ;;
            8) full_password_audit; press_enter ;;
            0) return ;;
            *) log WARN "Invalid option"; sleep 1 ;;
        esac
    done
}
