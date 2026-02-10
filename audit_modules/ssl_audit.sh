#!/usr/bin/env bash
# =============================================================================
# SSL/TLS & Certificate Audit Module
# Protocol testing, cipher analysis, certificate chain validation,
# HSTS, OCSP, Heartbleed, testssl.sh integration
# =============================================================================

# =============================================================================
# SSL Quick Check
# =============================================================================
ssl_quick_check() {
    require_target || return
    require_tool openssl "SSL check" || return
    separator
    echo -e "${BOLD}${WHITE}  SSL/TLS Quick Check${NC}"
    separator

    local host="$AUDIT_TARGET"
    local port="${1:-}"
    if [[ -z "$port" ]]; then
        echo -e "${YELLOW}Port (default: 443):${NC}"
        read -r port
    fi
    [[ -z "$port" ]] && port=443

    log INFO "Testing SSL/TLS on ${host}:${port}"

    local result
    result="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" -brief 2>/dev/null)" || true

    if [[ -z "$result" ]]; then
        log ERROR "Could not establish SSL connection to ${host}:${port}"
        add_finding "HIGH" "SSL/TLS" "SSL connection failed" \
            "Could not establish SSL/TLS connection to ${host}:${port}" \
            "Verify the service is running and supports SSL/TLS."
        return 1
    fi

    echo "$result"
    save_scan "ssl_quick" "$result"

    # Get certificate details
    echo -e "\n${WHITE}Certificate Details:${NC}"
    local cert_info
    cert_info="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" 2>/dev/null | \
        openssl x509 -noout -subject -issuer -dates -serial -fingerprint 2>/dev/null)" || true
    echo "$cert_info"

    # Check expiry
    local expiry
    expiry="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" 2>/dev/null | \
        openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)" || true

    if [[ -n "$expiry" ]]; then
        local expiry_epoch
        expiry_epoch="$(date -d "$expiry" +%s 2>/dev/null)" || true
        local now_epoch
        now_epoch="$(date +%s)"
        if [[ -n "$expiry_epoch" ]]; then
            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
            if (( days_left < 0 )); then
                add_finding "CRITICAL" "SSL/TLS" "Certificate expired" \
                    "Certificate for ${host} expired ${days_left#-} days ago" \
                    "Renew the SSL certificate immediately."
                echo -e "  ${RED}[✗]${NC} Certificate EXPIRED (${days_left} days)"
            elif (( days_left < 30 )); then
                add_finding "HIGH" "SSL/TLS" "Certificate expiring soon" \
                    "Certificate expires in ${days_left} days" \
                    "Renew the SSL certificate within ${days_left} days."
                echo -e "  ${YELLOW}[⚠]${NC} Expires in ${days_left} days"
            elif (( days_left < 90 )); then
                add_finding "MEDIUM" "SSL/TLS" "Certificate expiring within 90 days" \
                    "Certificate expires in ${days_left} days" \
                    "Plan certificate renewal."
                echo -e "  ${YELLOW}[⚠]${NC} Expires in ${days_left} days"
            else
                echo -e "  ${GREEN}[✓]${NC} Certificate valid for ${days_left} days"
            fi
        fi
    fi

    add_finding "INFO" "SSL/TLS" "SSL Quick Check Complete" \
        "Basic SSL check performed on ${host}:${port}" "N/A"
    log SUCCESS "SSL quick check complete"
}

# =============================================================================
# Protocol Version Test
# =============================================================================
protocol_version_test() {
    require_target || return
    require_tool openssl "protocol test" || return
    separator
    echo -e "${BOLD}${WHITE}  SSL/TLS Protocol Version Test${NC}"
    separator

    local host="$AUDIT_TARGET"
    local port="${1:-}"
    if [[ -z "$port" ]]; then
        echo -e "${YELLOW}Port (default: 443):${NC}"
        read -r port
    fi
    [[ -z "$port" ]] && port=443

    log INFO "Testing protocol versions on ${host}:${port}"

    local protocols=("ssl3:SSLv3" "tls1:TLS_1.0" "tls1_1:TLS_1.1" "tls1_2:TLS_1.2" "tls1_3:TLS_1.3")
    local result_text=""

    for proto_entry in "${protocols[@]}"; do
        local flag="${proto_entry%%:*}"
        local name="${proto_entry##*:}"
        local test_result

        test_result="$(echo | openssl s_client -connect "${host}:${port}" \
            -servername "$host" "-${flag}" 2>/dev/null)" || true

        if echo "$test_result" | grep -q "CONNECTED\|Protocol.*:.*TLS\|SSL"; then
            # Check if actually negotiated
            local negotiated
            negotiated="$(echo "$test_result" | grep -i 'Protocol\s*:' | head -1)" || true
            if [[ -n "$negotiated" ]]; then
                case "$name" in
                    SSLv3)
                        echo -e "  ${RED}[✗]${NC} $name: SUPPORTED (INSECURE)"
                        add_finding "CRITICAL" "SSL/TLS" "SSLv3 supported" \
                            "SSLv3 is enabled on ${host}:${port} - vulnerable to POODLE" \
                            "Disable SSLv3 in server configuration."
                        ;;
                    TLS_1.0)
                        echo -e "  ${YELLOW}[⚠]${NC} $name: SUPPORTED (Deprecated)"
                        add_finding "MEDIUM" "SSL/TLS" "TLS 1.0 supported" \
                            "TLS 1.0 is enabled - deprecated and has known weaknesses" \
                            "Disable TLS 1.0, require TLS 1.2+ minimum."
                        ;;
                    TLS_1.1)
                        echo -e "  ${YELLOW}[⚠]${NC} $name: SUPPORTED (Deprecated)"
                        add_finding "MEDIUM" "SSL/TLS" "TLS 1.1 supported" \
                            "TLS 1.1 is enabled - deprecated" \
                            "Disable TLS 1.1, require TLS 1.2+ minimum."
                        ;;
                    TLS_1.2)
                        echo -e "  ${GREEN}[✓]${NC} $name: SUPPORTED"
                        ;;
                    TLS_1.3)
                        echo -e "  ${GREEN}[✓]${NC} $name: SUPPORTED (Best)"
                        ;;
                esac
            else
                echo -e "  ${DIM}[−]${NC} $name: Not supported"
            fi
        else
            echo -e "  ${DIM}[−]${NC} $name: Not supported"
            if [[ "$name" == "TLS_1.2" ]]; then
                add_finding "HIGH" "SSL/TLS" "TLS 1.2 not supported" \
                    "TLS 1.2 is not enabled on ${host}:${port}" \
                    "Enable TLS 1.2 support."
            fi
        fi
        result_text+="$name: $test_result"$'\n'
    done

    save_scan "protocol_versions" "$result_text"
    log SUCCESS "Protocol version test complete"
}

# =============================================================================
# Cipher Suite Analysis
# =============================================================================
cipher_suite_analysis() {
    require_target || return
    require_tool openssl "cipher analysis" || return
    separator
    echo -e "${BOLD}${WHITE}  Cipher Suite Analysis${NC}"
    separator

    local host="$AUDIT_TARGET"
    local port="${1:-}"
    if [[ -z "$port" ]]; then
        echo -e "${YELLOW}Port (default: 443):${NC}"
        read -r port
    fi
    [[ -z "$port" ]] && port=443

    log INFO "Analyzing cipher suites on ${host}:${port}"

    # Get supported ciphers
    local cipher_list
    cipher_list="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" 2>/dev/null | grep -i 'cipher\|protocol' | head -5)" || true
    echo "$cipher_list"

    # Test weak ciphers
    echo -e "\n${WHITE}Testing for weak ciphers:${NC}"
    local weak_ciphers=("RC4" "DES" "3DES" "MD5" "NULL" "EXPORT" "aNULL" "eNULL")
    for cipher in "${weak_ciphers[@]}"; do
        local test_result
        test_result="$(echo | openssl s_client -connect "${host}:${port}" \
            -servername "$host" -cipher "$cipher" 2>/dev/null)" || true
        if echo "$test_result" | grep -qi "CONNECTED.*Cipher is"; then
            local negotiated
            negotiated="$(echo "$test_result" | grep 'Cipher' | head -1)" || true
            if [[ "$negotiated" != *"0000"* && "$negotiated" != *"(NONE)"* ]]; then
                echo -e "  ${RED}[✗]${NC} $cipher: ACCEPTED (WEAK)"
                add_finding "HIGH" "SSL/TLS" "Weak cipher accepted: $cipher" \
                    "${cipher} cipher suite accepted on ${host}:${port}" \
                    "Disable $cipher in server SSL configuration."
            else
                echo -e "  ${GREEN}[✓]${NC} $cipher: Rejected"
            fi
        else
            echo -e "  ${GREEN}[✓]${NC} $cipher: Rejected"
        fi
    done

    # Test for forward secrecy
    echo -e "\n${WHITE}Forward Secrecy Support:${NC}"
    local fs_result
    fs_result="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" -cipher 'ECDHE:DHE' 2>/dev/null)" || true
    if echo "$fs_result" | grep -qi "Cipher.*ECDHE\|Cipher.*DHE"; then
        echo -e "  ${GREEN}[✓]${NC} Forward secrecy supported (ECDHE/DHE)"
    else
        echo -e "  ${YELLOW}[⚠]${NC} Forward secrecy may not be supported"
        add_finding "MEDIUM" "SSL/TLS" "Forward secrecy not detected" \
            "ECDHE/DHE ciphers not negotiated on ${host}:${port}" \
            "Enable ECDHE/DHE cipher suites for forward secrecy."
    fi

    log SUCCESS "Cipher suite analysis complete"
}

# =============================================================================
# Certificate Chain Check
# =============================================================================
certificate_chain_check() {
    require_target || return
    require_tool openssl "certificate check" || return
    separator
    echo -e "${BOLD}${WHITE}  Certificate Chain Validation${NC}"
    separator

    local host="$AUDIT_TARGET"
    local port="${1:-}"
    if [[ -z "$port" ]]; then
        echo -e "${YELLOW}Port (default: 443):${NC}"
        read -r port
    fi
    [[ -z "$port" ]] && port=443

    log INFO "Validating certificate chain for ${host}:${port}"

    # Full chain dump
    local chain
    chain="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" -showcerts 2>/dev/null)" || true

    local chain_depth
    chain_depth="$(echo "$chain" | grep -c 'BEGIN CERTIFICATE' || true)"
    echo -e "  Chain depth: $chain_depth certificate(s)"

    # Verify chain
    local verify_result
    verify_result="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" -verify_return_error 2>&1)" || true

    if echo "$verify_result" | grep -q "Verify return code: 0"; then
        echo -e "  ${GREEN}[✓]${NC} Certificate chain validates successfully"
    else
        local verify_code
        verify_code="$(echo "$verify_result" | grep 'Verify return code:' | head -1)"
        echo -e "  ${RED}[✗]${NC} Chain validation issue: $verify_code"
        add_finding "HIGH" "SSL/TLS" "Certificate chain validation failed" \
            "Chain validation: $verify_code" \
            "Fix certificate chain - ensure all intermediate CAs are included."
    fi

    # Check CN and SAN
    echo -e "\n${WHITE}Subject & SAN:${NC}"
    local cert_detail
    cert_detail="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" 2>/dev/null | \
        openssl x509 -noout -subject -ext subjectAltName 2>/dev/null)" || true
    echo "$cert_detail"

    # Check if CN/SAN matches target
    local cn
    cn="$(echo "$cert_detail" | grep 'subject=' | sed 's/.*CN *= *//' | sed 's/,.*//')" || true
    local san
    san="$(echo "$cert_detail" | grep -A1 'Subject Alternative Name' | tail -1)" || true

    if [[ "$cn" != *"$host"* ]] && [[ "$san" != *"$host"* ]]; then
        add_finding "HIGH" "SSL/TLS" "Certificate hostname mismatch" \
            "Certificate CN=$cn does not match $host" \
            "Obtain a certificate with the correct hostname."
    fi

    # Key size
    echo -e "\n${WHITE}Key Information:${NC}"
    local key_info
    key_info="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" 2>/dev/null | \
        openssl x509 -noout -text 2>/dev/null | grep -E 'Public-Key:|RSA|ECDSA|Ed25519')" || true
    echo "$key_info"

    local key_bits
    key_bits="$(echo "$key_info" | grep -oE '[0-9]+ bit' | head -1 | grep -oE '[0-9]+')" || true
    if [[ -n "$key_bits" ]]; then
        if (( key_bits < 2048 )); then
            add_finding "HIGH" "SSL/TLS" "Weak key size: ${key_bits} bits" \
                "RSA key is only ${key_bits} bits" \
                "Use at least 2048-bit RSA or 256-bit ECDSA keys."
        elif (( key_bits >= 4096 )); then
            echo -e "  ${GREEN}[✓]${NC} Strong key: ${key_bits} bits"
        fi
    fi

    save_scan "cert_chain" "$chain"
    log SUCCESS "Certificate chain check complete"
}

# =============================================================================
# Certificate Transparency
# =============================================================================
certificate_transparency() {
    require_target || return
    require_tool curl "CT lookup" || return
    separator
    echo -e "${BOLD}${WHITE}  Certificate Transparency Log Lookup${NC}"
    separator

    local host="$AUDIT_TARGET"
    log INFO "Querying crt.sh for ${host}"

    local ct_result
    ct_result="$(curl -s "https://crt.sh/?q=%25.${host}&output=json" 2>/dev/null | \
        jq -r '.[] | "\(.id) | \(.name_value) | \(.not_before) | \(.issuer_name)"' 2>/dev/null | \
        head -30)" || true

    if [[ -n "$ct_result" ]]; then
        echo "$ct_result"
        save_scan "ct_logs" "$ct_result"
        local cert_count
        cert_count="$(echo "$ct_result" | wc -l)"
        add_finding "INFO" "SSL/TLS" "Certificate Transparency results" \
            "${cert_count} certificates found in CT logs for ${host}" \
            "Review CT logs for unauthorized certificate issuance."
    else
        echo -e "  ${DIM}No CT log entries found or crt.sh unavailable${NC}"
    fi

    log SUCCESS "CT lookup complete"
}

# =============================================================================
# HSTS Check
# =============================================================================
hsts_check() {
    require_target || return
    require_tool curl "HSTS check" || return
    separator
    echo -e "${BOLD}${WHITE}  HSTS (HTTP Strict Transport Security) Check${NC}"
    separator

    local host="$AUDIT_TARGET"
    log INFO "Checking HSTS on ${host}"

    local headers
    headers="$(curl -sI -m 10 "https://${host}/" 2>/dev/null)" || true

    local hsts_header
    hsts_header="$(echo "$headers" | grep -i 'strict-transport-security')" || true

    if [[ -n "$hsts_header" ]]; then
        echo -e "  ${GREEN}[✓]${NC} HSTS header present: $hsts_header"

        # Check max-age
        local max_age
        max_age="$(echo "$hsts_header" | grep -oiE 'max-age=([0-9]+)' | cut -d= -f2)" || true
        if [[ -n "$max_age" ]]; then
            if (( max_age < 15768000 )); then  # 6 months
                add_finding "LOW" "SSL/TLS" "HSTS max-age is short" \
                    "HSTS max-age is ${max_age}s (< 6 months)" \
                    "Set max-age to at least 31536000 (1 year)."
            else
                echo -e "  ${GREEN}[✓]${NC} max-age: ${max_age}s"
            fi
        fi

        # Check includeSubDomains
        if echo "$hsts_header" | grep -qi "includeSubDomains"; then
            echo -e "  ${GREEN}[✓]${NC} includeSubDomains: yes"
        else
            echo -e "  ${YELLOW}[⚠]${NC} includeSubDomains: not set"
            add_finding "LOW" "SSL/TLS" "HSTS missing includeSubDomains" \
                "HSTS header does not include subdomains" \
                "Add includeSubDomains to HSTS header."
        fi

        # Check preload
        if echo "$hsts_header" | grep -qi "preload"; then
            echo -e "  ${GREEN}[✓]${NC} Preload: yes"
        else
            echo -e "  ${DIM}[−]${NC} Preload: not set"
        fi
    else
        echo -e "  ${RED}[✗]${NC} HSTS header not found"
        add_finding "MEDIUM" "SSL/TLS" "HSTS not enabled" \
            "No Strict-Transport-Security header on ${host}" \
            "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    fi

    # Check other security headers while we're at it
    echo -e "\n${WHITE}Other Security Headers:${NC}"
    local sec_headers=("X-Content-Type-Options" "X-Frame-Options" \
        "X-XSS-Protection" "Content-Security-Policy" "Referrer-Policy" \
        "Permissions-Policy")
    for hdr in "${sec_headers[@]}"; do
        local val
        val="$(echo "$headers" | grep -i "^${hdr}:" | head -1)" || true
        if [[ -n "$val" ]]; then
            echo -e "  ${GREEN}[✓]${NC} $val"
        else
            echo -e "  ${YELLOW}[⚠]${NC} $hdr: missing"
            add_finding "LOW" "SSL/TLS" "Missing security header: $hdr" \
                "$hdr header not set on $host" \
                "Add $hdr header to HTTP responses."
        fi
    done

    save_scan "hsts_headers" "$headers"
    log SUCCESS "HSTS check complete"
}

# =============================================================================
# OCSP Stapling Check
# =============================================================================
ocsp_stapling_check() {
    require_target || return
    require_tool openssl "OCSP check" || return
    separator
    echo -e "${BOLD}${WHITE}  OCSP Stapling Check${NC}"
    separator

    local host="$AUDIT_TARGET"
    local port="${1:-}"
    if [[ -z "$port" ]]; then
        echo -e "${YELLOW}Port (default: 443):${NC}"
        read -r port
    fi
    [[ -z "$port" ]] && port=443

    log INFO "Checking OCSP stapling on ${host}:${port}"

    local result
    result="$(echo | openssl s_client -connect "${host}:${port}" \
        -servername "$host" -status 2>/dev/null)" || true

    if echo "$result" | grep -qi "OCSP Response Status: successful"; then
        echo -e "  ${GREEN}[✓]${NC} OCSP stapling is enabled"
        local ocsp_detail
        ocsp_detail="$(echo "$result" | grep -A5 'OCSP Response')" || true
        echo "$ocsp_detail"
        add_finding "INFO" "SSL/TLS" "OCSP stapling enabled" \
            "OCSP stapling is active on ${host}:${port}" "N/A"
    else
        echo -e "  ${YELLOW}[⚠]${NC} OCSP stapling not detected"
        add_finding "LOW" "SSL/TLS" "OCSP stapling not enabled" \
            "No OCSP stapling response from ${host}:${port}" \
            "Enable OCSP stapling in web server configuration."
    fi

    save_scan "ocsp_stapling" "$result"
    log SUCCESS "OCSP check complete"
}

# =============================================================================
# testssl.sh Integration
# =============================================================================
testssl_integration() {
    require_target || return
    require_tool testssl.sh "testssl" || {
        require_tool testssl "testssl" || return
    }
    separator
    echo -e "${BOLD}${WHITE}  testssl.sh Full Scan${NC}"
    separator

    local host="$AUDIT_TARGET"
    local port="${1:-}"
    if [[ -z "$port" ]]; then
        echo -e "${YELLOW}Port (default: 443):${NC}"
        read -r port
    fi
    [[ -z "$port" ]] && port=443

    local testssl_cmd
    if command -v testssl.sh &>/dev/null; then
        testssl_cmd="testssl.sh"
    elif command -v testssl &>/dev/null; then
        testssl_cmd="testssl"
    fi

    local json_out="$SESSION_DIR/scans/testssl_${SESSION_ID}.json"
    local html_out="$SESSION_DIR/scans/testssl_${SESSION_ID}.html"

    log INFO "Running testssl.sh on ${host}:${port} (this may take several minutes)"
    "$testssl_cmd" --jsonfile "$json_out" --htmlfile "$html_out" \
        "${host}:${port}" 2>&1 || true

    if [[ -f "$json_out" ]]; then
        log SUCCESS "testssl.sh output saved to $json_out"
        # Parse critical findings from JSON
        local critical_count
        critical_count="$(jq '[.[] | select(.severity == "CRITICAL")] | length' \
            "$json_out" 2>/dev/null)" || critical_count=0
        local high_count
        high_count="$(jq '[.[] | select(.severity == "HIGH")] | length' \
            "$json_out" 2>/dev/null)" || high_count=0

        if (( critical_count > 0 )); then
            add_finding "CRITICAL" "SSL/TLS" "testssl.sh found critical issues" \
                "${critical_count} critical findings from testssl.sh" \
                "Review testssl.sh report: $json_out"
        fi
        if (( high_count > 0 )); then
            add_finding "HIGH" "SSL/TLS" "testssl.sh found high severity issues" \
                "${high_count} high severity findings" \
                "Review testssl.sh report: $json_out"
        fi
    fi
}

# =============================================================================
# Heartbleed Test
# =============================================================================
ssl_heartbleed_check() {
    require_target || return
    require_tool nmap "Heartbleed check" || return
    separator
    echo -e "${BOLD}${WHITE}  Heartbleed Vulnerability Check${NC}"
    separator

    local host="$AUDIT_TARGET"
    local port="${1:-}"
    if [[ -z "$port" ]]; then
        echo -e "${YELLOW}Port (default: 443):${NC}"
        read -r port
    fi
    [[ -z "$port" ]] && port=443

    log INFO "Testing for Heartbleed (CVE-2014-0160) on ${host}:${port}"

    local result
    result="$(nmap -p "$port" --script ssl-heartbleed "$host" 2>/dev/null)" || true
    echo "$result"
    save_scan "heartbleed" "$result"

    if echo "$result" | grep -qi "VULNERABLE"; then
        add_finding "CRITICAL" "SSL/TLS" "Heartbleed vulnerability (CVE-2014-0160)" \
            "Server at ${host}:${port} is vulnerable to Heartbleed" \
            "Upgrade OpenSSL immediately and revoke/reissue certificates."
        echo -e "  ${RED}[✗]${NC} VULNERABLE to Heartbleed!"
    else
        echo -e "  ${GREEN}[✓]${NC} Not vulnerable to Heartbleed"
        add_finding "INFO" "SSL/TLS" "Heartbleed check passed" \
            "Not vulnerable to Heartbleed on ${host}:${port}" "N/A"
    fi

    log SUCCESS "Heartbleed check complete"
}

# =============================================================================
# Full SSL Audit
# =============================================================================
_ssl_run_with_port() {
    # Run an SSL function with a preset port (passed as argument, no prompt)
    local func="$1"
    local port="${2:-443}"
    "$func" "$port"
}

full_ssl_audit() {
    require_target || return
    log INFO "Starting full SSL/TLS audit on $AUDIT_TARGET"
    separator
    echo -e "${BOLD}${MAGENTA}  Running Full SSL/TLS Audit (port 443)${NC}"
    separator

    ssl_quick_check 443;        echo ""
    protocol_version_test 443;   echo ""
    cipher_suite_analysis 443;   echo ""
    certificate_chain_check 443; echo ""
    certificate_transparency;    echo ""
    hsts_check;                  echo ""
    ocsp_stapling_check 443;     echo ""
    ssl_heartbleed_check 443

    if command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
        echo ""
        testssl_integration 443
    fi

    log SUCCESS "Full SSL/TLS audit complete"
    show_findings_summary
}

# =============================================================================
# SSL Audit Menu
# =============================================================================
ssl_audit_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}${WHITE}  SSL/TLS & Certificate Audit${NC}"
        separator
        echo -e "  ${CYAN}[1]${NC}   SSL Quick Check"
        echo -e "  ${CYAN}[2]${NC}   Protocol Version Test"
        echo -e "  ${CYAN}[3]${NC}   Cipher Suite Analysis"
        echo -e "  ${CYAN}[4]${NC}   Certificate Chain Validation"
        echo -e "  ${CYAN}[5]${NC}   Certificate Transparency Lookup"
        echo -e "  ${CYAN}[6]${NC}   HSTS & Security Headers"
        echo -e "  ${CYAN}[7]${NC}   OCSP Stapling Check"
        echo -e "  ${CYAN}[8]${NC}   testssl.sh Full Scan"
        echo -e "  ${CYAN}[9]${NC}   Heartbleed Vulnerability Check"
        echo -e "  ${CYAN}[10]${NC}  Full SSL Audit (all above)"
        separator
        echo -e "  ${CYAN}[0]${NC}   Back to Main Menu"
        separator
        echo -e "${YELLOW}Select option [0-10]: ${NC}"
        read -r choice
        case "$choice" in
            1)  ssl_quick_check; press_enter ;;
            2)  protocol_version_test; press_enter ;;
            3)  cipher_suite_analysis; press_enter ;;
            4)  certificate_chain_check; press_enter ;;
            5)  certificate_transparency; press_enter ;;
            6)  hsts_check; press_enter ;;
            7)  ocsp_stapling_check; press_enter ;;
            8)  testssl_integration; press_enter ;;
            9)  ssl_heartbleed_check; press_enter ;;
            10) full_ssl_audit; press_enter ;;
            0)  return ;;
            *)  log WARN "Invalid option"; sleep 1 ;;
        esac
    done
}
