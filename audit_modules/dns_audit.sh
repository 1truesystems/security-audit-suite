#!/usr/bin/env bash
# =============================================================================
# DNS Security Audit Module
# Zone transfers, DNSSEC, enumeration, SPF/DKIM/DMARC, cache testing
# =============================================================================

# =============================================================================
# Zone Transfer Test
# =============================================================================
zone_transfer_test() {
    require_target || return
    require_tool dig "zone transfer" || return
    separator
    echo -e "${BOLD}${WHITE}  DNS Zone Transfer Test (AXFR)${NC}"
    separator

    local domain="$AUDIT_TARGET"
    log INFO "Testing zone transfer for $domain"

    # Get authoritative nameservers
    local nameservers
    nameservers="$(dig +short NS "$domain" 2>/dev/null)" || true

    if [[ -z "$nameservers" ]]; then
        log WARN "Could not resolve nameservers for $domain"
        return 1
    fi

    echo -e "${WHITE}Nameservers for ${domain}:${NC}"
    echo "$nameservers"

    local transfer_success=0
    while IFS= read -r ns; do
        [[ -z "$ns" ]] && continue
        ns="${ns%.}"  # Remove trailing dot
        echo -e "\n${WHITE}Testing AXFR against: ${ns}${NC}"
        local axfr_result
        axfr_result="$(dig @"$ns" "$domain" AXFR +noall +answer 2>/dev/null)" || true

        if [[ -n "$axfr_result" ]]; then
            local record_count
            record_count="$(echo "$axfr_result" | wc -l)"
            if (( record_count > 2 )); then
                echo -e "  ${RED}[✗]${NC} Zone transfer SUCCEEDED (${record_count} records)"
                echo "$axfr_result" | head -20
                save_scan "zone_transfer_${ns}" "$axfr_result"
                transfer_success=1
                add_finding "HIGH" "DNS" "Zone transfer allowed on $ns" \
                    "AXFR transfer returned ${record_count} records from $ns for $domain" \
                    "Restrict zone transfers to authorized secondary DNS servers only."
            else
                echo -e "  ${GREEN}[✓]${NC} Zone transfer denied"
            fi
        else
            echo -e "  ${GREEN}[✓]${NC} Zone transfer denied"
        fi
    done <<< "$nameservers"

    if [[ $transfer_success -eq 0 ]]; then
        add_finding "INFO" "DNS" "Zone transfers properly restricted" \
            "No nameserver allows AXFR zone transfer for $domain" "N/A"
    fi

    log SUCCESS "Zone transfer test complete"
}

# =============================================================================
# DNSSEC Validation
# =============================================================================
dnssec_validation() {
    require_target || return
    require_tool dig "DNSSEC check" || return
    separator
    echo -e "${BOLD}${WHITE}  DNSSEC Validation${NC}"
    separator

    local domain="$AUDIT_TARGET"
    log INFO "Checking DNSSEC for $domain"

    # Check DNSKEY
    echo -e "\n${WHITE}DNSKEY Records:${NC}"
    local dnskey
    dnskey="$(dig +short DNSKEY "$domain" 2>/dev/null)" || true
    if [[ -n "$dnskey" ]]; then
        echo -e "  ${GREEN}[✓]${NC} DNSKEY records found"
        echo "$dnskey" | head -5
    else
        echo -e "  ${YELLOW}[⚠]${NC} No DNSKEY records"
    fi

    # Check DS records
    echo -e "\n${WHITE}DS Records:${NC}"
    local ds
    ds="$(dig +short DS "$domain" 2>/dev/null)" || true
    if [[ -n "$ds" ]]; then
        echo -e "  ${GREEN}[✓]${NC} DS records found"
        echo "$ds"
    else
        echo -e "  ${YELLOW}[⚠]${NC} No DS records"
    fi

    # Check RRSIG
    echo -e "\n${WHITE}RRSIG Records:${NC}"
    local rrsig
    rrsig="$(dig +dnssec +short RRSIG "$domain" 2>/dev/null)" || true
    if [[ -n "$rrsig" ]]; then
        echo -e "  ${GREEN}[✓]${NC} RRSIG records found (zone is signed)"
        echo "$rrsig" | head -3
    else
        echo -e "  ${YELLOW}[⚠]${NC} No RRSIG records"
    fi

    # Validate DNSSEC chain
    echo -e "\n${WHITE}DNSSEC Validation:${NC}"
    local validation
    validation="$(dig +sigchase +trusted-key=/etc/trusted-key.key "$domain" A 2>/dev/null)" || \
        validation="$(dig +dnssec "$domain" A 2>/dev/null)" || true

    if echo "$validation" | grep -qi "ad" && dig +dnssec "$domain" 2>/dev/null | grep -q "flags.*ad"; then
        echo -e "  ${GREEN}[✓]${NC} DNSSEC validates (AD flag set)"
        add_finding "INFO" "DNS" "DNSSEC enabled and validating" \
            "DNSSEC is properly configured for $domain" "N/A"
    elif [[ -n "$dnskey" && -n "$rrsig" ]]; then
        echo -e "  ${YELLOW}[⚠]${NC} DNSSEC present but validation uncertain"
        add_finding "LOW" "DNS" "DNSSEC partially configured" \
            "DNSKEY and RRSIG present but full validation not confirmed" \
            "Verify DNSSEC chain of trust is complete."
    else
        echo -e "  ${RED}[✗]${NC} DNSSEC not enabled"
        add_finding "MEDIUM" "DNS" "DNSSEC not enabled" \
            "No DNSSEC signing detected for $domain" \
            "Implement DNSSEC to prevent DNS spoofing and cache poisoning."
    fi

    log SUCCESS "DNSSEC validation complete"
}

# =============================================================================
# DNS Enumeration
# =============================================================================
dns_enumeration() {
    require_target || return
    require_tool dig "DNS enumeration" || return
    separator
    echo -e "${BOLD}${WHITE}  DNS Record Enumeration${NC}"
    separator

    local domain="$AUDIT_TARGET"
    log INFO "Enumerating DNS records for $domain"

    local record_types=("A" "AAAA" "MX" "NS" "TXT" "SOA" "CNAME" "SRV" "CAA" "PTR")
    local all_results=""

    for rtype in "${record_types[@]}"; do
        echo -e "\n${WHITE}${rtype} Records:${NC}"
        local result
        result="$(dig +short "$rtype" "$domain" 2>/dev/null)" || true
        if [[ -n "$result" ]]; then
            echo "$result"
            all_results+="${rtype}: ${result}"$'\n'
        else
            echo -e "  ${DIM}(none)${NC}"
        fi
    done

    # Common subdomain check
    echo -e "\n${WHITE}Common Subdomain Check:${NC}"
    local subdomains=("www" "mail" "ftp" "smtp" "pop" "imap" "webmail" \
        "admin" "vpn" "remote" "dev" "staging" "test" "api" "ns1" "ns2" \
        "mx" "autodiscover" "portal" "cdn" "cloud")

    for sub in "${subdomains[@]}"; do
        local sub_result
        sub_result="$(dig +short A "${sub}.${domain}" 2>/dev/null)" || true
        if [[ -n "$sub_result" ]]; then
            echo -e "  ${GREEN}[✓]${NC} ${sub}.${domain} -> $sub_result"
            all_results+="${sub}.${domain}: ${sub_result}"$'\n'
        fi
    done

    save_scan "dns_enumeration" "$all_results"
    add_finding "INFO" "DNS" "DNS Enumeration Complete" \
        "Enumerated DNS records for $domain" "N/A"
    log SUCCESS "DNS enumeration complete"
}

# =============================================================================
# SPF Check
# =============================================================================
spf_check() {
    require_target || return
    require_tool dig "SPF check" || return
    separator
    echo -e "${BOLD}${WHITE}  SPF Record Analysis${NC}"
    separator

    local domain="$AUDIT_TARGET"
    log INFO "Checking SPF for $domain"

    local spf
    spf="$(dig +short TXT "$domain" 2>/dev/null | grep -i 'v=spf1')" || true

    if [[ -n "$spf" ]]; then
        echo -e "  ${GREEN}[✓]${NC} SPF record found:"
        echo "  $spf"

        # Parse SPF
        if echo "$spf" | grep -q '+all'; then
            add_finding "HIGH" "DNS" "SPF allows all senders (+all)" \
                "SPF policy is '+all' - any server can send as $domain" \
                "Change SPF to use '-all' (hard fail) or '~all' (soft fail)."
            echo -e "  ${RED}[✗]${NC} Policy: +all (PERMISSIVE)"
        elif echo "$spf" | grep -q '~all'; then
            add_finding "LOW" "DNS" "SPF soft fail (~all)" \
                "SPF uses soft fail - emails from unauthorized servers only marked" \
                "Consider using '-all' (hard fail) for stricter enforcement."
            echo -e "  ${YELLOW}[⚠]${NC} Policy: ~all (soft fail)"
        elif echo "$spf" | grep -q '\-all'; then
            echo -e "  ${GREEN}[✓]${NC} Policy: -all (hard fail - strict)"
        elif echo "$spf" | grep -q '?all'; then
            add_finding "MEDIUM" "DNS" "SPF neutral policy (?all)" \
                "SPF uses neutral policy - no enforcement" \
                "Change to '-all' for proper email authentication."
            echo -e "  ${YELLOW}[⚠]${NC} Policy: ?all (neutral)"
        fi

        # Check for too many lookups
        local lookup_count
        lookup_count="$(echo "$spf" | grep -oE '(include|redirect|a |mx |ptr )' | wc -l)" || true
        if (( lookup_count > 8 )); then
            add_finding "LOW" "DNS" "SPF record has many lookups" \
                "SPF has ~${lookup_count} mechanisms (limit is 10 DNS lookups)" \
                "Reduce SPF lookups to stay under the 10-lookup limit."
        fi
    else
        echo -e "  ${RED}[✗]${NC} No SPF record found"
        add_finding "MEDIUM" "DNS" "No SPF record" \
            "No SPF TXT record found for $domain" \
            "Add an SPF record: v=spf1 include:<mail_provider> -all"
    fi

    log SUCCESS "SPF check complete"
}

# =============================================================================
# DKIM Check
# =============================================================================
dkim_check() {
    require_target || return
    require_tool dig "DKIM check" || return
    separator
    echo -e "${BOLD}${WHITE}  DKIM Record Check${NC}"
    separator

    local domain="$AUDIT_TARGET"
    log INFO "Checking DKIM for $domain"

    # Common DKIM selectors to try
    local selectors=("default" "google" "dkim" "mail" "selector1" "selector2" \
        "s1" "s2" "k1" "k2" "sig1" "smtp" "mandrill" "everlytickey1" \
        "mxvault" "dk")

    local found_dkim=0
    for sel in "${selectors[@]}"; do
        local dkim_result
        dkim_result="$(dig +short TXT "${sel}._domainkey.${domain}" 2>/dev/null)" || true
        if [[ -n "$dkim_result" && "$dkim_result" != *"NXDOMAIN"* ]]; then
            echo -e "  ${GREEN}[✓]${NC} DKIM found: ${sel}._domainkey.${domain}"
            echo "  $dkim_result"
            found_dkim=1

            # Check key length if visible
            if echo "$dkim_result" | grep -qiE 'p=[A-Za-z0-9+/]'; then
                local key_data
                key_data="$(echo "$dkim_result" | grep -oE 'p=[A-Za-z0-9+/=]+' | cut -d= -f2-)"
                local key_len=${#key_data}
                if (( key_len < 200 )); then
                    add_finding "MEDIUM" "DNS" "Short DKIM key for selector $sel" \
                        "DKIM key appears to be 1024-bit or less" \
                        "Upgrade to 2048-bit DKIM key."
                fi
            fi
        fi
    done

    if [[ $found_dkim -eq 0 ]]; then
        echo -e "  ${YELLOW}[⚠]${NC} No DKIM records found with common selectors"
        add_finding "MEDIUM" "DNS" "No DKIM records found" \
            "No DKIM records found for $domain with common selectors" \
            "Configure DKIM email authentication for your domain."
    else
        add_finding "INFO" "DNS" "DKIM configured" \
            "DKIM records found for $domain" "N/A"
    fi

    log SUCCESS "DKIM check complete"
}

# =============================================================================
# DMARC Check
# =============================================================================
dmarc_check() {
    require_target || return
    require_tool dig "DMARC check" || return
    separator
    echo -e "${BOLD}${WHITE}  DMARC Policy Analysis${NC}"
    separator

    local domain="$AUDIT_TARGET"
    log INFO "Checking DMARC for $domain"

    local dmarc
    dmarc="$(dig +short TXT "_dmarc.${domain}" 2>/dev/null)" || true

    if [[ -n "$dmarc" && "$dmarc" == *"v=DMARC1"* ]]; then
        echo -e "  ${GREEN}[✓]${NC} DMARC record found:"
        echo "  $dmarc"

        # Parse policy
        local policy
        policy="$(echo "$dmarc" | grep -oiE 'p=(none|quarantine|reject)' | head -1 | cut -d= -f2)" || true

        case "${policy,,}" in
            reject)
                echo -e "  ${GREEN}[✓]${NC} Policy: reject (strict - best)"
                ;;
            quarantine)
                echo -e "  ${YELLOW}[⚠]${NC} Policy: quarantine (moderate)"
                add_finding "LOW" "DNS" "DMARC policy is quarantine" \
                    "DMARC policy is 'quarantine' - spoofed emails may reach spam" \
                    "Consider upgrading to 'p=reject' for full protection."
                ;;
            none)
                echo -e "  ${RED}[✗]${NC} Policy: none (monitoring only)"
                add_finding "MEDIUM" "DNS" "DMARC policy is none" \
                    "DMARC is in monitoring mode - no enforcement" \
                    "Set DMARC policy to 'p=quarantine' or 'p=reject'."
                ;;
        esac

        # Check subdomain policy
        local sp
        sp="$(echo "$dmarc" | grep -oiE 'sp=(none|quarantine|reject)' | cut -d= -f2)" || true
        [[ -n "$sp" ]] && echo -e "  ${DIM}Subdomain policy: $sp${NC}"

        # Check reporting
        if echo "$dmarc" | grep -qiE 'rua='; then
            echo -e "  ${GREEN}[✓]${NC} Aggregate reporting (rua) configured"
        else
            echo -e "  ${YELLOW}[⚠]${NC} No aggregate reporting (rua)"
        fi

        if echo "$dmarc" | grep -qiE 'ruf='; then
            echo -e "  ${GREEN}[✓]${NC} Forensic reporting (ruf) configured"
        fi

        # Check percentage
        local pct
        pct="$(echo "$dmarc" | grep -oiE 'pct=([0-9]+)' | cut -d= -f2)" || true
        if [[ -n "$pct" && "$pct" -lt 100 ]]; then
            echo -e "  ${YELLOW}[⚠]${NC} Only ${pct}% of mail subject to DMARC"
            add_finding "LOW" "DNS" "DMARC partial enforcement" \
                "DMARC pct=${pct} - only ${pct}% of mail checked" \
                "Set pct=100 for full DMARC enforcement."
        fi
    else
        echo -e "  ${RED}[✗]${NC} No DMARC record found"
        add_finding "MEDIUM" "DNS" "No DMARC record" \
            "No DMARC record found for $domain" \
            "Add DMARC: _dmarc.${domain} TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@${domain}\""
    fi

    log SUCCESS "DMARC check complete"
}

# =============================================================================
# DNS Cache Test
# =============================================================================
dns_cache_test() {
    require_target || return
    require_tool dig "DNS cache test" || return
    separator
    echo -e "${BOLD}${WHITE}  DNS Cache & Source Port Randomization Test${NC}"
    separator

    local domain="$AUDIT_TARGET"
    log INFO "Testing DNS resolver security for $domain"

    # Check source port randomization
    echo -e "\n${WHITE}Source Port Randomization:${NC}"
    local port_test
    port_test="$(dig +short porttest.dns-oarc.net TXT @$(dig +short NS "$domain" | head -1) 2>/dev/null)" || \
        port_test="$(dig +short porttest.dns-oarc.net TXT 2>/dev/null)" || true

    if [[ -n "$port_test" ]]; then
        echo "  $port_test"
        if echo "$port_test" | grep -qi "GREAT\|GOOD"; then
            echo -e "  ${GREEN}[✓]${NC} Source port randomization appears adequate"
        else
            add_finding "MEDIUM" "DNS" "Weak source port randomization" \
                "DNS resolver may be vulnerable to cache poisoning" \
                "Configure DNS resolver for better source port randomization."
        fi
    else
        echo -e "  ${DIM}Could not perform port test${NC}"
    fi

    # Test for open resolver
    echo -e "\n${WHITE}Open Resolver Check:${NC}"
    local ns_list
    ns_list="$(dig +short NS "$domain" 2>/dev/null)" || true
    while IFS= read -r ns; do
        [[ -z "$ns" ]] && continue
        ns="${ns%.}"
        local open_test
        open_test="$(dig @"$ns" example.com A +short +time=3 +tries=1 2>/dev/null)" || true
        if [[ -n "$open_test" ]]; then
            echo -e "  ${YELLOW}[⚠]${NC} $ns resolves external queries (potential open resolver)"
            add_finding "MEDIUM" "DNS" "Potential open DNS resolver: $ns" \
                "$ns resolves queries for external domains" \
                "Configure DNS server to only resolve for authorized clients."
        else
            echo -e "  ${GREEN}[✓]${NC} $ns properly restricts recursive queries"
        fi
    done <<< "$ns_list"

    # Check DNS response time
    echo -e "\n${WHITE}DNS Response Time:${NC}"
    local start_time end_time dns_time
    start_time="$(date +%s%N)"
    dig +short A "$domain" &>/dev/null
    end_time="$(date +%s%N)"
    dns_time=$(( (end_time - start_time) / 1000000 ))
    echo -e "  Response time: ${dns_time}ms"

    log SUCCESS "DNS cache test complete"
}

# =============================================================================
# Reverse DNS Audit
# =============================================================================
reverse_dns_audit() {
    require_target || return
    require_tool dig "reverse DNS" || return
    separator
    echo -e "${BOLD}${WHITE}  Reverse DNS (PTR) Audit${NC}"
    separator

    local target="$AUDIT_TARGET"
    log INFO "Checking reverse DNS for $target"

    # Resolve to IP if hostname
    local ip
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip="$target"
    else
        ip="$(dig +short A "$target" 2>/dev/null | head -1)" || true
    fi

    if [[ -z "$ip" ]]; then
        log WARN "Could not resolve IP for $target"
        return 1
    fi

    echo -e "  IP: $ip"

    # PTR lookup
    local ptr
    ptr="$(dig +short -x "$ip" 2>/dev/null)" || true

    if [[ -n "$ptr" ]]; then
        echo -e "  ${GREEN}[✓]${NC} PTR record: $ptr"

        # Forward confirmation
        local fwd
        fwd="$(dig +short A "${ptr%.}" 2>/dev/null)" || true
        if echo "$fwd" | grep -q "$ip"; then
            echo -e "  ${GREEN}[✓]${NC} Forward-confirmed reverse DNS (FCrDNS)"
            add_finding "INFO" "DNS" "PTR record configured and confirmed" \
                "Reverse DNS for $ip -> $ptr -> $ip (FCrDNS valid)" "N/A"
        else
            echo -e "  ${YELLOW}[⚠]${NC} PTR does not forward-confirm (FCrDNS mismatch)"
            add_finding "LOW" "DNS" "FCrDNS mismatch" \
                "PTR for $ip -> $ptr but forward lookup doesn't match" \
                "Ensure PTR and A records are consistent."
        fi
    else
        echo -e "  ${YELLOW}[⚠]${NC} No PTR record for $ip"
        add_finding "LOW" "DNS" "No reverse DNS record" \
            "No PTR record exists for $ip" \
            "Configure reverse DNS for the IP address."
    fi

    log SUCCESS "Reverse DNS audit complete"
}

# =============================================================================
# Full DNS Audit
# =============================================================================
full_dns_audit() {
    require_target || return
    if target_is_ip "$AUDIT_TARGET"; then
        log WARN "Target is an IP address. DNS audit works best with domain names."
        echo -e "  ${YELLOW}[⚠] DNS checks expect a domain name. Some checks may not work with IP: $AUDIT_TARGET${NC}"
    fi
    log INFO "Starting full DNS security audit on $AUDIT_TARGET"
    separator
    echo -e "${BOLD}${MAGENTA}  Running Full DNS Audit${NC}"
    separator

    zone_transfer_test;   echo ""
    dnssec_validation;    echo ""
    dns_enumeration;      echo ""
    spf_check;            echo ""
    dkim_check;           echo ""
    dmarc_check;          echo ""
    dns_cache_test;       echo ""
    reverse_dns_audit

    log SUCCESS "Full DNS audit complete"
    show_findings_summary
}

# =============================================================================
# DNS Audit Menu
# =============================================================================
dns_audit_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}${WHITE}  DNS Security Audit${NC}"
        separator
        echo -e "  ${CYAN}[1]${NC}  Zone Transfer Test (AXFR)"
        echo -e "  ${CYAN}[2]${NC}  DNSSEC Validation"
        echo -e "  ${CYAN}[3]${NC}  DNS Record Enumeration"
        echo -e "  ${CYAN}[4]${NC}  SPF Record Analysis"
        echo -e "  ${CYAN}[5]${NC}  DKIM Record Check"
        echo -e "  ${CYAN}[6]${NC}  DMARC Policy Analysis"
        echo -e "  ${CYAN}[7]${NC}  DNS Cache & Resolver Test"
        echo -e "  ${CYAN}[8]${NC}  Reverse DNS (PTR) Audit"
        echo -e "  ${CYAN}[9]${NC}  Full DNS Audit (all above)"
        separator
        echo -e "  ${CYAN}[0]${NC}  Back to Main Menu"
        separator
        echo -e "${YELLOW}Select option [0-9]: ${NC}"
        read -r choice
        case "$choice" in
            1) zone_transfer_test; press_enter ;;
            2) dnssec_validation; press_enter ;;
            3) dns_enumeration; press_enter ;;
            4) spf_check; press_enter ;;
            5) dkim_check; press_enter ;;
            6) dmarc_check; press_enter ;;
            7) dns_cache_test; press_enter ;;
            8) reverse_dns_audit; press_enter ;;
            9) full_dns_audit; press_enter ;;
            0) return ;;
            *) log WARN "Invalid option"; sleep 1 ;;
        esac
    done
}
