#!/usr/bin/env bash
# =============================================================================
# Network Security Audit Module
# ARP discovery, port scanning, OS fingerprinting, firewall detection,
# traffic capture, wireless scanning
# =============================================================================

# =============================================================================
# ARP Discovery
# =============================================================================
arp_discovery() {
    require_target || return
    separator
    echo -e "${BOLD}${WHITE}  ARP Network Discovery${NC}"
    separator

    # ARP is Layer 2 only - skip for internet targets
    if ! target_is_local_network "$AUDIT_TARGET"; then
        log WARN "ARP discovery only works on local network. Skipping for internet target."
        add_finding "INFO" "Network" "ARP Discovery skipped" \
            "Target is not on local network - ARP operates at Layer 2 only" "N/A"
        return 0
    fi

    local target_subnet="$AUDIT_TARGET"

    # Determine subnet if single local IP given
    if target_is_ip "$target_subnet" && [[ ! "$target_subnet" =~ / ]]; then
        target_subnet="${target_subnet%.*}.0/24"
        log INFO "Expanded target to subnet: $target_subnet"
    fi

    if command -v arp-scan &>/dev/null; then
        log INFO "Running ARP scan on $target_subnet"
        local result
        if [[ $EUID -eq 0 ]]; then
            result="$(arp-scan "$target_subnet" 2>/dev/null)" || true
        else
            result="$(sudo arp-scan "$target_subnet" 2>/dev/null)" || \
                result="ARP scan requires root privileges."
        fi
        echo "$result"
        save_scan "arp_discovery" "$result"
        local host_count
        host_count="$(echo "$result" | grep -cE '^[0-9]+\.' || true)"
        add_finding "INFO" "Network" "ARP Discovery Complete" \
            "${host_count} hosts discovered on ${target_subnet}" \
            "Review discovered hosts for unauthorized devices."
    elif command -v nmap &>/dev/null; then
        log INFO "arp-scan not found, falling back to nmap -sn"
        local result
        result="$(nmap -sn "$target_subnet" 2>/dev/null)" || true
        echo "$result"
        save_scan "arp_discovery_nmap" "$result"
        local host_count
        host_count="$(echo "$result" | grep -c 'Nmap scan report' || true)"
        add_finding "INFO" "Network" "Ping Sweep Discovery Complete" \
            "${host_count} hosts responded on ${target_subnet}" \
            "Review discovered hosts for unauthorized devices."
    else
        log ERROR "Neither arp-scan nor nmap available"
        return 1
    fi
}

# =============================================================================
# Ping Sweep
# =============================================================================
ping_sweep() {
    require_target || return
    require_tool nmap "ping sweep" || return
    separator
    echo -e "${BOLD}${WHITE}  ICMP Ping Sweep${NC}"
    separator

    local target_subnet="$AUDIT_TARGET"

    # Expand to /24 for local network IPs (LAN scan)
    if target_is_local_network "$target_subnet" && target_is_ip "$target_subnet" && \
       [[ ! "$target_subnet" =~ / ]]; then
        target_subnet="${target_subnet%.*}.0/24"
        log INFO "LAN target: expanded to subnet $target_subnet"
    fi

    log INFO "Ping sweeping $target_subnet"
    local result
    result="$(nmap -sn -PE -PP -PM "$target_subnet" 2>/dev/null)" || true
    echo "$result"
    save_scan "ping_sweep" "$result"

    local up_count
    up_count="$(echo "$result" | grep -c 'Host is up' || true)"
    add_finding "INFO" "Network" "Ping Sweep Results" \
        "${up_count} hosts responded to ICMP on ${target_subnet}" \
        "Hosts responding to ICMP may reveal network topology."
}

# =============================================================================
# Service Version Scan
# =============================================================================
service_version_scan() {
    require_target || return
    require_tool nmap "service scan" || return
    separator
    echo -e "${BOLD}${WHITE}  Service Version Detection${NC}"
    separator

    local port_range="${1:-}"
    if [[ -z "$port_range" && -t 0 ]]; then
        echo -e "${YELLOW}Port range (default: top 1000, or e.g. 1-65535):${NC}"
        read -r port_range
    fi

    local nmap_args=("-sV" "--version-intensity" "5" "-T4")
    [[ -n "$port_range" ]] && nmap_args+=("-p" "$port_range")
    nmap_args+=("$AUDIT_TARGET")

    log INFO "Running service version scan on $AUDIT_TARGET"
    local result
    result="$(nmap "${nmap_args[@]}" 2>/dev/null)" || true
    echo "$result"
    save_scan "service_version" "$result"

    # Check for outdated / risky services
    local risky_services=("ftp" "telnet" "rlogin" "rsh" "vnc" "smb")
    for svc in "${risky_services[@]}"; do
        if echo "$result" | grep -qi "$svc"; then
            add_finding "MEDIUM" "Network" "Risky service detected: $svc" \
                "$svc service found running on $AUDIT_TARGET" \
                "Consider disabling $svc or replacing with a secure alternative."
        fi
    done

    local open_count
    open_count="$(echo "$result" | grep -c '/open/' || echo "$result" | grep -c 'open' || true)"
    add_finding "INFO" "Network" "Service Version Scan Complete" \
        "${open_count} open ports detected on $AUDIT_TARGET" \
        "Review all open services and close unnecessary ones."
}

# =============================================================================
# OS Fingerprinting
# =============================================================================
os_fingerprint() {
    require_target || return
    require_tool nmap "OS detection" || return
    separator
    echo -e "${BOLD}${WHITE}  OS Fingerprinting${NC}"
    separator

    log INFO "Running OS detection on $AUDIT_TARGET"
    local result
    if [[ $EUID -eq 0 ]]; then
        result="$(nmap -O --osscan-guess "$AUDIT_TARGET" 2>/dev/null)" || true
    else
        log WARN "OS detection typically requires root. Attempting anyway..."
        result="$(nmap -O --osscan-guess "$AUDIT_TARGET" 2>/dev/null)" || \
            result="OS detection requires root privileges. Run with sudo."
    fi
    echo "$result"
    save_scan "os_fingerprint" "$result"

    local os_match
    os_match="$(echo "$result" | grep 'OS details\|Aggressive OS guesses\|Running:' | head -3 || true)"
    if [[ -n "$os_match" ]]; then
        add_finding "INFO" "Network" "OS Detection Results" \
            "$os_match" \
            "Verify OS version is current and patched."
    fi
}

# =============================================================================
# Firewall Detection
# =============================================================================
firewall_detect() {
    require_target || return
    require_tool nmap "firewall detection" || return
    separator
    echo -e "${BOLD}${WHITE}  Firewall / Packet Filter Detection${NC}"
    separator

    log INFO "Running ACK scan for firewall detection on $AUDIT_TARGET"
    local result
    if [[ $EUID -eq 0 ]]; then
        result="$(nmap -sA -T4 -p 80,443,22,21,25,53 "$AUDIT_TARGET" 2>/dev/null)" || true
    else
        result="$(nmap -sA -T4 -p 80,443,22,21,25,53 "$AUDIT_TARGET" 2>&1)" || true
    fi
    echo "$result"
    save_scan "firewall_detect" "$result"

    if echo "$result" | grep -q "filtered"; then
        add_finding "INFO" "Network" "Firewall detected" \
            "Filtered ports indicate a firewall is present on $AUDIT_TARGET" \
            "Ensure firewall rules follow least-privilege principle."
    else
        add_finding "MEDIUM" "Network" "No firewall detected" \
            "No evidence of packet filtering on $AUDIT_TARGET" \
            "Deploy a host-based firewall (iptables/nftables/ufw)."
    fi

    # Also try window scan
    if [[ $EUID -eq 0 ]]; then
        log INFO "Running Window scan for additional firewall analysis"
        local win_result
        win_result="$(nmap -sW -T4 -p 80,443,22 "$AUDIT_TARGET" 2>/dev/null)" || true
        echo "$win_result"
    fi
}

# =============================================================================
# Traceroute Analysis
# =============================================================================
traceroute_analysis() {
    require_target || return
    separator
    echo -e "${BOLD}${WHITE}  Traceroute / Network Path Analysis${NC}"
    separator

    log INFO "Tracing route to $AUDIT_TARGET"
    local result
    if command -v traceroute &>/dev/null; then
        result="$(traceroute -m 30 "$AUDIT_TARGET" 2>/dev/null)" || true
    elif command -v nmap &>/dev/null; then
        result="$(nmap --traceroute "$AUDIT_TARGET" 2>/dev/null)" || true
    else
        log WARN "No traceroute tool available"
        return 1
    fi
    echo "$result"
    save_scan "traceroute" "$result"

    local hop_count
    hop_count="$(echo "$result" | grep -cE '^\s*[0-9]+' || true)"
    add_finding "INFO" "Network" "Network Path Analysis" \
        "Route to $AUDIT_TARGET traverses ~${hop_count} hops" \
        "Review network path for unexpected routing."
}

# =============================================================================
# Traffic Capture
# =============================================================================
traffic_capture() {
    require_tool tcpdump "traffic capture" || return
    separator
    echo -e "${BOLD}${WHITE}  Network Traffic Capture${NC}"
    separator

    echo -e "${YELLOW}Capture interface (default: any):${NC}"
    read -r iface
    [[ -z "$iface" ]] && iface="any"

    echo -e "${YELLOW}Capture duration in seconds (default: 30):${NC}"
    read -r duration
    [[ -z "$duration" ]] && duration=30

    echo -e "${YELLOW}BPF filter (default: none, e.g. 'port 80'):${NC}"
    read -r bpf_filter

    local pcap_file="$SESSION_DIR/scans/capture_${SESSION_ID}.pcap"
    local tcpdump_args=("-i" "$iface" "-c" "10000" "-w" "$pcap_file")
    [[ -n "$bpf_filter" ]] && tcpdump_args+=($bpf_filter)

    log INFO "Capturing traffic on $iface for ${duration}s"
    if [[ $EUID -eq 0 ]]; then
        timeout "$duration" tcpdump "${tcpdump_args[@]}" 2>/dev/null &
        local pid=$!
        echo -e "${DIM}Capturing... (PID: $pid, ${duration}s)${NC}"
        wait $pid 2>/dev/null || true
    else
        log WARN "Traffic capture requires root privileges"
        return 1
    fi

    if [[ -f "$pcap_file" ]]; then
        local pkt_count
        pkt_count="$(tcpdump -r "$pcap_file" 2>/dev/null | wc -l || true)"
        log SUCCESS "Captured ${pkt_count} packets to $pcap_file"
        add_finding "INFO" "Network" "Traffic Capture Complete" \
            "Captured ${pkt_count} packets on interface $iface" \
            "Review capture for suspicious traffic patterns."

        # Basic analysis if tshark available
        if command -v tshark &>/dev/null; then
            echo -e "\n${WHITE}Protocol Distribution:${NC}"
            tshark -r "$pcap_file" -q -z io,phs 2>/dev/null | head -30 || true
        fi
    fi
}

# =============================================================================
# Wireless Interface Scan
# =============================================================================
wireless_scan() {
    separator
    echo -e "${BOLD}${WHITE}  Wireless Interface Detection${NC}"
    separator

    if [[ "$AUDIT_MODE" == "remote" ]]; then
        log INFO "Wireless scan shows local interfaces (not related to remote target)"
        echo -e "  ${DIM}Note: This scans YOUR local wireless interfaces${NC}"
    fi

    local found_wireless=0

    if command -v iw &>/dev/null; then
        log INFO "Enumerating wireless interfaces with iw"
        local iw_result
        iw_result="$(iw dev 2>/dev/null)" || true
        echo "$iw_result"
        if [[ -n "$iw_result" ]]; then
            found_wireless=1
            save_scan "wireless_iw" "$iw_result"

            # Try scanning if root
            if [[ $EUID -eq 0 ]]; then
                local wlan_iface
                wlan_iface="$(echo "$iw_result" | awk '/Interface/{print $2}' | head -1)"
                if [[ -n "$wlan_iface" ]]; then
                    log INFO "Scanning on $wlan_iface"
                    local scan_result
                    scan_result="$(iw dev "$wlan_iface" scan 2>/dev/null | \
                        grep -E 'BSS|SSID|signal|freq|capability' | head -50)" || true
                    echo "$scan_result"
                    save_scan "wireless_scan" "$scan_result"
                fi
            fi
        fi
    elif command -v iwlist &>/dev/null; then
        log INFO "Enumerating wireless interfaces with iwlist"
        local iwlist_result
        iwlist_result="$(iwlist scan 2>/dev/null | head -50)" || \
            iwlist_result="iwlist scan requires root."
        echo "$iwlist_result"
        [[ -n "$iwlist_result" ]] && found_wireless=1
    fi

    if [[ $found_wireless -eq 0 ]]; then
        log INFO "No wireless interfaces detected"
        add_finding "INFO" "Network" "No wireless interfaces" \
            "No wireless interfaces detected on this system" \
            "N/A"
    else
        add_finding "INFO" "Network" "Wireless interfaces detected" \
            "Wireless interfaces found on this system" \
            "Ensure wireless interfaces are secured with WPA3/WPA2."
    fi
}

# =============================================================================
# Full Network Audit
# =============================================================================
full_network_audit() {
    require_target || return
    log INFO "Starting full network audit on $AUDIT_TARGET (mode: $AUDIT_MODE)"
    separator
    echo -e "${BOLD}${MAGENTA}  Running Full Network Audit${NC}"
    separator

    if target_is_local_network "$AUDIT_TARGET"; then
        arp_discovery
        echo ""
        ping_sweep
        echo ""
    else
        log INFO "Skipping ARP/ping sweep (internet target - not on local network)"
    fi

    service_version_scan ""
    echo ""
    os_fingerprint
    echo ""
    firewall_detect
    echo ""
    traceroute_analysis

    if [[ "$AUDIT_MODE" == "local" ]]; then
        echo ""
        wireless_scan
    fi

    log SUCCESS "Full network audit complete"
    show_findings_summary
}

# =============================================================================
# Network Audit Menu
# =============================================================================
network_audit_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}${WHITE}  Network Security Audit${NC}"
        separator
        echo -e "  ${CYAN}[1]${NC}  ARP Host Discovery"
        echo -e "  ${CYAN}[2]${NC}  ICMP Ping Sweep"
        echo -e "  ${CYAN}[3]${NC}  Service Version Detection"
        echo -e "  ${CYAN}[4]${NC}  OS Fingerprinting"
        echo -e "  ${CYAN}[5]${NC}  Firewall / Packet Filter Detection"
        echo -e "  ${CYAN}[6]${NC}  Traceroute / Path Analysis"
        echo -e "  ${CYAN}[7]${NC}  Traffic Capture (tcpdump)"
        echo -e "  ${CYAN}[8]${NC}  Wireless Interface Scan"
        echo -e "  ${CYAN}[9]${NC}  Full Network Audit (all above)"
        separator
        echo -e "  ${CYAN}[0]${NC}  Back to Main Menu"
        separator
        echo -e "${YELLOW}Select option [0-9]: ${NC}"
        read -r choice
        case "$choice" in
            1) arp_discovery; press_enter ;;
            2) ping_sweep; press_enter ;;
            3) service_version_scan; press_enter ;;
            4) os_fingerprint; press_enter ;;
            5) firewall_detect; press_enter ;;
            6) traceroute_analysis; press_enter ;;
            7) traffic_capture; press_enter ;;
            8) wireless_scan; press_enter ;;
            9) full_network_audit; press_enter ;;
            0) return ;;
            *) log WARN "Invalid option"; sleep 1 ;;
        esac
    done
}
