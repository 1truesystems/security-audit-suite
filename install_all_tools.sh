#!/usr/bin/env bash
# =============================================================================
#
#   ╔══════════════════════════════════════════════════════════════╗
#   ║       SECURITY AUDIT SUITE - FULL TOOL INSTALLER           ║
#   ║       Complete Security Tool Installer                     ║
#   ╠═════════════════════════════════════════════════════════════╣
#   ║  Zorin OS / Ubuntu / Debian / Raspberry Pi Compatible      ║
#   ╚══════════════════════════════════════════════════════════════╝
#
#   Usage:  sudo ./install_all_tools.sh
#           sudo ./install_all_tools.sh --all
#           sudo ./install_all_tools.sh --category network
#           sudo ./install_all_tools.sh --list
#
# =============================================================================

set -euo pipefail

# ── Prevent interactive prompts during install ───────────────────────────────
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Counters ─────────────────────────────────────────────────────────────────
INSTALLED=0
SKIPPED=0
FAILED=0
NOT_IN_REPO=0
TOTAL=0

# ── Failed packages log ─────────────────────────────────────────────────────
declare -a FAILED_LIST=()

# =============================================================================
# Helper Functions
# =============================================================================
separator() {
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
}

banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
    ╔══════════════════════════════════════════════════════════════╗
    ║  ___           _        _ _   _____           _            ║
    ║ |_ _|_ __  ___| |_ __ _| | | |_   _|__   ___ | |___        ║
    ║  | || '_ \/ __| __/ _` | | |   | |/ _ \ / _ \| / __|       ║
    ║  | || | | \__ \ || (_| | | |   | | (_) | (_) | \__ \       ║
    ║ |___|_| |_|___/\__\__,_|_|_|   |_|\___/ \___/|_|___/       ║
    ║                                                             ║
    ║         SECURITY AUDIT SUITE - FULL INSTALLER               ║
    ╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[✗] This script must be run as root (sudo)${NC}"
        echo -e "${DIM}  Usage: sudo $0${NC}"
        exit 1
    fi
}

# ── APT install with proper error handling ───────────────────────────────────
install_pkg() {
    local pkg="$1"
    local description="$2"
    local check_cmd="${3:-$pkg}"

    TOTAL=$((TOTAL + 1))

    # Check if already installed (by command OR dpkg)
    if command -v "$check_cmd" &>/dev/null || dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
        echo -e "  ${GREEN}[✓]${NC} ${WHITE}${pkg}${NC} - ${DIM}${description}${NC} ${GREEN}(already installed)${NC}"
        SKIPPED=$((SKIPPED + 1))
        return 0
    fi

    # Check if package exists in repo first
    if ! apt-cache show "$pkg" &>/dev/null; then
        echo -e "  ${RED}[✗]${NC} ${WHITE}${pkg}${NC} - ${description} ${RED}(not in repo)${NC}"
        NOT_IN_REPO=$((NOT_IN_REPO + 1))
        FAILED_LIST+=("$pkg (not in repo)")
        return 1
    fi

    # Install
    echo -ne "  ${YELLOW}[⟳]${NC} ${WHITE}${pkg}${NC} - ${description}... "
    local install_log
    install_log="$(apt-get install -y -q "$pkg" 2>&1)" || true

    # Verify installation
    if command -v "$check_cmd" &>/dev/null || dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
        echo -e "${GREEN}INSTALLED${NC}"
        INSTALLED=$((INSTALLED + 1))
    else
        # Show last 2 lines of error
        local err
        err="$(echo "$install_log" | grep -iE 'error|unable|fail|unmet' | tail -2)"
        echo -e "${RED}FAILED${NC}"
        [[ -n "$err" ]] && echo -e "         ${DIM}${err}${NC}"
        FAILED=$((FAILED + 1))
        FAILED_LIST+=("$pkg")
    fi
}

# ── Library install (no command to check) ────────────────────────────────────
install_lib() {
    local pkg="$1"
    local description="$2"

    TOTAL=$((TOTAL + 1))

    if dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
        echo -e "  ${GREEN}[✓]${NC} ${WHITE}${pkg}${NC} - ${DIM}${description}${NC} ${GREEN}(already installed)${NC}"
        SKIPPED=$((SKIPPED + 1))
        return 0
    fi

    if ! apt-cache show "$pkg" &>/dev/null; then
        echo -e "  ${RED}[✗]${NC} ${WHITE}${pkg}${NC} - ${description} ${RED}(not in repo)${NC}"
        NOT_IN_REPO=$((NOT_IN_REPO + 1))
        FAILED_LIST+=("$pkg (not in repo)")
        return 1
    fi

    echo -ne "  ${YELLOW}[⟳]${NC} ${WHITE}${pkg}${NC} - ${description}... "
    apt-get install -y -q "$pkg" &>/dev/null || true

    if dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
        echo -e "${GREEN}INSTALLED${NC}"
        INSTALLED=$((INSTALLED + 1))
    else
        echo -e "${RED}FAILED${NC}"
        FAILED=$((FAILED + 1))
        FAILED_LIST+=("$pkg")
    fi
}

# ── Pip install ──────────────────────────────────────────────────────────────
install_pip() {
    local pkg="$1"
    local description="$2"
    local check_cmd="${3:-$pkg}"

    TOTAL=$((TOTAL + 1))

    if command -v "$check_cmd" &>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} ${WHITE}${pkg}${NC} - ${DIM}${description}${NC} ${GREEN}(already installed)${NC}"
        SKIPPED=$((SKIPPED + 1))
        return 0
    fi

    if ! command -v pip3 &>/dev/null && ! command -v pipx &>/dev/null; then
        echo -e "  ${RED}[✗]${NC} ${WHITE}${pkg}${NC} - ${description} ${RED}(pip3/pipx not available)${NC}"
        FAILED=$((FAILED + 1))
        FAILED_LIST+=("$pkg (needs pip3)")
        return 1
    fi

    echo -ne "  ${YELLOW}[⟳]${NC} ${WHITE}${pkg}${NC} - ${description} ${DIM}(pip)${NC}... "

    if command -v pipx &>/dev/null; then
        pipx install "$pkg" &>/dev/null || pip3 install --break-system-packages "$pkg" &>/dev/null || true
    else
        pip3 install --break-system-packages "$pkg" &>/dev/null || pip3 install "$pkg" &>/dev/null || true
    fi

    if command -v "$check_cmd" &>/dev/null; then
        echo -e "${GREEN}INSTALLED${NC}"
        INSTALLED=$((INSTALLED + 1))
    else
        echo -e "${RED}FAILED${NC}"
        FAILED=$((FAILED + 1))
        FAILED_LIST+=("$pkg (pip)")
    fi
}

# ── Git clone install ────────────────────────────────────────────────────────
install_git() {
    local repo_url="$1"
    local name="$2"
    local description="$3"
    local check_cmd="${4:-}"
    local install_dir="/opt/${name}"

    TOTAL=$((TOTAL + 1))

    if [[ -n "$check_cmd" ]] && command -v "$check_cmd" &>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} ${WHITE}${name}${NC} - ${DIM}${description}${NC} ${GREEN}(already installed)${NC}"
        SKIPPED=$((SKIPPED + 1))
        return 0
    fi

    if [[ -d "$install_dir" ]]; then
        echo -e "  ${GREEN}[✓]${NC} ${WHITE}${name}${NC} - ${DIM}${description}${NC} ${GREEN}(already in ${install_dir})${NC}"
        SKIPPED=$((SKIPPED + 1))
        return 0
    fi

    echo -ne "  ${YELLOW}[⟳]${NC} ${WHITE}${name}${NC} - ${description} ${DIM}(git)${NC}... "
    if git clone --depth 1 "$repo_url" "$install_dir" &>/dev/null; then
        echo -e "${GREEN}INSTALLED -> ${install_dir}${NC}"
        INSTALLED=$((INSTALLED + 1))
    else
        echo -e "${RED}FAILED${NC}"
        FAILED=$((FAILED + 1))
        FAILED_LIST+=("$name (git)")
    fi
}

# =============================================================================
#  CATEGORY 1: CORE SYSTEM UTILITIES
#  Essential system utilities
# =============================================================================
install_core() {
    separator
    echo -e "${BOLD}${MAGENTA}  [1/10] CORE SYSTEM UTILITIES${NC}"
    echo -e "${DIM}  Essential system utilities - base functionality${NC}"
    separator

    install_pkg "coreutils"    "Basic Unix utilities (ls, cat, chmod, stat, sort, etc.)"  "stat"
    install_pkg "util-linux"   "System utilities (mount, lsblk, fdisk, etc.)"             "mount"
    install_pkg "procps"       "Process utilities (ps, top, kill, free, uptime)"           "ps"
    install_pkg "iproute2"     "Network utilities (ss, ip, bridge, tc)"                   "ss"
    install_pkg "gawk"         "GNU AWK - pattern scanning and text processing"           "awk"
    install_pkg "sed"          "Stream editor - text transformation"                      "sed"
    install_pkg "grep"         "Text pattern matching"                                    "grep"
    install_pkg "findutils"    "File search utilities (find, xargs, locate)"              "find"
    install_pkg "jq"           "JSON parser and processor (report generation)"            "jq"
    install_pkg "curl"         "HTTP client - URL transfers, API calls, header checks"    "curl"
    install_pkg "wget"         "File downloader - alternative to curl"                    "wget"
    install_pkg "bash"         "Bourne Again Shell - script interpreter"                  "bash"
    install_pkg "git"          "Version control system"                                   "git"
    install_pkg "bc"           "Calculator - arithmetic in scripts"                       "bc"
    install_pkg "file"         "File type identifier"                                     "file"
    install_pkg "xxd"          "Hex dump utility"                                         "xxd"
    install_pkg "tree"         "Directory structure viewer"                                "tree"
    install_pkg "python3"      "Python 3 interpreter (for pip-based tools)"               "python3"
    install_pkg "python3-pip"  "Python package manager"                                   "pip3"
    install_pkg "pipx"         "Install Python CLI apps in isolation"                     "pipx"
}

# =============================================================================
#  CATEGORY 2: NETWORK SCANNING & DISCOVERY
#  Network scanning and discovery
# =============================================================================
install_network_scanning() {
    separator
    echo -e "${BOLD}${MAGENTA}  [2/10] NETWORK SCANNING & DISCOVERY${NC}"
    echo -e "${DIM}  Network scanning, port discovery, service identification${NC}"
    separator

    install_pkg "nmap"          "Network mapper - port scan, OS detect, service version"    "nmap"
    install_pkg "arp-scan"      "ARP level host discovery on local network"                 "arp-scan"
    install_pkg "masscan"       "Ultra-fast port scanner (10M packets/sec)"                 "masscan"
    install_pkg "netdiscover"   "Active/passive ARP reconnaissance"                        "netdiscover"
    install_pkg "fping"         "Fast parallel ping sweep"                                 "fping"
    install_pkg "hping3"        "TCP/IP packet assembler and analyzer"                     "hping3"
    install_pkg "arping"        "ARP level pinging"                                        "arping"
    install_pkg "traceroute"    "Network path tracing"                                     "traceroute"
    install_pkg "mtr-tiny"      "Combined traceroute and ping diagnostic"                  "mtr"
    install_pkg "net-tools"     "Legacy networking (ifconfig, netstat, route, arp)"         "netstat"
    install_pkg "iputils-ping"  "ICMP ping utility"                                        "ping"
    install_pkg "nbtscan"       "NetBIOS name scanner"                                     "nbtscan"
}

# =============================================================================
#  CATEGORY 3: TRAFFIC CAPTURE & ANALYSIS
#  Traffic capture and analysis
# =============================================================================
install_traffic_analysis() {
    separator
    echo -e "${BOLD}${MAGENTA}  [3/10] TRAFFIC CAPTURE & ANALYSIS${NC}"
    echo -e "${DIM}  Network traffic capture, packet analysis, protocol decode${NC}"
    separator

    install_pkg "tcpdump"            "Command-line packet capture and analysis"            "tcpdump"
    install_pkg "tshark"             "Wireshark CLI - deep packet inspection"              "tshark"
    install_pkg "wireshark-common"   "Wireshark shared components"                         "wireshark"
    install_pkg "ngrep"              "Network packet grep - search inside traffic"         "ngrep"
    install_pkg "tcpflow"            "TCP session reassembly and recording"                "tcpflow"
    install_pkg "dsniff"             "Network audit tools (arpspoof, dnsspoof, filesnarf)" "arpspoof"
    install_pkg "ettercap-text-only" "MITM attack suite - text mode"                       "ettercap"
    install_pkg "netsniff-ng"        "High-performance network toolkit"                    "netsniff-ng"
}

# =============================================================================
#  CATEGORY 4: DNS & DOMAIN TOOLS
#  DNS and domain tools
# =============================================================================
install_dns_tools() {
    separator
    echo -e "${BOLD}${MAGENTA}  [4/10] DNS & DOMAIN TOOLS${NC}"
    echo -e "${DIM}  DNS record analysis, zone transfer, DNSSEC, subdomain enum${NC}"
    separator

    install_pkg "dnsutils"      "DNS utilities (dig, nslookup, nsupdate)"                  "dig"
    install_pkg "bind9-host"    "Simple DNS lookup utility (host command)"                  "host"
    install_pkg "whois"         "Domain WHOIS lookup"                                      "whois"
    install_pkg "dnsenum"       "DNS enumeration and zone transfer testing"                "dnsenum"
    install_pkg "dnsrecon"      "DNS reconnaissance and enumeration"                       "dnsrecon"
    install_pkg "fierce"        "DNS brute-force and reconnaissance"                       "fierce"
    install_pkg "dnsmap"        "DNS subdomain brute-forcing"                              "dnsmap"
    install_pkg "dnstracer"     "DNS delegation chain tracer"                              "dnstracer"
    install_pkg "ldnsutils"     "DNS tool suite (drill - DNSSEC validation)"               "drill"
}

# =============================================================================
#  CATEGORY 5: SSL/TLS & CRYPTOGRAPHY
#  SSL/TLS and cryptography tools
# =============================================================================
install_ssl_crypto() {
    separator
    echo -e "${BOLD}${MAGENTA}  [5/10] SSL/TLS & CRYPTOGRAPHY${NC}"
    echo -e "${DIM}  Certificate analysis, TLS testing, cipher audit${NC}"
    separator

    install_pkg "openssl"         "SSL/TLS toolkit - cert check, protocol test, ciphers"   "openssl"
    install_pkg "testssl.sh"      "Complete SSL/TLS testing (protocols, ciphers, vulns)"    "testssl.sh"
    install_pkg "sslscan"         "SSL/TLS cipher and protocol scanner"                    "sslscan"
    install_pkg "gnutls-bin"      "GnuTLS tools (gnutls-cli - alternative TLS client)"     "gnutls-cli"
    install_pkg "ca-certificates" "Root CA certificate bundle"                             "update-ca-certificates"
    install_lib "libssl-dev"      "OpenSSL development libraries"

    # sslyze - Python package, not in Ubuntu repos
    install_pip "sslyze"          "Fast SSL/TLS configuration analyzer (Python)"           "sslyze"
}

# =============================================================================
#  CATEGORY 6: PASSWORD & AUTHENTICATION TESTING
#  Password and authentication testing
# =============================================================================
install_password_tools() {
    separator
    echo -e "${BOLD}${MAGENTA}  [6/10] PASSWORD & AUTHENTICATION TESTING${NC}"
    echo -e "${DIM}  Brute-force tests, credential audit, hash cracking${NC}"
    separator

    install_pkg "hydra"            "Fast network brute-force (SSH, HTTP, FTP, SMB, etc.)"  "hydra"
    install_pkg "medusa"           "Parallel brute-force authentication tester"            "medusa"
    install_pkg "ncrack"           "High-speed network auth cracker (by nmap team)"        "ncrack"
    install_pkg "john"             "John the Ripper - password hash cracker"               "john"
    install_pkg "hashcat"          "Advanced GPU-based hash cracker"                       "hashcat"
    install_pkg "sshpass"          "Non-interactive SSH password authentication"           "sshpass"
    install_pkg "crunch"           "Custom wordlist generator"                             "crunch"
    install_pkg "cewl"             "Custom wordlist from website content"                  "cewl"
    install_pkg "wordlists"        "Collection of common password wordlists"               "ls"
    install_lib "libpam-pwquality" "PAM password quality checking module"
}

# =============================================================================
#  CATEGORY 7: WEB APPLICATION SECURITY
#  Web application security
# =============================================================================
install_web_tools() {
    separator
    echo -e "${BOLD}${MAGENTA}  [7/10] WEB APPLICATION SECURITY${NC}"
    echo -e "${DIM}  Web scanning, vulnerability testing, directory discovery${NC}"
    separator

    install_pkg "nikto"          "Web server vulnerability scanner"                        "nikto"
    install_pkg "dirb"           "Web directory and file brute-forcer"                     "dirb"
    install_pkg "gobuster"       "Fast directory/DNS/vhost brute-forcing (Go)"             "gobuster"
    install_pkg "wfuzz"          "Web application fuzzer"                                  "wfuzz"
    install_pkg "sqlmap"         "Automatic SQL injection detection and exploitation"      "sqlmap"
    install_pkg "wapiti"         "Web application vulnerability scanner"                   "wapiti"
    install_pkg "whatweb"        "Web technology identifier (CMS, frameworks, etc.)"       "whatweb"
    install_pkg "wafw00f"        "Web Application Firewall (WAF) detector"                 "wafw00f"

    # Python-based tools not in Ubuntu repos
    install_pip "commix"         "Command injection exploitation tool (Python)"            "commix"
}

# =============================================================================
#  CATEGORY 8: SMB / WIRELESS / EXPLOITATION
#  SMB, wireless networks, exploitation
# =============================================================================
install_exploitation_tools() {
    separator
    echo -e "${BOLD}${MAGENTA}  [8/10] SMB / WIRELESS / EXPLOITATION${NC}"
    echo -e "${DIM}  SMB enumeration, WiFi audit, exploitation frameworks${NC}"
    separator

    echo -e "\n  ${WHITE}── SMB / NetBIOS ──${NC}"
    install_pkg "smbclient"      "SMB/CIFS client for file sharing access"                 "smbclient"
    install_pkg "smbmap"         "SMB share enumeration and access checker"                "smbmap"
    install_pkg "rpcclient"      "RPC client for Windows enumeration"                      "rpcclient"
    install_pkg "nbtscan"        "NetBIOS name scanner"                                    "nbtscan"
    # enum4linux - Perl script, try apt then git
    install_pkg "enum4linux"     "SMB/NetBIOS enumeration (shares, users, policies)"       "enum4linux"
    if ! command -v enum4linux &>/dev/null; then
        install_git "https://github.com/cddmp/enum4linux-ng.git" "enum4linux-ng" \
            "SMB enumeration - next generation (Python)" "enum4linux-ng"
    fi
    # netexec (formerly crackmapexec)
    install_pip "netexec"        "Swiss army knife for pentesting Windows/AD (ex-CME)"     "nxc"

    echo -e "\n  ${WHITE}── Wireless ──${NC}"
    install_pkg "iw"             "Wireless device configuration and scanning"              "iw"
    install_pkg "wireless-tools" "Legacy wireless tools (iwconfig, iwlist, iwspy)"          "iwlist"
    install_pkg "aircrack-ng"    "WiFi security audit suite (capture, crack, inject)"      "aircrack-ng"
    install_pkg "reaver"         "WPS brute-force attack tool"                             "reaver"
    install_pkg "wifite"         "Automated WiFi attack tool"                              "wifite"
    install_pkg "macchanger"     "MAC address spoofing utility"                            "macchanger"
    install_pkg "kismet"         "Wireless network detector, sniffer, IDS"                 "kismet"

    echo -e "\n  ${WHITE}── Exploitation ──${NC}"
    install_pkg "metasploit-framework" "Full exploitation framework"                       "msfconsole"
    # exploitdb / searchsploit
    install_pkg "exploitdb"      "Exploit database search (searchsploit)"                  "searchsploit"
    if ! command -v searchsploit &>/dev/null; then
        install_git "https://gitlab.com/exploit-database/exploitdb.git" "exploitdb" \
            "Exploit-DB with searchsploit" "searchsploit"
    fi
}

# =============================================================================
#  CATEGORY 9: SYSTEM HARDENING & COMPLIANCE
#  System hardening and compliance
# =============================================================================
install_hardening_tools() {
    separator
    echo -e "${BOLD}${MAGENTA}  [9/10] SYSTEM HARDENING & COMPLIANCE${NC}"
    echo -e "${DIM}  CIS benchmark, file integrity, firewall, audit logging${NC}"
    separator

    echo -e "\n  ${WHITE}── Firewall ──${NC}"
    install_pkg "ufw"            "Uncomplicated Firewall - easy iptables management"       "ufw"
    install_pkg "iptables"       "Linux kernel packet filtering (IPv4)"                    "iptables"
    install_pkg "nftables"       "Modern packet filtering framework"                       "nft"
    install_pkg "fail2ban"       "Intrusion prevention - bans IPs after failed logins"     "fail2ban-client"

    echo -e "\n  ${WHITE}── File Integrity & Rootkit Detection ──${NC}"
    install_pkg "aide"           "Advanced Intrusion Detection Environment"                "aide"
    install_pkg "tripwire"       "File integrity checker (alternative to AIDE)"            "tripwire"
    install_pkg "rkhunter"       "Rootkit hunter - scans for rootkits and backdoors"       "rkhunter"
    install_pkg "chkrootkit"     "Rootkit detector - checks for known rootkit signatures"  "chkrootkit"
    install_pkg "clamav"         "Antivirus engine - malware/virus scanner"                "clamscan"
    install_pkg "lynis"          "Security auditing and hardening tool (CIS checks)"       "lynis"

    echo -e "\n  ${WHITE}── Audit & Logging ──${NC}"
    install_pkg "auditd"         "Linux Audit daemon - system call monitoring"             "auditd"
    install_lib "audispd-plugins" "Audit dispatcher plugins for remote logging"
    install_pkg "syslog-ng-core" "Advanced syslog daemon"                                  "syslog-ng"
    install_pkg "logwatch"       "Log analysis and reporting"                              "logwatch"
    install_pkg "acct"           "Process accounting (lastcomm, sa, accton)"               "lastcomm"

    echo -e "\n  ${WHITE}── Security Scanning ──${NC}"
    install_pkg "openscap-scanner" "SCAP compliance scanner"                               "oscap"
    install_lib "libopenscap8"     "OpenSCAP library"
    install_pkg "debsums"        "Verify installed package files against MD5"              "debsums"
    install_pkg "needrestart"    "Check which services need restart after updates"         "needrestart"
}

# =============================================================================
#  CATEGORY 10: UTILITIES & REPORTING
#  Utilities and reporting
# =============================================================================
install_utilities() {
    separator
    echo -e "${BOLD}${MAGENTA}  [10/10] UTILITIES & REPORTING${NC}"
    echo -e "${DIM}  Reporting, visualization, helper utilities${NC}"
    separator

    echo -e "\n  ${WHITE}── Reporting & Output ──${NC}"
    install_pkg "html2text"     "HTML to text converter"                                   "html2text"
    install_pkg "pandoc"        "Universal document converter (MD -> PDF/HTML)"             "pandoc"
    install_pkg "xmlstarlet"    "XML processing from command line"                         "xmlstarlet"
    install_pkg "csvtool"       "CSV file manipulation"                                    "csvtool"

    echo -e "\n  ${WHITE}── Scripting Helpers ──${NC}"
    install_pkg "expect"        "Automate interactive commands"                            "expect"
    install_pkg "screen"        "Terminal multiplexer - persistent sessions"               "screen"
    install_pkg "tmux"          "Modern terminal multiplexer"                              "tmux"
    install_pkg "pv"            "Pipe viewer - progress monitoring"                        "pv"
    install_pkg "parallel"      "Execute commands in parallel"                             "parallel"

    echo -e "\n  ${WHITE}── Network Utilities ──${NC}"
    install_pkg "socat"              "Multipurpose network relay (like advanced netcat)"    "socat"
    install_pkg "netcat-openbsd"     "Network swiss army knife (nc)"                       "nc"
    install_pkg "proxychains4"       "Route connections through proxy chains"              "proxychains4"
    install_pkg "tor"                "Anonymity network client"                            "tor"
    install_pkg "openvpn"            "VPN client and server"                               "openvpn"

    echo -e "\n  ${WHITE}── OSINT (Python-based) ──${NC}"
    install_pip "theHarvester"  "Email, subdomain, IP harvester for OSINT"                 "theHarvester"
    install_git "https://github.com/lanmaster53/recon-ng.git" "recon-ng" \
        "Web reconnaissance framework" "recon-ng"
    install_pip "spiderfoot"    "Automated OSINT collection"                               "spiderfoot"
}

# =============================================================================
# Summary & Report
# =============================================================================
show_summary() {
    echo ""
    separator
    echo -e "${BOLD}${WHITE}  INSTALLATION SUMMARY${NC}"
    separator
    echo -e "  ${GREEN}New installs${NC}:    $INSTALLED"
    echo -e "  ${BLUE}Already had${NC}:     $SKIPPED"
    echo -e "  ${YELLOW}Not in repo${NC}:    $NOT_IN_REPO"
    echo -e "  ${RED}Failed${NC}:          $FAILED"
    echo -e "  ${WHITE}──────────────────${NC}"
    echo -e "  ${BOLD}Total checked${NC}:   $TOTAL"
    separator

    if [[ ${#FAILED_LIST[@]} -gt 0 ]]; then
        echo -e "\n${YELLOW}[⚠] Failed packages:${NC}"
        for pkg in "${FAILED_LIST[@]}"; do
            echo -e "    ${DIM}• $pkg${NC}"
        done
        echo ""
    fi

    echo -e "${GREEN}[✓] Installation complete!${NC}"
    echo -e "${CYAN}    Run: ./security_audit_suite.sh${NC}"
    echo -e "${CYAN}    Or:  sudo ./security_audit_suite.sh${NC}\n"
}

# =============================================================================
# Category Selection Menu
# =============================================================================
show_list() {
    banner
    echo -e "${BOLD}${WHITE}  Available Categories:${NC}"
    separator
    echo -e "  ${CYAN}[1]${NC}   Core System Utilities              ${DIM}(20 packages)${NC}"
    echo -e "  ${CYAN}[2]${NC}   Network Scanning & Discovery       ${DIM}(12 packages)${NC}"
    echo -e "  ${CYAN}[3]${NC}   Traffic Capture & Analysis         ${DIM}(8 packages)${NC}"
    echo -e "  ${CYAN}[4]${NC}   DNS & Domain Tools                 ${DIM}(9 packages)${NC}"
    echo -e "  ${CYAN}[5]${NC}   SSL/TLS & Cryptography             ${DIM}(7 packages)${NC}"
    echo -e "  ${CYAN}[6]${NC}   Password & Authentication Testing  ${DIM}(10 packages)${NC}"
    echo -e "  ${CYAN}[7]${NC}   Web Application Security           ${DIM}(9 packages)${NC}"
    echo -e "  ${CYAN}[8]${NC}   SMB / Wireless / Exploitation      ${DIM}(16 packages)${NC}"
    echo -e "  ${CYAN}[9]${NC}   System Hardening & Compliance      ${DIM}(18 packages)${NC}"
    echo -e "  ${CYAN}[10]${NC}  Utilities & Reporting              ${DIM}(17 packages)${NC}"
    separator
    echo -e "  ${BOLD}Total: ~126 packages (apt + pip + git)${NC}"
    separator
}

select_menu() {
    while true; do
        show_list
        echo -e "\n  ${CYAN}[A]${NC}   Install ALL categories"
        echo -e "  ${CYAN}[S]${NC}   Select specific categories"
        echo -e "  ${CYAN}[Q]${NC}   Quit"
        separator
        echo -e "${YELLOW}Select option: ${NC}"
        read -r choice
        case "${choice,,}" in
            a|all)
                install_all
                show_summary
                exit 0
                ;;
            s|select)
                echo -e "${YELLOW}Enter category numbers separated by spaces (e.g., 1 2 5 9):${NC}"
                read -r cats
                run_update
                for c in $cats; do
                    case "$c" in
                        1)  install_core ;;
                        2)  install_network_scanning ;;
                        3)  install_traffic_analysis ;;
                        4)  install_dns_tools ;;
                        5)  install_ssl_crypto ;;
                        6)  install_password_tools ;;
                        7)  install_web_tools ;;
                        8)  install_exploitation_tools ;;
                        9)  install_hardening_tools ;;
                        10) install_utilities ;;
                        *)  echo -e "${RED}Unknown category: $c${NC}" ;;
                    esac
                done
                show_summary
                exit 0
                ;;
            q|quit|0)
                echo -e "${CYAN}Goodbye.${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

# =============================================================================
# Update apt cache
# =============================================================================
run_update() {
    echo -e "\n${CYAN}Updating package lists...${NC}"
    if apt-get update -q 2>&1 | tail -3; then
        echo -e "${GREEN}[✓] Package lists updated${NC}"
    else
        echo -e "${YELLOW}[⚠] Some repos may have issues, continuing anyway...${NC}"
    fi
}

# =============================================================================
# Install All Categories
# =============================================================================
install_all() {
    run_update

    install_core
    install_network_scanning
    install_traffic_analysis
    install_dns_tools
    install_ssl_crypto
    install_password_tools
    install_web_tools
    install_exploitation_tools
    install_hardening_tools
    install_utilities
}

# =============================================================================
# Main Entry Point
# =============================================================================
main() {
    banner
    check_root

    case "${1:-}" in
        --list|-l)
            show_list
            exit 0
            ;;
        --all|-a)
            install_all
            show_summary
            exit 0
            ;;
        --category|-c)
            shift
            run_update
            case "${1:-}" in
                core|1)           install_core ;;
                network|2)        install_network_scanning ;;
                traffic|3)        install_traffic_analysis ;;
                dns|4)            install_dns_tools ;;
                ssl|5)            install_ssl_crypto ;;
                password|6)       install_password_tools ;;
                web|7)            install_web_tools ;;
                exploitation|8)   install_exploitation_tools ;;
                hardening|9)      install_hardening_tools ;;
                utilities|10)     install_utilities ;;
                *)
                    echo -e "${RED}Unknown category: ${1:-}${NC}"
                    echo -e "${DIM}Valid: core, network, traffic, dns, ssl, password, web, exploitation, hardening, utilities${NC}"
                    exit 1
                    ;;
            esac
            show_summary
            exit 0
            ;;
        --help|-h)
            echo -e "${WHITE}Usage:${NC}"
            echo -e "  ${CYAN}sudo $0${NC}                         Interactive menu"
            echo -e "  ${CYAN}sudo $0 --all${NC}                    Install everything"
            echo -e "  ${CYAN}sudo $0 --list${NC}                   Show categories"
            echo -e "  ${CYAN}sudo $0 --category network${NC}       Install specific category"
            echo -e "  ${CYAN}sudo $0 --help${NC}                   Show this help"
            exit 0
            ;;
        "")
            select_menu
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo -e "${DIM}Use --help for usage${NC}"
            exit 1
            ;;
    esac
}

main "$@"
