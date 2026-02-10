#!/usr/bin/env bash
# =============================================================================
# Infrastructure Module - Security Audit Suite
# Colors, logging, session management, finding system, helpers
# =============================================================================

# ── Color Definitions ────────────────────────────────────────────────────────
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

# ── Global Configuration ─────────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_NAME="Security Audit Suite"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULES_DIR="$SCRIPT_DIR/audit_modules"
BASE_OUTPUT_DIR="$HOME/security-audits"
SESSION_ID="$(date +%Y%m%d_%H%M%S)"
SESSION_DIR=""
LOG_FILE=""
AUDIT_TARGET=""
AUDIT_MODE="remote"  # remote or local

# ── Finding Storage ───────────────────────────────────────────────────────────
declare -a FINDINGS_CRITICAL=()
declare -a FINDINGS_HIGH=()
declare -a FINDINGS_MEDIUM=()
declare -a FINDINGS_LOW=()
declare -a FINDINGS_INFO=()
declare -i FINDING_COUNT=0

# ── Required / Optional Tools ────────────────────────────────────────────────
REQUIRED_TOOLS=(nmap openssl dig curl ss awk jq)
RECOMMENDED_TOOLS=(testssl.sh hydra arp-scan tcpdump tshark nikto)
OPTIONAL_TOOLS=(iw iwlist enum4linux medusa)

# =============================================================================
# Logging
# =============================================================================
log() {
    local level="$1"; shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && \
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

    case "$level" in
        ERROR)   echo -e "${RED}[✗] $message${NC}" ;;
        SUCCESS) echo -e "${GREEN}[✓] $message${NC}" ;;
        INFO)    echo -e "${CYAN}[ℹ] $message${NC}" ;;
        WARN)    echo -e "${YELLOW}[⚠] $message${NC}" ;;
        DEBUG)   echo -e "${DIM}[•] $message${NC}" ;;
    esac
}

# =============================================================================
# UI Helpers
# =============================================================================
separator() {
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
}

press_enter() {
    echo -e "\n${YELLOW}Press ENTER to continue...${NC}"
    read -r
}

clear_screen() {
    clear 2>/dev/null || printf '\033[2J\033[H'
}

show_banner() {
    clear_screen
    echo -e "${CYAN}"
    cat << 'BANNER'
    ╔══════════════════════════════════════════════════════════════╗
    ║   ____                      _ _            _             _ ║
    ║  / ___|  ___  ___ _   _ _ __(_) |_ _   _  / \  _   _  __| |║
    ║  \___ \ / _ \/ __| | | | '__| | __| | | |/ _ \| | | |/ _` |║
    ║   ___) |  __/ (__| |_| | |  | | |_| |_| / ___ \ |_| | (_| |║
    ║  |____/ \___|\___|\__,_|_|  |_|\__|\__, /_/   \_\__,_|\__,_|║
    ║                                    |___/                    ║
    ║              ____        _ _                                ║
    ║             / ___| _   _(_) |_ ___                          ║
    ║             \___ \| | | | | __/ _ \                         ║
    ║              ___) | |_| | | ||  __/                         ║
    ║             |____/ \__,_|_|\__\___|                         ║
    ║                                                             ║
    ║         PROFESSIONAL SECURITY AUDIT FRAMEWORK               ║
    ║                    Enterprise v1.0                           ║
    ╠═════════════════════════════════════════════════════════════╣
    ║  Modules: Network | System | SSL/TLS | DNS | Auth | CIS    ║
    ║  Output:  HTML Reports | JSON | CSV                        ║
    ╚══════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
    echo -e "${DIM}  Session: ${SESSION_ID}    Target: ${AUDIT_TARGET:-not set}${NC}"
    separator
}

# =============================================================================
# Session Management
# =============================================================================
init_session() {
    SESSION_DIR="$BASE_OUTPUT_DIR/session_${SESSION_ID}"
    mkdir -p "$SESSION_DIR"/{logs,scans,reports}
    LOG_FILE="$SESSION_DIR/logs/audit_${SESSION_ID}.log"
    touch "$LOG_FILE"
    echo "target,${AUDIT_TARGET}" > "$SESSION_DIR/session_meta.csv"
    echo "start_time,$(date -Iseconds)" >> "$SESSION_DIR/session_meta.csv"
    echo "severity|module|title|description|remediation" > "$SESSION_DIR/findings.csv"
    log INFO "Session initialized: $SESSION_DIR"
}

# =============================================================================
# Target Sanitization
# =============================================================================
sanitize_target() {
    local raw="$1"
    # Strip protocol prefix
    raw="${raw#https://}"
    raw="${raw#http://}"
    # Strip trailing path (keep only host)
    raw="${raw%%/*}"
    # Strip port suffix (e.g., :443)
    raw="${raw%%:*}"
    # Strip trailing dots and whitespace
    raw="${raw%.}"
    raw="${raw// /}"
    echo "$raw"
}

detect_audit_mode() {
    local target="$1"
    local hostname_local
    hostname_local="$(hostname 2>/dev/null)" || true
    local local_ips
    local_ips="$(hostname -I 2>/dev/null)" || true

    case "$target" in
        127.0.0.1|localhost|::1|0.0.0.0)
            echo "local" ;;
        127.*)
            echo "local" ;;
        "$hostname_local")
            echo "local" ;;
        *)
            # Check if target matches any local IP
            if [[ -n "$local_ips" ]] && echo "$local_ips" | grep -qw "$target"; then
                echo "local"
            else
                echo "remote"
            fi
            ;;
    esac
}

target_is_ip() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

target_is_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] && [[ "$1" == *.* ]]
}

target_is_local_network() {
    # Check if target is a private/LAN IP address (not internet-routable)
    local target="$1"
    local ip
    if target_is_ip "$target"; then
        ip="$target"
    else
        ip="$(dig +short A "$target" 2>/dev/null | head -1)" || true
    fi
    [[ -z "$ip" ]] && return 1
    # RFC 1918 private ranges + link-local
    [[ "$ip" =~ ^10\. ]] && return 0
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
    [[ "$ip" =~ ^192\.168\. ]] && return 0
    [[ "$ip" =~ ^169\.254\. ]] && return 0
    [[ "$ip" =~ ^127\. ]] && return 0
    return 1
}

# =============================================================================
# Target Configuration
# =============================================================================
set_target() {
    echo -e "\n${CYAN}[ℹ] Current target: ${AUDIT_TARGET:-not set}${NC}"
    echo -e "${YELLOW}Enter target (IP, hostname, or domain):${NC}"
    echo -e "${DIM}  Example: 192.168.1.1, example.com, scanme.nmap.org${NC}"
    read -r new_target
    if [[ -z "$new_target" ]]; then
        log WARN "No target provided"
        return 1
    fi
    AUDIT_TARGET="$(sanitize_target "$new_target")"
    AUDIT_MODE="$(detect_audit_mode "$AUDIT_TARGET")"
    log SUCCESS "Target set to: $AUDIT_TARGET (mode: $AUDIT_MODE)"
    # Re-init session with target info
    if [[ -n "$SESSION_DIR" ]]; then
        echo "target,${AUDIT_TARGET}" > "$SESSION_DIR/session_meta.csv"
        echo "mode,${AUDIT_MODE}" >> "$SESSION_DIR/session_meta.csv"
    fi
}

# =============================================================================
# Authorization & Ethics Check
# =============================================================================
check_authorization() {
    clear_screen
    echo -e "${RED}"
    cat << 'AUTH'
    ╔══════════════════════════════════════════════════════════════╗
    ║                   ⚠  AUTHORIZATION NOTICE  ⚠                ║
    ╠═════════════════════════════════════════════════════════════╣
    ║                                                             ║
    ║  This tool performs active security testing that may:        ║
    ║                                                             ║
    ║  • Scan networks and enumerate services                     ║
    ║  • Test for vulnerabilities and misconfigurations           ║
    ║  • Attempt authentication and credential testing            ║
    ║  • Generate significant network traffic                     ║
    ║                                                             ║
    ║  ONLY use this tool on systems you OWN or have EXPLICIT     ║
    ║  WRITTEN AUTHORIZATION to test.                             ║
    ║                                                             ║
    ║  Unauthorized access to computer systems is ILLEGAL.        ║
    ║                                                             ║
    ╚══════════════════════════════════════════════════════════════╝
AUTH
    echo -e "${NC}"
    echo -e "${YELLOW}Do you have authorization to test the target system? (yes/no):${NC}"
    read -r auth_response
    if [[ "${auth_response,,}" != "yes" ]]; then
        echo -e "${RED}[✗] Authorization not confirmed. Exiting.${NC}"
        exit 1
    fi
    log SUCCESS "Authorization confirmed by operator"
}

# =============================================================================
# Dependency Checking
# =============================================================================
check_dependencies() {
    echo -e "\n${CYAN}${BOLD}[Dependency Check]${NC}"
    separator
    local missing_required=0

    echo -e "${WHITE}Required Tools:${NC}"
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} $tool"
        else
            echo -e "  ${RED}[✗]${NC} $tool ${RED}(MISSING - required)${NC}"
            missing_required=1
        fi
    done

    echo -e "\n${WHITE}Recommended Tools:${NC}"
    for tool in "${RECOMMENDED_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} $tool"
        else
            echo -e "  ${YELLOW}[−]${NC} $tool ${DIM}(optional - some features unavailable)${NC}"
        fi
    done

    echo -e "\n${WHITE}Optional Tools:${NC}"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} $tool"
        else
            echo -e "  ${DIM}[−]${NC} $tool ${DIM}(optional)${NC}"
        fi
    done

    if [[ $missing_required -eq 1 ]]; then
        echo -e "\n${RED}[✗] Missing required tools. Install them before proceeding.${NC}"
        echo -e "${DIM}  Debian/Ubuntu: sudo apt install nmap openssl dnsutils curl iproute2 gawk jq${NC}"
        echo -e "${DIM}  RHEL/Fedora:   sudo dnf install nmap openssl bind-utils curl iproute2 gawk jq${NC}"
        press_enter
        return 1
    fi

    log SUCCESS "Dependency check passed"
    return 0
}

# =============================================================================
# Root Privilege Check
# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log WARN "Running without root privileges. Some checks will be limited."
        echo -e "${YELLOW}[⚠] Some audit checks require root. Consider: sudo $0${NC}"
        return 1
    fi
    return 0
}

# =============================================================================
# Tool Availability Helper
# =============================================================================
require_tool() {
    local tool="$1"
    local module="${2:-}"
    if ! command -v "$tool" &>/dev/null; then
        log WARN "$tool not found. Skipping ${module:-this check}."
        return 1
    fi
    return 0
}

require_target() {
    if [[ -z "$AUDIT_TARGET" ]]; then
        echo -e "\n${YELLOW}[⚠] No target set.${NC}"
        echo -e "${CYAN}Enter target (IP, hostname, or domain):${NC}"
        echo -e "${DIM}  Example: 192.168.1.1, example.com, scanme.nmap.org${NC}"
        read -r new_target
        if [[ -z "$new_target" ]]; then
            log ERROR "No target provided. Cannot continue."
            return 1
        fi
        AUDIT_TARGET="$(sanitize_target "$new_target")"
        AUDIT_MODE="$(detect_audit_mode "$AUDIT_TARGET")"
        log SUCCESS "Target set to: $AUDIT_TARGET (mode: $AUDIT_MODE)"
        if [[ -n "$SESSION_DIR" ]]; then
            echo "target,${AUDIT_TARGET}" > "$SESSION_DIR/session_meta.csv"
            echo "mode,${AUDIT_MODE}" >> "$SESSION_DIR/session_meta.csv"
        fi
    fi
    return 0
}

require_local() {
    if [[ "$AUDIT_MODE" != "local" ]]; then
        echo -e "  ${DIM}[−] Skipped (local-only check, target is remote)${NC}"
        return 1
    fi
    return 0
}

require_domain() {
    if ! target_is_domain "$AUDIT_TARGET"; then
        log WARN "Target '$AUDIT_TARGET' is not a domain name. DNS checks may not work."
    fi
    return 0
}

# =============================================================================
# Finding Recording System
# =============================================================================
add_finding() {
    local severity="$1"
    local module="$2"
    local title="$3"
    local description="$4"
    local remediation="${5:-No specific remediation provided.}"

    FINDING_COUNT+=1
    local finding="${FINDING_COUNT}|${module}|${title}|${description}|${remediation}"

    case "$severity" in
        CRITICAL) FINDINGS_CRITICAL+=("$finding") ;;
        HIGH)     FINDINGS_HIGH+=("$finding") ;;
        MEDIUM)   FINDINGS_MEDIUM+=("$finding") ;;
        LOW)      FINDINGS_LOW+=("$finding") ;;
        INFO)     FINDINGS_INFO+=("$finding") ;;
        *)        log WARN "Unknown severity: $severity"; FINDINGS_INFO+=("$finding") ;;
    esac

    # Log to file
    if [[ -n "$SESSION_DIR" ]]; then
        echo "${severity}|${module}|${title}|${description}|${remediation}" >> "$SESSION_DIR/findings.csv"
    fi

    # Console output based on severity
    case "$severity" in
        CRITICAL) log ERROR "CRITICAL: $title" ;;
        HIGH)     log ERROR "HIGH: $title" ;;
        MEDIUM)   log WARN "MEDIUM: $title" ;;
        LOW)      log INFO "LOW: $title" ;;
        INFO)     log DEBUG "INFO: $title" ;;
    esac
}

# =============================================================================
# Risk Score Calculation
# =============================================================================
calculate_risk_score() {
    local score=100
    score=$(( score - ( ${#FINDINGS_CRITICAL[@]} * 20 ) ))
    score=$(( score - ( ${#FINDINGS_HIGH[@]} * 10 ) ))
    score=$(( score - ( ${#FINDINGS_MEDIUM[@]} * 5 ) ))
    score=$(( score - ( ${#FINDINGS_LOW[@]} * 2 ) ))
    # INFO findings don't reduce score

    [[ $score -lt 0 ]] && score=0

    echo "$score"
}

risk_grade() {
    local score
    score="$(calculate_risk_score)"
    if   (( score >= 90 )); then echo "A"
    elif (( score >= 80 )); then echo "B"
    elif (( score >= 70 )); then echo "C"
    elif (( score >= 60 )); then echo "D"
    else echo "F"
    fi
}

# =============================================================================
# Findings Summary
# =============================================================================
show_findings_summary() {
    separator
    echo -e "${BOLD}${WHITE}  Findings Summary${NC}"
    separator
    echo -e "  ${RED}CRITICAL : ${#FINDINGS_CRITICAL[@]}${NC}"
    echo -e "  ${RED}HIGH     : ${#FINDINGS_HIGH[@]}${NC}"
    echo -e "  ${YELLOW}MEDIUM   : ${#FINDINGS_MEDIUM[@]}${NC}"
    echo -e "  ${BLUE}LOW      : ${#FINDINGS_LOW[@]}${NC}"
    echo -e "  ${DIM}INFO     : ${#FINDINGS_INFO[@]}${NC}"
    echo -e "  ${WHITE}──────────────────${NC}"
    echo -e "  ${BOLD}TOTAL    : ${FINDING_COUNT}${NC}"
    local score grade
    score="$(calculate_risk_score)"
    grade="$(risk_grade)"
    local grade_color
    case "$grade" in
        A) grade_color="$GREEN" ;;
        B) grade_color="$GREEN" ;;
        C) grade_color="$YELLOW" ;;
        D) grade_color="$YELLOW" ;;
        F) grade_color="$RED" ;;
    esac
    echo -e "\n  ${BOLD}Risk Score: ${grade_color}${score}/100 (Grade: ${grade})${NC}"
    separator
}

# =============================================================================
# Cleanup Handler
# =============================================================================
cleanup() {
    if [[ -n "$SESSION_DIR" && -d "$SESSION_DIR" ]]; then
        echo "end_time,$(date -Iseconds)" >> "$SESSION_DIR/session_meta.csv"
        echo "findings_total,${FINDING_COUNT}" >> "$SESSION_DIR/session_meta.csv"
        echo "risk_score,$(calculate_risk_score)" >> "$SESSION_DIR/session_meta.csv"
        log INFO "Session ended. Output: $SESSION_DIR"
    fi
}

# =============================================================================
# Save scan output helper
# =============================================================================
save_scan() {
    local name="$1"
    local data="$2"
    local outfile="$SESSION_DIR/scans/${name}_${SESSION_ID}.txt"
    echo "$data" > "$outfile"
    log DEBUG "Saved: $outfile"
    echo "$outfile"
}
