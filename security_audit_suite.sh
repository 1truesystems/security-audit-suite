#!/usr/bin/env bash
# =============================================================================
#
#   ____                      _ _            _             _ _ _
#  / ___|  ___  ___ _   _ _ __(_) |_ _   _  / \  _   _  __| (_) |_
#  \___ \ / _ \/ __| | | | '__| | __| | | |/ _ \| | | |/ _` | | __|
#   ___) |  __/ (__| |_| | |  | | |_| |_| / ___ \ |_| | (_| | | |_
#  |____/ \___|\___|\__,_|_|  |_|\__|\__, /_/   \_\__,_|\__,_|_|\__|
#                                    |___/
#   ____        _ _
#  / ___| _   _(_) |_ ___
#  \___ \| | | | | __/ _ \
#   ___) | |_| | | ||  __/
#  |____/ \__,_|_|\__\___|
#
#  Professional Security Audit Framework v1.0
#  Modular architecture with 7 audit modules + reporting engine
#
#  Modules: Network | System | SSL/TLS | DNS | Password | CIS | Reporting
#
#  Usage: ./security_audit_suite.sh
#  Root:  sudo ./security_audit_suite.sh  (recommended for full functionality)
#
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

# ── Resolve script directory and source modules ─────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/audit_modules"

# Verify modules directory exists
if [[ ! -d "$MODULES_DIR" ]]; then
    echo "[ERROR] Modules directory not found: $MODULES_DIR"
    echo "Ensure audit_modules/ is in the same directory as this script."
    exit 1
fi

# Source all modules
for module in infrastructure network_audit system_audit ssl_audit \
              dns_audit password_audit compliance_audit reporting; do
    if [[ -f "$MODULES_DIR/${module}.sh" ]]; then
        # shellcheck source=/dev/null
        source "$MODULES_DIR/${module}.sh"
    else
        echo "[ERROR] Missing module: $MODULES_DIR/${module}.sh"
        exit 1
    fi
done

# =============================================================================
# Workflow Pipelines
# =============================================================================

# ── Quick Audit (~2-3 min) ──────────────────────────────────────────────────
workflow_quick() {
    require_target || return
    log INFO "Starting Quick Audit on $AUDIT_TARGET"
    separator
    echo -e "${BOLD}${MAGENTA}  Quick Security Audit${NC}"
    echo -e "${DIM}  Estimated time: 2-3 minutes${NC}"
    separator

    echo -e "\n${BOLD}[1/5] Open Ports...${NC}"
    open_ports_audit

    echo -e "\n${BOLD}[2/5] SSL Quick Check...${NC}"
    ssl_quick_check 443

    if [[ "$AUDIT_MODE" == "local" ]]; then
        echo -e "\n${BOLD}[3/5] SSH Configuration...${NC}"
        ssh_config_audit

        echo -e "\n${BOLD}[4/5] Firewall Status...${NC}"
        firewall_rules_audit

        echo -e "\n${BOLD}[5/5] Password Policy...${NC}"
        password_policy_check
    else
        echo -e "\n${BOLD}[3/5] HSTS & Security Headers...${NC}"
        hsts_check

        echo -e "\n${BOLD}[4/5] DNS (SPF/DMARC)...${NC}"
        spf_check
        dmarc_check

        echo -e "\n${BOLD}[5/5] Certificate Check...${NC}"
        certificate_chain_check 443
    fi

    log SUCCESS "Quick audit complete"
    show_findings_summary
    generate_html_report
}

# ── Standard Audit (~10-15 min) ─────────────────────────────────────────────
workflow_standard() {
    require_target || return
    log INFO "Starting Standard Audit on $AUDIT_TARGET"
    separator
    echo -e "${BOLD}${MAGENTA}  Standard Security Audit${NC}"
    echo -e "${DIM}  Estimated time: 10-15 minutes${NC}"
    separator

    echo -e "\n${BOLD}=== Network Module ===${NC}"
    service_version_scan ""
    firewall_detect
    traceroute_analysis

    echo -e "\n${BOLD}=== SSL/TLS Module ===${NC}"
    ssl_quick_check 443
    protocol_version_test 443
    hsts_check

    echo -e "\n${BOLD}=== DNS Module ===${NC}"
    dns_enumeration
    spf_check
    dmarc_check

    if [[ "$AUDIT_MODE" == "local" ]]; then
        echo -e "\n${BOLD}=== System Module (local) ===${NC}"
        ssh_config_audit
        firewall_rules_audit
        open_ports_audit
        running_services_audit
        user_account_audit
        kernel_security_audit

        echo -e "\n${BOLD}=== Password Module (local) ===${NC}"
        password_policy_check
        ssh_key_audit

        echo -e "\n${BOLD}=== CIS Benchmark (Level 1, local) ===${NC}"
        cis_filesystem
        cis_services
        cis_network_params
        cis_firewall
        cis_logging
    else
        echo -e "\n${DIM}=== System/CIS/Password (skipped - local-only checks, target is remote) ===${NC}"
    fi

    log SUCCESS "Standard audit complete"
    show_findings_summary
    generate_all_reports
}

# ── Deep Audit (~30+ min) ───────────────────────────────────────────────────
workflow_deep() {
    require_target || return
    log INFO "Starting Deep Audit on $AUDIT_TARGET"
    separator
    echo -e "${BOLD}${MAGENTA}  Deep Security Audit${NC}"
    echo -e "${DIM}  Estimated time: 30+ minutes (includes brute-force tests)${NC}"
    separator

    echo -e "${RED}[!] Deep audit includes brute-force tests. Continue? (yes/no):${NC}"
    read -r confirm
    [[ "${confirm,,}" != "yes" ]] && return

    echo -e "\n${BOLD}=== Full Network Audit ===${NC}"
    full_network_audit

    echo -e "\n${BOLD}=== Full System Audit ===${NC}"
    full_system_audit

    echo -e "\n${BOLD}=== Full SSL/TLS Audit ===${NC}"
    full_ssl_audit

    echo -e "\n${BOLD}=== Full DNS Audit ===${NC}"
    full_dns_audit

    echo -e "\n${BOLD}=== Full Password Audit ===${NC}"
    full_password_audit

    echo -e "\n${BOLD}=== Full CIS Benchmark ===${NC}"
    run_full_cis_audit

    log SUCCESS "Deep audit complete"
    show_findings_summary
    generate_all_reports
}

# ── Custom Audit ─────────────────────────────────────────────────────────────
workflow_custom() {
    require_target || return
    separator
    echo -e "${BOLD}${WHITE}  Custom Audit - Select Modules${NC}"
    separator
    echo -e "  ${CYAN}[1]${NC}  Network Security"
    echo -e "  ${CYAN}[2]${NC}  System / Host Security"
    echo -e "  ${CYAN}[3]${NC}  SSL/TLS & Certificates"
    echo -e "  ${CYAN}[4]${NC}  DNS Security"
    echo -e "  ${CYAN}[5]${NC}  Password & Authentication"
    echo -e "  ${CYAN}[6]${NC}  CIS Compliance Benchmark"
    separator
    echo -e "${YELLOW}Enter module numbers separated by spaces (e.g., 1 3 5):${NC}"
    read -r selections

    for sel in $selections; do
        case "$sel" in
            1) echo -e "\n${BOLD}=== Network Audit ===${NC}";   full_network_audit ;;
            2) echo -e "\n${BOLD}=== System Audit ===${NC}";    full_system_audit ;;
            3) echo -e "\n${BOLD}=== SSL/TLS Audit ===${NC}";   full_ssl_audit ;;
            4) echo -e "\n${BOLD}=== DNS Audit ===${NC}";       full_dns_audit ;;
            5) echo -e "\n${BOLD}=== Password Audit ===${NC}";  full_password_audit ;;
            6) echo -e "\n${BOLD}=== CIS Benchmark ===${NC}";   run_full_cis_audit ;;
            *) log WARN "Invalid module: $sel" ;;
        esac
    done

    show_findings_summary
    generate_all_reports
}

# ── Raspberry Pi Self-Audit ─────────────────────────────────────────────────
workflow_pi_selfaudit() {
    AUDIT_TARGET="127.0.0.1"
    AUDIT_MODE="local"
    log INFO "Starting Raspberry Pi self-audit (localhost)"
    separator
    echo -e "${BOLD}${MAGENTA}  Raspberry Pi Self-Audit${NC}"
    echo -e "${DIM}  Auditing local system security${NC}"
    separator

    echo -e "\n${BOLD}[1/7] SSH Configuration...${NC}"
    ssh_config_audit

    echo -e "\n${BOLD}[2/7] Firewall Rules...${NC}"
    firewall_rules_audit

    echo -e "\n${BOLD}[3/7] Open Ports...${NC}"
    open_ports_audit

    echo -e "\n${BOLD}[4/7] Running Services...${NC}"
    running_services_audit

    echo -e "\n${BOLD}[5/7] User Accounts...${NC}"
    user_account_audit

    echo -e "\n${BOLD}[6/7] Kernel Security...${NC}"
    kernel_security_audit

    echo -e "\n${BOLD}[7/7] CIS Benchmark...${NC}"
    run_full_cis_audit

    log SUCCESS "Raspberry Pi self-audit complete"
    show_findings_summary
    generate_all_reports
}

# =============================================================================
# Workflow Menu
# =============================================================================
workflow_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}${WHITE}  Automated Workflow Pipelines${NC}"
        separator
        echo -e "  ${CYAN}[1]${NC}  Quick Audit        ${DIM}(~2-3 min)  Ports, SSH, FW, SSL, Passwords${NC}"
        echo -e "  ${CYAN}[2]${NC}  Standard Audit     ${DIM}(~10-15 min) All basics + CIS Level 1${NC}"
        echo -e "  ${CYAN}[3]${NC}  Deep Audit         ${DIM}(~30+ min)  Everything including brute-force${NC}"
        echo -e "  ${CYAN}[4]${NC}  Custom Audit       ${DIM}Select specific modules${NC}"
        echo -e "  ${CYAN}[5]${NC}  Pi Self-Audit      ${DIM}Audit this Raspberry Pi (localhost)${NC}"
        separator
        echo -e "  ${CYAN}[0]${NC}  Back to Main Menu"
        separator
        echo -e "${YELLOW}Select option [0-5]: ${NC}"
        read -r choice
        case "$choice" in
            1) workflow_quick; press_enter ;;
            2) workflow_standard; press_enter ;;
            3) workflow_deep; press_enter ;;
            4) workflow_custom; press_enter ;;
            5) workflow_pi_selfaudit; press_enter ;;
            0) return ;;
            *) log WARN "Invalid option"; sleep 1 ;;
        esac
    done
}

# =============================================================================
# Main Menu
# =============================================================================
main_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}${WHITE}  Main Menu${NC}"
        separator
        echo -e "  ${CYAN}[1]${NC}   Set Target"
        echo -e "  ${CYAN}[2]${NC}   Network Security Audit"
        echo -e "  ${CYAN}[3]${NC}   System / Host Security Audit"
        echo -e "  ${CYAN}[4]${NC}   SSL/TLS & Certificate Audit"
        echo -e "  ${CYAN}[5]${NC}   DNS Security Audit"
        echo -e "  ${CYAN}[6]${NC}   Password & Authentication Audit"
        echo -e "  ${CYAN}[7]${NC}   CIS Compliance Benchmark"
        separator
        echo -e "  ${CYAN}[8]${NC}   Automated Workflows"
        echo -e "  ${CYAN}[9]${NC}   Generate Reports"
        echo -e "  ${CYAN}[10]${NC}  Check Dependencies"
        echo -e "  ${CYAN}[11]${NC}  View Findings Summary"
        separator
        echo -e "  ${CYAN}[0]${NC}   Exit"
        separator
        echo -e "${YELLOW}Select option [0-11]: ${NC}"
        read -r choice
        case "$choice" in
            1)  set_target ;;
            2)  network_audit_menu ;;
            3)  system_audit_menu ;;
            4)  ssl_audit_menu ;;
            5)  dns_audit_menu ;;
            6)  password_audit_menu ;;
            7)  compliance_menu ;;
            8)  workflow_menu ;;
            9)  reporting_menu ;;
            10) check_dependencies; press_enter ;;
            11) show_findings_summary; press_enter ;;
            0)
                cleanup
                echo -e "\n${GREEN}Session output: $SESSION_DIR${NC}"
                echo -e "${CYAN}Thank you for using Security Audit Suite.${NC}\n"
                exit 0
                ;;
            *)  log WARN "Invalid option"; sleep 1 ;;
        esac
    done
}

# =============================================================================
# Entry Point
# =============================================================================
main() {
    # Set trap for cleanup
    trap cleanup EXIT INT TERM

    # Initialize session
    init_session

    # Authorization check
    check_authorization

    # Show banner and root check
    show_banner
    check_root || true
    check_dependencies || true
    press_enter

    # Enter main menu
    main_menu
}

# Run
main "$@"
