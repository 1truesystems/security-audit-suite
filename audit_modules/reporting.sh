#!/usr/bin/env bash
# =============================================================================
# Reporting Engine Module
# HTML, JSON, CSV report generation with risk scoring and remediation
# =============================================================================

# =============================================================================
# HTML Report Generator
# =============================================================================
generate_html_report() {
    local report_file="$SESSION_DIR/reports/audit_report_${SESSION_ID}.html"
    local score
    score="$(calculate_risk_score)"
    local grade
    grade="$(risk_grade)"
    local total_findings=$FINDING_COUNT
    local report_date
    report_date="$(date '+%B %d, %Y %H:%M:%S')"

    log INFO "Generating HTML report: $report_file"

    # Determine grade color
    local grade_color_hex
    case "$grade" in
        A) grade_color_hex="#00e676" ;;
        B) grade_color_hex="#76ff03" ;;
        C) grade_color_hex="#ffc107" ;;
        D) grade_color_hex="#ff9800" ;;
        F) grade_color_hex="#f44336" ;;
    esac

    cat > "$report_file" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report</title>
<style>
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-card: #1c2333;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --border-color: #30363d;
    --accent-cyan: #58a6ff;
    --accent-green: #3fb950;
    --critical-color: #ff4757;
    --high-color: #ff6348;
    --medium-color: #ffa502;
    --low-color: #58a6ff;
    --info-color: #7c8894;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 20px;
}
.container { max-width: 1200px; margin: 0 auto; }
.header {
    text-align: center;
    padding: 40px 20px;
    background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
    border: 1px solid var(--border-color);
    border-radius: 12px;
    margin-bottom: 30px;
}
.header h1 {
    font-size: 2.2em;
    color: var(--accent-cyan);
    margin-bottom: 10px;
    letter-spacing: 2px;
}
.header .subtitle {
    color: var(--text-secondary);
    font-size: 1.1em;
}
.meta-info {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin: 20px 0;
    padding: 15px;
    background: var(--bg-primary);
    border-radius: 8px;
}
.meta-item { padding: 10px; }
.meta-label { color: var(--text-secondary); font-size: 0.85em; text-transform: uppercase; }
.meta-value { color: var(--text-primary); font-size: 1.1em; font-weight: 600; }

/* Score Card */
.score-card {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 40px;
    padding: 30px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    margin-bottom: 30px;
}
.score-circle {
    width: 150px;
    height: 150px;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-size: 3em;
    font-weight: bold;
    border: 4px solid;
}
.score-label { font-size: 0.3em; color: var(--text-secondary); font-weight: normal; }
.score-details { text-align: left; }
.score-details h3 { margin-bottom: 10px; color: var(--text-primary); }

/* Severity badges */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 0.8em;
    font-weight: 600;
    text-transform: uppercase;
}
.badge-critical { background: var(--critical-color); color: #fff; }
.badge-high { background: var(--high-color); color: #fff; }
.badge-medium { background: var(--medium-color); color: #000; }
.badge-low { background: var(--low-color); color: #fff; }
.badge-info { background: var(--info-color); color: #fff; }

/* Stats bar */
.stats-bar {
    display: flex;
    gap: 15px;
    margin: 15px 0;
    flex-wrap: wrap;
}
.stat-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    background: var(--bg-primary);
    border-radius: 8px;
    border: 1px solid var(--border-color);
}
.stat-count { font-size: 1.5em; font-weight: bold; }
.stat-label { color: var(--text-secondary); font-size: 0.85em; }

/* Sections */
.section {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 25px;
    margin-bottom: 20px;
}
.section h2 {
    color: var(--accent-cyan);
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 10px;
    margin-bottom: 20px;
    font-size: 1.4em;
}

/* Findings table */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
}
th {
    background: var(--bg-primary);
    color: var(--accent-cyan);
    padding: 12px 15px;
    text-align: left;
    font-weight: 600;
    border-bottom: 2px solid var(--border-color);
}
td {
    padding: 12px 15px;
    border-bottom: 1px solid var(--border-color);
    color: var(--text-primary);
}
tr:hover td { background: rgba(88, 166, 255, 0.05); }
.remediation {
    color: var(--accent-green);
    font-style: italic;
    font-size: 0.9em;
}

/* Footer */
.footer {
    text-align: center;
    padding: 20px;
    color: var(--text-secondary);
    font-size: 0.85em;
    border-top: 1px solid var(--border-color);
    margin-top: 30px;
}

@media print {
    body { background: #fff; color: #000; }
    .header { background: #f5f5f5; }
    .section { border: 1px solid #ddd; }
    th { background: #f0f0f0; color: #333; }
    td { color: #333; }
}
</style>
</head>
<body>
<div class="container">
HTMLHEAD

    # Header
    cat >> "$report_file" << EOF
<div class="header">
    <h1>SECURITY AUDIT REPORT</h1>
    <p class="subtitle">Professional Security Assessment</p>
    <div class="meta-info">
        <div class="meta-item">
            <div class="meta-label">Target</div>
            <div class="meta-value">${AUDIT_TARGET:-N/A}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Date</div>
            <div class="meta-value">${report_date}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Session ID</div>
            <div class="meta-value">${SESSION_ID}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Audit Mode</div>
            <div class="meta-value">${AUDIT_MODE}</div>
        </div>
    </div>
</div>
EOF

    # Executive Summary / Score Card
    cat >> "$report_file" << EOF
<div class="score-card">
    <div class="score-circle" style="border-color: ${grade_color_hex}; color: ${grade_color_hex};">
        ${grade}
        <span class="score-label">${score}/100</span>
    </div>
    <div class="score-details">
        <h3>Risk Assessment Score</h3>
        <div class="stats-bar">
            <div class="stat-item">
                <span class="stat-count" style="color: var(--critical-color)">${#FINDINGS_CRITICAL[@]}</span>
                <span class="stat-label">Critical</span>
            </div>
            <div class="stat-item">
                <span class="stat-count" style="color: var(--high-color)">${#FINDINGS_HIGH[@]}</span>
                <span class="stat-label">High</span>
            </div>
            <div class="stat-item">
                <span class="stat-count" style="color: var(--medium-color)">${#FINDINGS_MEDIUM[@]}</span>
                <span class="stat-label">Medium</span>
            </div>
            <div class="stat-item">
                <span class="stat-count" style="color: var(--low-color)">${#FINDINGS_LOW[@]}</span>
                <span class="stat-label">Low</span>
            </div>
            <div class="stat-item">
                <span class="stat-count" style="color: var(--info-color)">${#FINDINGS_INFO[@]}</span>
                <span class="stat-label">Info</span>
            </div>
        </div>
        <p style="color: var(--text-secondary); margin-top: 10px;">
            Total findings: ${total_findings}
        </p>
    </div>
</div>
EOF

    # Findings Table - sorted by severity
    cat >> "$report_file" << 'EOF'
<div class="section">
    <h2>Detailed Findings</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Module</th>
                <th>Finding</th>
                <th>Description</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
EOF

    local row_num=0

    # Helper to output finding rows
    _html_findings_rows() {
        local severity="$1"
        local badge_class="$2"
        shift 2
        local -a findings=("$@")
        for finding in "${findings[@]}"; do
            [[ -z "$finding" ]] && continue
            row_num=$((row_num + 1))
            IFS='|' read -r _id module title description remediation <<< "$finding"
            # Escape HTML
            title="${title//&/&amp;}"
            title="${title//</&lt;}"
            title="${title//>/&gt;}"
            description="${description//&/&amp;}"
            description="${description//</&lt;}"
            description="${description//>/&gt;}"
            remediation="${remediation//&/&amp;}"
            remediation="${remediation//</&lt;}"
            remediation="${remediation//>/&gt;}"
            cat >> "$report_file" << EOF
            <tr>
                <td>${row_num}</td>
                <td><span class="badge ${badge_class}">${severity}</span></td>
                <td>${module}</td>
                <td><strong>${title}</strong></td>
                <td>${description}</td>
                <td class="remediation">${remediation}</td>
            </tr>
EOF
        done
    }

    (( ${#FINDINGS_CRITICAL[@]} > 0 )) && _html_findings_rows "CRITICAL" "badge-critical" "${FINDINGS_CRITICAL[@]}"
    (( ${#FINDINGS_HIGH[@]} > 0 ))     && _html_findings_rows "HIGH"     "badge-high"     "${FINDINGS_HIGH[@]}"
    (( ${#FINDINGS_MEDIUM[@]} > 0 ))   && _html_findings_rows "MEDIUM"   "badge-medium"   "${FINDINGS_MEDIUM[@]}"
    (( ${#FINDINGS_LOW[@]} > 0 ))      && _html_findings_rows "LOW"      "badge-low"      "${FINDINGS_LOW[@]}"
    (( ${#FINDINGS_INFO[@]} > 0 ))     && _html_findings_rows "INFO"     "badge-info"     "${FINDINGS_INFO[@]}"

    if (( row_num == 0 )); then
        cat >> "$report_file" << 'EOF'
            <tr>
                <td colspan="6" style="text-align: center; color: var(--text-secondary);">
                    No findings recorded. Run audit modules to generate findings.
                </td>
            </tr>
EOF
    fi

    cat >> "$report_file" << 'EOF'
        </tbody>
    </table>
</div>
EOF

    # Remediation Priority Section
    if (( ${#FINDINGS_CRITICAL[@]} > 0 || ${#FINDINGS_HIGH[@]} > 0 )); then
        cat >> "$report_file" << 'EOF'
<div class="section">
    <h2>Priority Remediation Actions</h2>
    <p style="color: var(--text-secondary); margin-bottom: 15px;">
        Address these issues in order of severity to improve your security posture.
    </p>
    <ol style="padding-left: 20px;">
EOF
        for finding in "${FINDINGS_CRITICAL[@]}"; do
            [[ -z "$finding" ]] && continue
            IFS='|' read -r _id module title description remediation <<< "$finding"
            remediation="${remediation//&/&amp;}"
            remediation="${remediation//</&lt;}"
            remediation="${remediation//>/&gt;}"
            title="${title//&/&amp;}"
            title="${title//</&lt;}"
            title="${title//>/&gt;}"
            cat >> "$report_file" << EOF
        <li style="margin-bottom: 10px;">
            <span class="badge badge-critical">CRITICAL</span>
            <strong>${title}</strong><br>
            <span class="remediation">${remediation}</span>
        </li>
EOF
        done
        for finding in "${FINDINGS_HIGH[@]}"; do
            [[ -z "$finding" ]] && continue
            IFS='|' read -r _id module title description remediation <<< "$finding"
            remediation="${remediation//&/&amp;}"
            remediation="${remediation//</&lt;}"
            remediation="${remediation//>/&gt;}"
            title="${title//&/&amp;}"
            title="${title//</&lt;}"
            title="${title//>/&gt;}"
            cat >> "$report_file" << EOF
        <li style="margin-bottom: 10px;">
            <span class="badge badge-high">HIGH</span>
            <strong>${title}</strong><br>
            <span class="remediation">${remediation}</span>
        </li>
EOF
        done
        echo '    </ol></div>' >> "$report_file"
    fi

    # Footer
    cat >> "$report_file" << EOF
<div class="footer">
    <p>Security Audit Suite v${VERSION} | Report generated: ${report_date}</p>
    <p>Session: ${SESSION_ID} | Target: ${AUDIT_TARGET:-N/A}</p>
    <p style="margin-top: 10px;">
        This report is confidential and intended for authorized personnel only.
    </p>
</div>
</div>
</body>
</html>
EOF

    log SUCCESS "HTML report generated: $report_file"
    echo -e "${GREEN}[✓]${NC} Report: $report_file"
}

# =============================================================================
# JSON Report Generator
# =============================================================================
generate_json_report() {
    local report_file="$SESSION_DIR/reports/audit_report_${SESSION_ID}.json"
    log INFO "Generating JSON report: $report_file"

    local score
    score="$(calculate_risk_score)"
    local grade
    grade="$(risk_grade)"

    # Build findings arrays
    _json_findings_array() {
        local severity="$1"
        shift
        local -a findings=("$@")
        local first=1
        echo "["
        for finding in "${findings[@]}"; do
            [[ -z "$finding" ]] && continue
            IFS='|' read -r _id module title description remediation <<< "$finding"
            # Escape JSON
            title="${title//\\/\\\\}"
            title="${title//\"/\\\"}"
            description="${description//\\/\\\\}"
            description="${description//\"/\\\"}"
            remediation="${remediation//\\/\\\\}"
            remediation="${remediation//\"/\\\"}"
            [[ $first -eq 0 ]] && echo ","
            first=0
            cat << EOF
    {
      "severity": "${severity}",
      "module": "${module}",
      "title": "${title}",
      "description": "${description}",
      "remediation": "${remediation}"
    }
EOF
        done
        echo "  ]"
    }

    cat > "$report_file" << EOF
{
  "report": {
    "title": "Security Audit Report",
    "version": "${VERSION}",
    "generated": "$(date -Iseconds)",
    "session_id": "${SESSION_ID}",
    "target": "${AUDIT_TARGET:-null}",
    "audit_mode": "${AUDIT_MODE}"
  },
  "risk_assessment": {
    "score": ${score},
    "grade": "${grade}",
    "total_findings": ${FINDING_COUNT},
    "by_severity": {
      "critical": ${#FINDINGS_CRITICAL[@]},
      "high": ${#FINDINGS_HIGH[@]},
      "medium": ${#FINDINGS_MEDIUM[@]},
      "low": ${#FINDINGS_LOW[@]},
      "info": ${#FINDINGS_INFO[@]}
    }
  },
  "findings": {
    "critical": $( (( ${#FINDINGS_CRITICAL[@]} > 0 )) && _json_findings_array "CRITICAL" "${FINDINGS_CRITICAL[@]}" || echo "[]"),
    "high": $( (( ${#FINDINGS_HIGH[@]} > 0 )) && _json_findings_array "HIGH" "${FINDINGS_HIGH[@]}" || echo "[]"),
    "medium": $( (( ${#FINDINGS_MEDIUM[@]} > 0 )) && _json_findings_array "MEDIUM" "${FINDINGS_MEDIUM[@]}" || echo "[]"),
    "low": $( (( ${#FINDINGS_LOW[@]} > 0 )) && _json_findings_array "LOW" "${FINDINGS_LOW[@]}" || echo "[]"),
    "info": $( (( ${#FINDINGS_INFO[@]} > 0 )) && _json_findings_array "INFO" "${FINDINGS_INFO[@]}" || echo "[]")
  }
}
EOF

    log SUCCESS "JSON report generated: $report_file"
    echo -e "${GREEN}[✓]${NC} Report: $report_file"
}

# =============================================================================
# CSV Report Generator
# =============================================================================
generate_csv_report() {
    local report_file="$SESSION_DIR/reports/audit_report_${SESSION_ID}.csv"
    log INFO "Generating CSV report: $report_file"

    echo '"#","Severity","Module","Title","Description","Remediation"' > "$report_file"

    local row=0

    _csv_findings() {
        local severity="$1"
        shift
        local -a findings=("$@")
        for finding in "${findings[@]}"; do
            [[ -z "$finding" ]] && continue
            row=$((row + 1))
            IFS='|' read -r _id module title description remediation <<< "$finding"
            # Escape CSV (double-quote escaping)
            title="${title//\"/\"\"}"
            description="${description//\"/\"\"}"
            remediation="${remediation//\"/\"\"}"
            echo "\"${row}\",\"${severity}\",\"${module}\",\"${title}\",\"${description}\",\"${remediation}\""
        done
    }

    (( ${#FINDINGS_CRITICAL[@]} > 0 )) && _csv_findings "CRITICAL" "${FINDINGS_CRITICAL[@]}" >> "$report_file"
    (( ${#FINDINGS_HIGH[@]} > 0 ))     && _csv_findings "HIGH"     "${FINDINGS_HIGH[@]}"     >> "$report_file"
    (( ${#FINDINGS_MEDIUM[@]} > 0 ))   && _csv_findings "MEDIUM"   "${FINDINGS_MEDIUM[@]}"   >> "$report_file"
    (( ${#FINDINGS_LOW[@]} > 0 ))      && _csv_findings "LOW"      "${FINDINGS_LOW[@]}"      >> "$report_file"
    (( ${#FINDINGS_INFO[@]} > 0 ))     && _csv_findings "INFO"     "${FINDINGS_INFO[@]}"     >> "$report_file"

    log SUCCESS "CSV report generated: $report_file"
    echo -e "${GREEN}[✓]${NC} Report: $report_file"
}

# =============================================================================
# Generate All Reports
# =============================================================================
generate_all_reports() {
    separator
    echo -e "${BOLD}${WHITE}  Generating All Reports${NC}"
    separator
    generate_html_report
    generate_json_report
    generate_csv_report
    echo -e "\n${GREEN}All reports saved to: $SESSION_DIR/reports/${NC}"
}

# =============================================================================
# Reporting Menu
# =============================================================================
reporting_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}${WHITE}  Report Generation${NC}"
        separator
        show_findings_summary
        echo ""
        echo -e "  ${CYAN}[1]${NC}  Generate HTML Report"
        echo -e "  ${CYAN}[2]${NC}  Generate JSON Report"
        echo -e "  ${CYAN}[3]${NC}  Generate CSV Report"
        echo -e "  ${CYAN}[4]${NC}  Generate All Reports"
        echo -e "  ${CYAN}[5]${NC}  View Findings Summary"
        separator
        echo -e "  ${CYAN}[0]${NC}  Back to Main Menu"
        separator
        echo -e "${YELLOW}Select option [0-5]: ${NC}"
        read -r choice
        case "$choice" in
            1) generate_html_report; press_enter ;;
            2) generate_json_report; press_enter ;;
            3) generate_csv_report; press_enter ;;
            4) generate_all_reports; press_enter ;;
            5) show_findings_summary; press_enter ;;
            0) return ;;
            *) log WARN "Invalid option"; sleep 1 ;;
        esac
    done
}
