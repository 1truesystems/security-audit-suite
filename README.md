# Security Audit Suite

Professional security audit framework for Linux infrastructure. Modular Bash architecture with 7 specialized audit engines and automated workflow orchestration.

## Architecture

**7 audit modules | 5 workflow modes | 126+ integrated tools | ~6,000 lines**

```
┌─────────────────────────────────────────────────────┐
│            security_audit_suite.sh                  │
│            Main Orchestrator & Menu                  │
├─────────┬─────────┬─────────┬─────────┬─────────────┤
│ Network │ System  │ SSL/TLS │   DNS   │  Password   │
│  Audit  │  Audit  │  Audit  │  Audit  │   Audit     │
├─────────┴─────────┴─────────┴─────────┴─────────────┤
│    CIS Compliance Engine    │    Reporting Engine    │
├─────────────────────────────┴───────────────────────┤
│              Infrastructure Layer                    │
│        Colors · Logging · Session · Helpers          │
└─────────────────────────────────────────────────────┘
```

## Modules

| Module | Scope |
|--------|-------|
| **Network Audit** | Port scanning, service enumeration, firewall rules, ARP cache, routing, open connections, traffic analysis |
| **System Audit** | User accounts, SUID/SGID, world-writable files, cron jobs, running services, kernel parameters, disk & mount security |
| **SSL/TLS Audit** | Certificate validation, protocol versions, cipher strength, expiry checks, chain verification, HSTS |
| **DNS Audit** | Zone transfer testing, DNSSEC validation, record enumeration, subdomain discovery, MX/SPF/DMARC checks |
| **Password Audit** | PAM configuration, password policy, hash strength, account lockout, empty passwords, sudo configuration |
| **CIS Compliance** | Automated CIS Benchmark checks with pass/fail/skip scoring and control ID mapping |
| **Reporting** | HTML (styled), JSON (structured), TXT (plain) — per-module and aggregated session reports |

## Workflows

| Mode | Depth | Use Case |
|------|-------|----------|
| Quick Scan | ~2–3 min | Rapid security posture check |
| Standard Audit | ~10–15 min | Routine assessment |
| Deep Audit | ~30+ min | Comprehensive evaluation |
| Custom | Selective | Module-specific targeting |
| Pi Self-Audit | Optimized | Raspberry Pi hardening |

## Quick Start

```bash
# Install required tools (126+ packages)
sudo ./install_all_tools.sh

# Run audit suite
./security_audit_suite.sh

# Recommended: run as root for full access
sudo ./security_audit_suite.sh
```

## Tool Installer

`install_all_tools.sh` provides categorized installation of 126+ security packages:

| Category | Examples |
|----------|---------|
| Core | nmap, netcat, tcpdump, wireshark, socat |
| Network | masscan, arp-scan, nbtscan, hping3, iperf3 |
| Traffic | tshark, ettercap, mitmproxy, bettercap |
| DNS | dnsrecon, dnsenum, fierce, dnsutils, whois |
| SSL/TLS | testssl.sh, sslyze, sslscan, openssl |
| Password | john, hashcat, hydra, medusa, crunch |
| Web | nikto, dirb, gobuster, sqlmap, wpscan |
| Hardening | lynis, chkrootkit, rkhunter, aide, apparmor |

**Supports:** Ubuntu, Debian, Zorin OS, Raspberry Pi OS

## Requirements

- Bash 4.0+
- Linux (Debian-based recommended)
- Root access recommended for full functionality

## Output

- **Formats:** HTML (styled dark-theme), JSON, TXT
- **Session directory:** Timestamped per-run output with aggregated findings
- **Scoring:** Per-module pass/fail/skip with overall compliance percentage

## License

Proprietary. All rights reserved.
