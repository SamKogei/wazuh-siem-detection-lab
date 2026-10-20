# Adversary Simulation & Detection Engineering Lab
### Wazuh SIEM | MITRE ATT&CK | Custom Rules | Threat Hunting

![Wazuh Dashboard](screenshots/wazuh-01-overview-dashboard.png)

## Overview

This lab simulates a real-world adversarial attack scenario against a monitored endpoint, with full detection, investigation, and response documentation. Built from scratch using VirtualBox, Ubuntu Server 22.04, and Kali Linux, the environment replicates a SOC analyst's day-to-day workflow — from initial alert triage to threat hunting and custom detection rule development.

The lab goes beyond basic SIEM setup. I deployed Wazuh as a full XDR platform, executed a multi-stage attack chain against the monitored server, wrote custom detection rules to close gaps in default coverage, built a custom SOC dashboard, and conducted structured threat hunts using DQL queries mapped to MITRE ATT&CK tactics.

---

## Environment

| **Component** | **Details** |
|---------------|-------------|
| Host OS | Windows 11 |
| Hypervisor | VirtualBox 7.2 |
| SIEM | Wazuh 4.12.0 (Manager + Indexer + Dashboard) |
| Server | Ubuntu Server 22.04 LTS — 192.168.56.102 |
| Attacker | Kali Linux 2026.2 — 192.168.56.103 |
| Network | VirtualBox Host-Only (192.168.56.0/24) |

Both machines ran on the same isolated host-only network. Kali was enrolled as a Wazuh agent (ID 002), so every command it executed was being monitored alongside the attacks it launched — intentional, since that mirrors how a managed but compromised endpoint behaves.

---

## Attack Chain Executed

The attack followed a realistic kill chain across 8 stages:

| **Stage** | **Technique** | **Tool** | **MITRE ID** |
|-----------|--------------|----------|--------------|
| Reconnaissance | Stealth SYN scan — basic, then T2 timing | nmap -sS / nmap -sS -T2 | T1595.001 |
| Service Discovery | Version, OS, and SSL cert fingerprinting | nmap -sV -sC -O | T1046 |
| Vulnerability Assessment | CVE and misconfiguration scan | nmap --script=vuln | T1595 |
| Web Enumeration | Directory brute force and parameter fuzzing | nikto, dirb, wfuzz | T1083 |
| Credential Attack | SSH brute force against multiple usernames | Hydra + rockyou.txt | T1110.001 |
| Persistence | Backdoor user created with sudo rights, then deleted | useradd / userdel | T1136.001 |
| Defense Evasion | auth.log and syslog cleared to remove brute force evidence | truncate | T1070.002 |
| Credential Harvesting | /etc/shadow, /etc/passwd, /etc/sudoers accessed directly | cat + sudo | T1003.008 |

---

## Key Findings

### Vulnerabilities Discovered
- **CVE-2007-6750** — Slowloris DoS: LIKELY VULNERABLE
- **HTTP Verb Tampering** — Authentication bypass: VULNERABLE (Exploitable)
- **SSL Misconfiguration** — Certificate SAN limited to 127.0.0.1, CN/hostname mismatch
- **Server Identity Exposure** — `osd-name: wazuhmanager` leaked in HTTP response headers
- **Missing Security Headers** — CSP, HSTS, Permissions-Policy, Referrer-Policy, X-Content-Type-Options
- **201 Vulnerabilities on Kali agent** — 4 Critical, 89 High, 88 Medium, 20 Low

### Detection Results
- **213,320** total security events across the 48-hour simulation window
- **173,703** authentication failures attributed to Hydra brute force from 192.168.56.103
- **6 custom detection rules** deployed — Rules 100002, 100004, and 100006 confirmed fired
- **4 MITRE ATT&CK tactics** mapped on the Kali agent: Defense Evasion (15), Privilege Escalation (14), Persistence (8), Initial Access (8)

---

## Custom Detection Rules

Six custom rules were written to close gaps in Wazuh's default detection coverage. The full rule file is at `detection-engineering/custom-rules/local_rules.xml`.

| **Rule ID** | **Level** | **Description** | **MITRE** |
|-------------|-----------|-----------------|-----------|
| 100001 | 10 | Stealth port scan from known attacker IP | T1595.001 |
| 100002 | 14 | /etc/shadow accessed via sudo — credential harvesting | T1003.008 |
| 100003 | 12 | New file created in /etc/cron.d — persistence mechanism | T1053.003 |
| 100004 | 13 | Log file cleared via truncate — attacker covering tracks | T1070.002 |
| 100005 | 14 | SSH brute force threshold exceeded (10+ failures in 60s) | T1110.001 |
| 100006 | 15 | Backdoor user account created on system | T1136.001 |

![Custom Rules Firing](screenshots/detection-03-custom-rules-firing.png)

---

## Threat Hunting

Three structured threat hunts were conducted using DQL queries against the Wazuh indexer:

| **Hunt** | **Query** | **Findings** |
|----------|-----------|--------------|
| Brute Force Validation | `data.srcip: "192.168.56.103" AND rule.groups: "authentication_failed"` | 173,703 hits — 0 successful authentications |
| Persistence Hunt | `rule.mitre.tactic: "Persistence"` | 106 hits — Rule 100006 confirmed fired |
| Defense Evasion Hunt | `rule.mitre.tactic: "Defense Evasion"` | 189 hits — Rule 100004 confirmed fired |

![Brute Force Hunt](screenshots/threat-hunt-01-brute-force.png)

---

## MITRE ATT&CK Coverage

![MITRE ATT&CK Framework](screenshots/mitre-02-framework-matrix.png)

| **Tactic** | **Detections** | **Techniques** |
|------------|---------------|----------------|
| Defense Evasion | 15 | T1070.002, T1562.001, T1078 |
| Privilege Escalation | 14 | T1548.003 |
| Persistence | 8 | T1136.001, T1053.003 |
| Initial Access | 8 | T1078 |

Credential Access registers zero on the Kali agent because shadow file access was executed directly on the wazuhmanager host — those events are attributed to agent 000, not agent 002.

![MITRE ATT&CK Events](screenshots/mitre-01-kali-agent-events.png)

---

## Custom SOC Dashboard

A custom dashboard named "SOC Operations Overview" was built in OpenSearch with 8 visualizations:

- Attack Timeline by Agent
- Alert Severity Breakdown
- Top 10 Triggered Rules
- MITRE ATT&CK Tactic Distribution
- Authentication Failures vs Success
- Custom Detection Rules Fired
- Critical and High Alerts Timeline
- PCI DSS Compliance Violations

![SOC Dashboard Top](screenshots/dashboard-01-soc-top.png)
![SOC Dashboard Bottom](screenshots/dashboard-02-soc-bottom.png)

---

## Compliance Mapping

Wazuh automatically mapped alerts to compliance frameworks. The controls below reflect what fired during the simulation:

| **Framework** | **Controls Triggered** |
|---------------|----------------------|
| PCI DSS | 10.2.5, 10.6.1, 10.2.2, 10.2.6 |
| GDPR | IV_35.7.d, IV_32.2 |
| HIPAA | 164.312.b, 164.312.a.2.I, 164.312.a.2.II, 164.312.c.1, 164.312.c.2 |
| NIST 800-53 | AU.14, AC.7, AC.2, IA.4, SI.7 |

![PCI DSS Compliance](screenshots/kali-agent-02-pci-dss.png)

---

## Repository Structure

```
wazuh-siem-detection-lab/
├── README.md
├── incident-report.md
├── attack-simulation.md
├── detection-engineering.md
├── threat-hunting.md
├── detection-engineering/
│   └── custom-rules/
│       └── local_rules.xml
└── screenshots/
```

---

## Skills Demonstrated

- SIEM/XDR deployment and configuration (Wazuh 4.12)
- Detection rule engineering (XML, MITRE mapping)
- Adversary simulation (8 attack techniques)
- Threat hunting (DQL queries, tactic-based investigation)
- Vulnerability assessment (CVE identification, risk analysis)
- Incident response (alert triage, evidence collection, reporting)
- Compliance monitoring (PCI DSS, GDPR, HIPAA, NIST 800-53)
- Custom dashboard development (OpenSearch visualizations)
- Linux administration (Ubuntu Server, systemd, netplan)

---

## Tools Used

`Wazuh 4.12` `Kali Linux 2026.2` `nmap` `Hydra` `Nikto` `Dirb` `Wfuzz` `VirtualBox` `Ubuntu Server 22.04` `OpenSearch Dashboards`
