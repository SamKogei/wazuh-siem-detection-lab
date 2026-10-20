# Incident Report
## Security Incident: Multi-Stage Adversarial Attack Against Monitored Endpoint

**Report ID:** IR-2026-001  
**Date:** October 19, 2026  
**Severity:** Critical  
**Status:** Completed — Controlled Lab Simulation  
**Analyst:** SOC Detection Engineering Lab  

---

## Executive Summary

A controlled adversarial simulation was conducted against a monitored 
Ubuntu Server endpoint (192.168.56.102) running Wazuh SIEM/XDR 4.12.0. 
The attacker machine (Kali Linux 2026.2, 192.168.56.103) executed a 
multi-stage attack chain spanning reconnaissance, web enumeration, 
credential attacks, persistence, defense evasion, and credential 
harvesting.

Wazuh detected and logged all attack stages. Custom detection rules 
written specifically for this environment identified gaps in default 
coverage — including shadow file access and log tampering — which 
default rules alone would have missed at the appropriate severity level.

A total of **213,320 security events** were generated over the simulation 
period, with **173,703 authentication failures** attributed to SSH brute 
force activity from the attacker IP (192.168.56.103).

---

## Incident Timeline

| Date | Event |
|------|-------|
| Oct 17, 2026 | Initial reconnaissance — stealth SYN scan, service fingerprinting, vulnerability scan |
| Oct 17, 2026 | Web enumeration — nikto, dirb, wfuzz executed against target |
| Oct 18, 2026 | SSH brute force initiated — Hydra with multiple usernames and rockyou.txt wordlist |
| Oct 18, 2026 | 173,703 authentication failures recorded in Wazuh |
| Oct 19, 2026 | Backdoor user (bqckdoor-user) created — Rule 100006 fired |
| Oct 19, 2026 | Backdoor user deleted by attacker — Rule 5902 lifecycle captured |
| Oct 19, 2026 | Log files cleared via truncate — Rule 100004 fired |
| Oct 19, 2026 | /etc/shadow, /etc/passwd, /etc/sudoers accessed — Rule 100002 fired |
| Oct 19, 2026 | Malicious cron job created in /etc/cron.d — FIM alert triggered |
| Oct 19, 2026 | SUID binaries enumerated, sudo -l executed |

---

## Attack Narrative

### Stage 1 — Reconnaissance
The attacker began with a slow stealth SYN scan (`nmap -sS -T2`) 
designed to evade detection by slowing packet transmission. Two open 
ports were identified: 22 (SSH) and 443 (HTTPS). A subsequent full 
service scan revealed the server was running OpenSSH 8.9p1 and exposed 
its identity through the `osd-name: wazuhmanager` response header — 
confirming the target was a Wazuh deployment.

A vulnerability scan identified two exploitable issues:
- **CVE-2007-6750** — Slowloris DoS: LIKELY VULNERABLE
- **HTTP Verb Tampering** — Authentication bypass: VULNERABLE

![Reconnaissance](screenshots/recon-vuln-scan.png)

### Stage 2 — Web Enumeration
Nikto identified 23 security issues including five missing HTTP security 
headers and several exposed endpoints. Dirb and Wfuzz confirmed that 
authentication controls blocked most directory enumeration, though the 
`/ui` endpoint (HTTP 403) was discovered — indicating an interface exists 
beyond the login portal.

![Web Enumeration](screenshots/nikto-results.png)

### Stage 3 — Credential Attack
Hydra was used to execute an SSH brute force attack using multiple 
usernames and the rockyou.txt wordlist. Over 173,000 authentication 
failures were generated. No successful authentication was achieved, 
however the volume of attempts triggered multiple Wazuh alert rules and 
saturated the authentication logs.

![Brute Force](screenshots/threat-hunt-01-brute-force-kali.png)

### Stage 4 — Persistence
A backdoor user account (`bqckdoor-user`) was created with sudo 
privileges and subsequently deleted to simulate an attacker establishing 
then removing a persistence mechanism. Wazuh Rule 5902 (New user added) 
and custom Rule 100006 (Backdoor user detected) both fired, capturing 
the full account lifecycle including UID, GID, home directory, and shell 
assignment.

![Persistence](screenshots/persistence-02-wazuh-useradd-alerts.png)

### Stage 5 — Defense Evasion
The attacker cleared `/var/log/auth.log` and `/var/log/syslog` using 
the `truncate` command in an attempt to remove evidence of the brute 
force activity. Despite the logs being cleared, Wazuh's journald-based 
log collection captured the truncate command itself, including the full 
sudo invocation with timestamp, source user, and target command — 
demonstrating that Wazuh's collection layer operates independently of 
the log files being monitored.

![Log Tampering](screenshots/log-tamper-02-wazuh-alert.png)

### Stage 6 — Credential Harvesting
The attacker read `/etc/shadow`, `/etc/passwd`, and `/etc/sudoers` 
using sudo to harvest password hashes for offline cracking. A copy of 
`/etc/shadow` was also saved to `/tmp/shadow-copy`. Custom Rule 100002 
(level 14) fired on the shadow file access, capturing the exact command, 
source user, target user, and TTY session — providing a complete 
forensic trail of the credential harvesting attempt.

![Credential Harvesting](screenshots/credential-harvest-02-shadow-alert-detail.png)

### Stage 7 — Post-Exploitation Enumeration
SUID binaries were enumerated using `find / -perm -4000` and available 
sudo privileges were listed using `sudo -l`, providing the attacker with 
a map of local privilege escalation paths.

---

## Vulnerabilities Identified

| ID | Vulnerability | Severity | Status |
|----|--------------|----------|--------|
| CVE-2007-6750 | Slowloris DoS | High | Unpatched |
| — | HTTP Verb Tampering | High | Unpatched |
| — | SSL Certificate Misconfiguration | Medium | Unpatched |
| — | Server Identity Disclosure (osd-name header) | Medium | Unpatched |
| — | Missing HTTP Security Headers (5) | Medium | Unpatched |
| — | 201 package vulnerabilities on endpoint | Critical–Low | Unpatched |

---

## Alerts Generated

| Rule ID | Level | Description | Count |
|---------|-------|-------------|-------|
| 5763 | 10 | SSH brute force | 173,703 |
| 5902 | 8 | New user added | 8 |
| 554 | 5 | File added to system (FIM) | 8 |
| 100006 | 15 | Backdoor user created (custom) | 2 |
| 100004 | 13 | Log file cleared (custom) | 4 |
| 100002 | 14 | Shadow file accessed (custom) | 3 |
| 5402 | 3 | Sudo to ROOT executed | 47 |

![All Alerts](screenshots/events-tab-full-alert-list.png)

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection |
|--------|-----------|-----|-----------|
| Reconnaissance | Active Scanning | T1595.001 | Rule 100001 |
| Discovery | Network Service Discovery | T1046 | Rule 40101 |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Rule 5763 |
| Credential Access | OS Credential Dumping: /etc/passwd and /etc/shadow | T1003.008 | Rule 100002 |
| Persistence | Create Account: Local Account | T1136.001 | Rule 100006 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 | Rule 100003 |
| Defense Evasion | Indicator Removal: Clear Linux Logs | T1070.002 | Rule 100004 |
| Privilege Escalation | Abuse Elevation: Sudo | T1548.003 | Rule 5402 |

![MITRE ATT&CK](screenshots/mitre-attack-framework-matrix.png)

---

## Compliance Impact

| Framework | Controls Affected |
|-----------|------------------|
| **PCI DSS** | 10.2.5 (auth failures), 10.6.1 (log review), 8.1.2 (user management) |
| **GDPR** | IV_35.7.d (data protection), IV_32.2 (security measures) |
| **HIPAA** | 164.312.b (audit controls), 164.312.a.2.I (access management) |
| **NIST 800-53** | AU.14 (session audit), AC.7 (failed logons), IA.4 (identifier management) |

---

## Custom Rule Performance

| Rule | Fired | Finding |
|------|-------|---------|
| 100002 — Shadow access | Yes | Credential harvesting detected |
| 100004 — Log tampering | Yes | Defense evasion detected |
| 100006 — Backdoor user | Yes | Persistence detected |
| 100001 — Stealth scan | Partial | Dependent on parent rule 40101 |
| 100003 — Cron job | Partial | FIM scan cycle dependent |
| 100005 — Brute force threshold | Yes | Threshold rule triggered |

![Custom Rules](screenshots/custom-rules-firing-all.png)

---

## Threat Hunting Findings

**Hunt 1 — Brute Force Validation**
```
Query: data.srcip: "192.168.56.103" AND rule.groups: "authentication_failed"
Result: 173,703 hits — all authentication failures confirmed from attacker IP
```

**Hunt 2 — Persistence Hunt**
```
Query: rule.mitre.tactic: "Persistence"
Result: 106 hits — backdoor user creation confirmed, Rule 100006 validated
```

**Hunt 3 — Defense Evasion Hunt**
```
Query: rule.mitre.tactic: "Defense Evasion"
Result: 189 hits — log tampering confirmed, Rule 100004 validated
```

---

## Actions Taken During Simulation

The following actions were performed as part of the simulation to 
demonstrate the full attack lifecycle:

- Backdoor user (`bqckdoor-user`) was created then deleted during simulation
- Malicious cron job created at `/etc/cron.d/malicious-job`
- Shadow file copied to `/tmp/shadow-copy`
- Log files cleared using truncate

---

## Recommended Remediation

| Finding | Recommendation | Priority |
|---------|---------------|----------|
| Slowloris DoS vulnerability | Implement connection rate limiting | High |
| HTTP Verb Tampering | Configure strict HTTP method controls | High |
| SSH brute force exposure | Implement fail2ban or Wazuh active response to auto-block attacking IPs | High |
| 201 package vulnerabilities | Patch critical and high severity packages | Critical |
| Missing security headers | Add CSP, HSTS, X-Content-Type-Options headers | Medium |
| SSL misconfiguration | Update certificate SAN to include server IP | Medium |
| Server identity exposure | Remove osd-name header from responses | Medium |
| Attacker IP 192.168.56.103 | Block via firewall rule or Wazuh active response | High |

---

## Lessons Learned

### What Worked Well
- Wazuh captured all attack stages including activity that occurred after log clearing
- Custom rules closed detection gaps in shadow file access and log tampering
- FIM detected malicious file creation within one scan cycle
- Compliance frameworks were automatically mapped to all alerts
- Journald-based collection proved resilient against log tampering attempts

### What Could Be Improved
- Increase FIM scan frequency for critical directories (currently default interval)
- Add active response to auto-block IPs after brute force threshold is reached
- Tune Rule 100001 to fire independently of parent rule 40101
- Add email or webhook alerting for level 14+ critical events
- Disable server identity disclosure in HTTP response headers

---

## Conclusion

The simulated attack demonstrated that a determined attacker can 
generate significant forensic evidence even when attempting to cover 
their tracks. Wazuh's architecture — collecting from journald rather 
than flat log files — proved resilient against log tampering. Custom 
detection rules added meaningful coverage beyond default rules, 
particularly for credential harvesting and defense evasion techniques 
that default rules either missed or flagged at insufficient severity.

The engagement validates the lab environment as a functional detection 
platform capable of supporting real-world SOC analyst workflows.

---

*This report was produced as part of a controlled adversarial simulation 
conducted in an isolated lab environment. All activities were performed 
on systems owned and operated by the analyst. No production systems 
were affected.*
