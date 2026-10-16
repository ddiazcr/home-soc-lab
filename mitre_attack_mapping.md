# MITRE ATT&CK Mapping — Home SOC Lab Incident

This document maps each phase of the simulated intrusion documented in
[`INCIDENT_REPORT.md`](./INCIDENT_REPORT.md) to its MITRE ATT&CK (Enterprise)
technique, the evidence that supports it, and whether the lab's detection
stack (Suricata + Wazuh) caught it.

Coverage legend: ✅ detected = an alert fired and is captured in the evidence;
❌ not detected = no rule in this lab covered the technique; it was identified
during manual investigation or is known from the attacker side of the exercise.

## Summary

| Phase | Tactic | Technique | ID | Evidence | Detection |
|---|---|---|---|---|---|
| Reconnaissance | Discovery | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | `nmap -sV -sC` against 192.168.56.104 | ❌ not detected |
| Exploitation | Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Samba `usermap_script`, CVE-2007-2447 (ports 139/445) | ❌ not detected |
| Exploitation | Execution | Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | `cmd/unix/reverse` payload; `/tmp/beacon.sh` | ❌ not detected |
| Post-exploitation | Discovery | System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | `whoami`, `id` → `uid=0(root)` | ❌ not detected |
| Post-exploitation | Discovery | System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | `uname -a` | ❌ not detected |
| Persistence | Persistence, Execution | Scheduled Task/Job: Cron | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Entry in `/etc/crontab` running `/tmp/beacon.sh` every 2 minutes | ❌ not detected (found during response) |
| C2 | Command and Control | Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) | Raw TCP reverse shell from target to attacker | ✅ Suricata `sid:1000001` → Wazuh rule 100101 |
| C2 | Command and Control | Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | Beacon to a dedicated listener port, not a well-known service port | ✅ Suricata `sid:1000001` → Wazuh rule 100101 |

**Kill chain in one line:** T1046 → T1190 → T1059.004 → T1033 / T1082 →
T1053.003 → T1095 / T1571.

## Technique details

### T1046 — Network Service Discovery
The attacker enumerated exposed services on the target with `nmap -sV -sC`,
identifying vsftpd 2.3.4, Samba smbd 3.0.20, UnrealIRCd, Java RMI and a bind
shell on port 1524. This scan happened entirely inside the Host-Only network
between two lab hosts.

### T1190 — Exploit Public-Facing Application (CVE-2007-2447)
Samba 3.0.20 passes the username supplied during authentication to the
`username map script` without sanitizing shell metacharacters. The Metasploit
module `exploit/multi/samba/usermap_script` abuses this to run arbitrary
commands as the Samba process, which on Metasploitable2 runs as **root**. No
privilege escalation step was needed, so no Privilege Escalation technique is
mapped for this incident.

### T1059.004 — Unix Shell
The injected command spawned a reverse shell (`cmd/unix/reverse`) back to the
attacker. The same technique applies to the persistence payload, since the
cron job executes a shell script (`/tmp/beacon.sh`).

### T1033 / T1082 — Discovery after access
`whoami`, `id` and `uname -a` were run to confirm the access level and the
kernel version. These are typical first commands after landing on a host.

### T1053.003 — Scheduled Task/Job: Cron
A cron entry added to `/etc/crontab` executed `/tmp/beacon.sh` every two
minutes. This gives the attacker persistence across reboots and is also the
trigger for the C2 beacon. ATT&CK lists this technique under Persistence,
Execution and Privilege Escalation; here it was used for persistence and
execution only, since the attacker was already root.

### T1095 / T1571 — C2 over raw TCP on a non-standard port
Each cron run opened a short-lived TCP connection from the target
(192.168.56.104) to the attacker (192.168.56.103) on a dedicated listener
port. The traffic is a raw shell over TCP (no application-layer protocol such
as HTTP or DNS), sent to a port that does not belong to any standard service.
The regular two-minute interval is what made it detectable.

## Detection coverage

| Detection | Source | Logic | Techniques |
|---|---|---|---|
| Suricata `sid:1000001` — "POSSIBLE C2 BEACON" | Network (NIDS) | Repeated short-lived TCP connections from the target to the attacker's listener port in a short window | T1095, T1571 |
| Wazuh rule `100101` (level 10) — "Home SOC Lab: possible recurring C2 connections" | SIEM correlation of Suricata `eve.json` | Raises the Suricata signature to a level 10 alert | T1095, T1571 |

The rule fired on 2026-09-20 17:40:06 and 2026-09-21 15:51:44, and no new
alerts appeared after remediation (see
[`INCIDENT_REPORT.md`](./INCIDENT_REPORT.md), Sections 6 and 8, and the
[`evidence/`](./evidence/) folder).

## Detection gaps and next steps

Only the C2 phase was detected. The earlier phases were invisible to the
stack, which means a real attacker would have had several days of access
before the first alert (compromise on 2026-09-14, first detection on
2026-09-20). Possible improvements for each gap:

| Gap | Technique | Proposed detection |
|---|---|---|
| Port scan not alerted | T1046 | Suricata threshold rule for many SYNs to distinct ports from one source, or enable the scan-detection signatures of a public ruleset |
| Exploit not alerted | T1190 | Suricata signature for shell metacharacters (backticks, `/=`) in the SMB session-setup username field |
| Cron change not alerted | T1053.003 | Wazuh File Integrity Monitoring (`syscheck`) on `/etc/crontab` and `/etc/cron.*`, which requires a host agent on the target |
| Script dropped in `/tmp` not alerted | T1059.004 | FIM or auditd rule for executable files created in `/tmp` |

Metasploitable2 runs a very old distribution (Ubuntu 8.04), so installing a
current Wazuh agent on it may not be possible. In that case, network-based
detection of the exploit (T1190) is the most practical first improvement.

The AI triage pipeline in [`AI/`](./AI/README.md) was tested against alerts
from the T1095 / T1571 detection above. Its own metrics are documented
separately in [`pipeline_metrics.md`](./pipeline_metrics.md).
