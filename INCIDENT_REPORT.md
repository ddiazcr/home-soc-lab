# Incident Report — Home SOC Lab

**Classification:** Simulated Incident (Home Lab Environment)
**Analyst:** Daniel Díaz
**Environment:** Isolated VirtualBox Host-Only network (192.168.56.0/24)
**Status:** Contained and Remediated

---

## 1. Executive Summary

On September 14, 2026, a simulated attacker gained unauthorized root access to a lab host (Metasploitable2) by exploiting a known vulnerability in the Samba service. The attacker established persistence and a periodic outbound connection resembling Command & Control (C2) beaconing. This activity was later detected through correlated network (Suricata) and host-based (Wazuh) monitoring, and fully remediated. This report documents the complete incident lifecycle, from initial reconnaissance to final verification, as a hands-on exercise in detection engineering and incident response.

## 2. Scope

| Item | Detail |
|---|---|
| Affected host | Metasploitable2 — 192.168.56.104 |
| Attacker host | Kali Linux — 192.168.56.103 |
| Monitoring host | Wazuh Server (SIEM + NIDS) — 192.168.56.102 |
| Network | Isolated VirtualBox Host-Only network |
| Impact | Simulated — no production systems or real data involved |

## 3. Reconnaissance

An `nmap -sV -sC` scan was run against the target to enumerate running services and identify potential attack vectors. Results revealed several outdated, vulnerable services typical of a deliberately insecure host:

- **vsftpd 2.3.4** (port 21) — anonymous FTP access enabled
- **Samba smbd 3.0.20-Debian** (ports 139/445)
- **UnrealIRCd** (port 6667)
- **Java RMI Registry** (port 1099)
- A pre-configured root shell (port 1524)

Of these, the Samba service was selected as the exploitation vector, prioritizing a vulnerability with real-world relevance and documented impact over more commonly demonstrated shortcuts (e.g. the vsftpd 2.3.4 backdoor).

## 4. Exploitation

**Vulnerability:** Samba `usermap_script` Remote Command Execution — **CVE-2007-2447**
**Tool:** Metasploit Framework
**Module:** `exploit/multi/samba/usermap_script`
**Payload:** `cmd/unix/reverse`

The exploit was launched against 192.168.56.104 with the payload configured to call back to the attacker host (192.168.56.103) on port 4444. The exploit succeeded on **2026-09-14 at 17:19:43**, returning an interactive command shell.

**Post-exploitation verification:**
- `whoami` → `root`
- `id` → `uid=0(root) gid=0(root)`
- `uname -a` → Linux metasploitable 2.6.24-16-server

No privilege escalation was required — the vulnerability granted immediate root-level access.

## 5. Persistence & Command and Control (C2)

To simulate a realistic post-exploitation scenario, a persistence mechanism was installed combining persistence and C2 beaconing into a single technique: a cron job was added to the target's system crontab, executing a lightweight beacon script every 2 minutes to re-establish a reverse connection to the attacker host on a dedicated port.

This mechanism was confirmed active on **2026-09-14 at 21:51:42**, with a successful reconnection observed on the attacker's listener.

> **Note:** Exact script contents and full payload details are intentionally omitted from this report to avoid providing a directly reusable attack script.

## 6. Detection

Two independent detection layers were configured to identify this activity:

**Network layer (Suricata):**
A custom rule was written to flag the periodic beacon pattern. The rule fired correctly in `eve.json`, generating the alert:
> `signature: "POSSIBLE C2 BEACON"` — category: *A Network Trojan was detected*

**SIEM layer (Wazuh):**
The Suricata alert was ingested and correlated into a custom Wazuh detection rule (`rule.id 100101`, severity level 10):
> *"Home SOC Lab: possible C2 connections"*

This alert surfaced directly in the Wazuh dashboard and was confirmed as reproducible, appearing consistently across multiple days while the beacon remained active — validating that the detection logic was reliable rather than a one-off match.

## 7. Containment & Eradication

Remediation was performed directly on the affected host:

1. Removed the malicious cron entries from `/etc/crontab`.
2. Verified the change with a `diff` against a pre-remediation backup, confirming that only the malicious lines were removed and no legitimate configuration was affected.
3. Checked all other common persistence locations (`cron.d`, `cron.daily`, `cron.weekly`, `cron.hourly`, `cron.monthly`, `init.d`, `rc.local`) — no additional persistence found.
4. Confirmed no beacon process was running, no active connections remained on the C2 port, and the dropped script file no longer existed on disk.

Remediation was completed on **2026-09-20 at 19:28:05**.

## 8. Verification

Following remediation, the Wazuh dashboard was reviewed over a 24-hour window spanning the cleanup. The last C2-related alert was observed **before** remediation; **no new alerts were generated afterward**, confirming the threat was fully contained and did not reappear.

## 9. Indicators of Compromise (IOCs)

| Type | Indicator |
|---|---|
| CVE | CVE-2007-2447 (Samba `usermap_script`) |
| Persistence | Unauthorized entry in `/etc/crontab` executing a script every 2 minutes |
| Network | Periodic outbound connection matching Suricata signature `sid:1000001` |
| Detection rule | Wazuh `rule.id 100101` (level 10) |

## 10. Lessons Learned

- Correlating network-based (Suricata) and host-based (Wazuh) detections produced far more reliable results than relying on either source alone.
- Persistence and C2 mechanisms can be technically simple — a single cron entry — while remaining highly effective if not actively monitored.
- Infrastructure issues (e.g. systemd startup timeouts under constrained lab resources) can silently break detection pipelines; monitoring the health of the SOC stack itself is as important as monitoring the target.
- Documenting each phase in real time made the final report significantly easier to reconstruct accurately.

## 11. Architecture

```
                    Host-Only Network (192.168.56.0/24)

   ┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
   │   Kali Linux     │        │   Wazuh Server   │        │  Metasploitable2 │
   │  192.168.56.103  │◄──────►│  192.168.56.102  │◄──────►│  192.168.56.104  │
   │  (Attacker)      │        │ (SIEM + NIDS)    │        │  (Target)        │
   └─────────────────┘        └─────────────────┘        └─────────────────┘
                                       │
                                       ▼
                              Wazuh Manager + Indexer
                              + Dashboard + Suricata
```

---

## Appendix — Timeline

| Timestamp (2026) | Event |
|---|---|
| Sep 14, 17:19:43 | Initial exploitation (Samba `usermap_script` / CVE-2007-2447) |
| Sep 14, 21:51:42 | Persistence + C2 established via cron beacon |
| Sep 20, 17:40:06 | First Wazuh detection (rule.id 100101) |
| Sep 20, 19:28:05 | Remediation completed (crontab cleaned, verified) |
| Sep 21, 15:51:44 | Second detection, confirming rule reliability |

---

*This report documents a simulated security incident conducted entirely within an isolated home lab environment for educational purposes. No production systems, real organizations, or real data were involved.*
