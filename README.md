# Home SOC Lab

A self-built home lab simulating a full incident response lifecycle — from initial reconnaissance to detection and remediation — using a real SIEM stack (Wazuh + Suricata) against a deliberately vulnerable target (Metasploitable2).

## Overview

This project simulates a real-world security incident end-to-end in a controlled home lab environment. The goal was to gain hands-on experience with the complete SOC workflow: attack simulation, network/host-based detection, and incident response — not just tool installation, but a documented, reproducible case study.

**Scope covered:**
- Reconnaissance and vulnerability identification
- Exploitation of a real CVE
- Persistence and C2 (Command & Control) simulation
- Detection using a SIEM (Wazuh) and NIDS (Suricata)
- Containment, eradication, and verification
- Full incident report following industry-standard structure

## Architecture

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

All three machines run as VirtualBox VMs on an isolated Host-Only network, with no exposure to the host's production network.

## Lab Setup

| Component | Details |
|---|---|
| Hypervisor | VirtualBox |
| Attacker | Kali Linux — 192.168.56.103 |
| Target | Metasploitable2 — 192.168.56.104 |
| SIEM / NIDS | Wazuh 4.9.2 + Suricata 8.0.3 — 192.168.56.102 |
| Network | Host-Only, 192.168.56.0/24 |

## Attack Simulation

### Reconnaissance
`nmap -sV -sC` against the target revealed multiple outdated, vulnerable services typical of Metasploitable2, including:
- vsftpd 2.3.4 (port 21, anonymous FTP enabled)
- Samba smbd 3.0.20-Debian (ports 139/445)
- UnrealIRCd (port 6667)
- Java RMI Registry (port 1099)
- A pre-configured root shell (port 1524)

### Exploitation
Selected **Samba `usermap_script` (CVE-2007-2447)** as the exploitation vector over more commonly used vectors (e.g. vsftpd 2.3.4 backdoor), prioritizing technical relevance and impact.

Using Metasploit's `exploit/multi/samba/usermap_script` with a `cmd/unix/reverse` payload, a reverse shell was established, granting **immediate root access** with no privilege escalation required (`uid=0(root)`).

### Persistence & C2
A cron job was installed on the target (`/etc/crontab`) to execute a beacon script (`/tmp/beacon.sh`) every 2 minutes, opening a periodic reverse connection back to the attacker machine — simulating both **persistence** and **C2 beaconing** in a single mechanism.

## Detection

- **Suricata** custom rule (`sid:1000001`) flagged the periodic beacon traffic as *"POSSIBLE C2 BEACON"*, correctly classified under the Network Trojan category.
- **Wazuh** correlated the Suricata alert into a custom detection rule (`rule.id 100101`, level 10) — *"Home SOC Lab: possible C2 connections"* — surfaced directly in the Wazuh dashboard.
- Alerts were confirmed on two separate days, validating that detection persisted reliably across the beacon's lifecycle.

## Response & Remediation

1. Removed the persistence mechanism from `/etc/crontab` on the target.
2. Verified via `diff` against a pre-remediation backup that only the malicious lines were removed.
3. Checked for additional persistence across `cron.d`, `cron.daily/weekly/hourly/monthly`, `init.d`, and `rc.local` — none found.
4. Confirmed no `beacon.sh` process running, no active connections on the C2 port, and the dropped file no longer present on disk.

## Verification

Reviewed the Wazuh dashboard over a 24-hour window spanning the remediation: the last C2 alert appeared *before* remediation, with **no new alerts generated afterward** — confirming the incident was fully contained.

## Timeline

| Timestamp (2026) | Event |
|---|---|
| Sep 14, 17:19:43 | Initial exploitation (Samba `usermap_script` / CVE-2007-2447) |
| Sep 14, 21:51:42 | Persistence + C2 established via cron beacon |
| Sep 20, 17:40:06 | First Wazuh detection (rule.id 100101) |
| Sep 20, 19:28:05 | Remediation completed (crontab cleaned, verified) |
| Sep 21, 15:51:44 | Second detection confirming rule reliability |

## Incident Report

A full incident report is included in this repository, following a standard structure (Executive Summary, Scope, Reconnaissance, Exploitation, Persistence/C2, Detection, Containment/Eradication, Verification, IOCs, Lessons Learned, Architecture):

📄 [`INCIDENT_REPORT.md`](./INCIDENT_REPORT.md)

## Lessons Learned

- Correlating NIDS (Suricata) and SIEM (Wazuh) detections is significantly more reliable than relying on either tool alone.
- Persistence and C2 mechanisms are often simple (a single cron entry) but can be highly effective if not actively monitored.
- Systemd timeout defaults are a common, easy-to-miss cause of failures when running resource-heavy security tools (Suricata, Wazuh indexer) on constrained lab hardware.

## Tools Used

- Wazuh 4.9.2 (SIEM)
- Suricata 8.0.3 (NIDS)
- Kali Linux
- Metasploitable2
- VirtualBox

## Roadmap

Next planned addition to this lab: Windows + Active Directory logging via a Wazuh agent, focused on login events, account creation, privilege changes, and scheduled tasks — closing the gap in Windows-based enterprise detection scenarios.

---

*This project is for educational purposes only, built entirely within an isolated home lab environment.*
