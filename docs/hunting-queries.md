# Threat hunting & investigation queries — Home SOC Lab

Saved queries for reading this lab's telemetry the way an analyst would: the
Suricata C2 signature (sid 1000001 → Wazuh 100101) and the Wazuh alert feed.
The goal is to show the *pivot* — from an alert to the raw flow to a verdict —
not just that a rule fired.

> Run these on the Wazuh manager. `alerts.json` holds rule matches;
> Suricata's `eve.json` holds every network event it saw.

## Validate the Wazuh rule before deploy — `wazuh-logtest`

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste one Suricata eve.json "alert" line, then read:
#   Phase 3: Completed filtering (rules)  ->  id 100101, level 10
```

The syntax of the whole rule file is checked with:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

## The C2 beacon case (sid 1000001 / rule 100101)

### In Wazuh

```bash
# Every time the custom C2 correlation fired, with the hosts involved
sudo jq -c 'select(.rule.id=="100101")
            | {t:.timestamp, level:.rule.level,
               sig:.data.alert.signature_id,
               src:.data.src_ip, dst:.data.dest_ip,
               dport:.data.dest_port}' \
     /var/ossec/logs/alerts/alerts.json
```

### In Suricata (the raw flows behind the alert)

```bash
# All events for the lab C2 signature
sudo jq -c 'select(.alert.signature_id==1000001)
            | {t:.timestamp, src:.src_ip, sport:.src_port,
               dst:.dest_ip, dport:.dest_port, proto:.proto}' \
     /var/log/suricata/eve.json

# Beacon cadence: count flows to the C2 port per minute (regularity = beacon)
sudo jq -r 'select(.dest_port==4445 and .event_type=="flow")
            | .timestamp[0:16]' /var/log/suricata/eve.json \
  | sort | uniq -c
```

A roughly constant count per interval is the beacon tell — contrast it with
human traffic, which is bursty.

### Field breakdown (what to read, and why)

| Field (eve.json) | Meaning |
|---|---|
| `alert.signature_id` | which rule matched (`1000001` = lab C2) |
| `src_ip` / `dest_ip` | victim → C2 direction |
| `dest_port` | `4445` — the C2 listener |
| `flow.bytes_toserver` / `bytes_toclient` | small, symmetric = beacon; large pull = exfil/stage |
| `proto` | TCP here |

## General triage — what fired, ranked

```bash
sudo jq -r '[.rule.level, .rule.id, .rule.description] | @tsv' \
     /var/ossec/logs/alerts/alerts.json | sort -rn | uniq -c | head -20
```

## Correlate network ↔ host

The same compromise should be visible from two angles. List every distinct
source IP Suricata flagged, then check whether the host logs show activity
from it:

```bash
sudo jq -r 'select(.event_type=="alert") | .src_ip' \
     /var/log/suricata/eve.json | sort | uniq -c | sort -rn
```

## Pattern for new signatures

When you add a signature, capture one `eve.json` alert line into
[`../samples/`](../samples/) and paste it through `wazuh-logtest` so the repo
shows both the raw event and the proof the rule classifies it.
