# Detections

Detection content used in the Home SOC Lab incident ([`INCIDENT_REPORT.md`](../INCIDENT_REPORT.md), Section 6).
The original files lived only on the lab VMs; these versions were **reconstructed from the captured evidence**
and every field is marked below as either *confirmed* (visible in a screenshot) or *inferred*.

| File | Tool | What it does |
|---|---|---|
| [`suricata/local.rules`](suricata/local.rules) | Suricata | `sid:1000001` — flags recurring TCP flows from the target to the attacker's listener (C2 beacon) |
| [`wazuh/ossec_localfile.xml`](wazuh/ossec_localfile.xml) | Wazuh | `<localfile>` block that makes Wazuh read Suricata's `eve.json` |
| [`wazuh/local_rules.xml`](wazuh/local_rules.xml) | Wazuh | Rule `100101` (level 10) — raises the Suricata signature to a high-severity "possible C2" alert |

## Detection pipeline

```
Metasploitable2 (192.168.56.104) --TCP/4445 every ~2 min--> Kali (192.168.56.103)
        |
        v  traffic seen on enp0s3 of the Wazuh server (192.168.56.102)
Suricata  sid:1000001  -> /var/log/suricata/eve.json
        |
        v  <localfile> log_format=json  (built-in JSON decoder)
Wazuh rule 86601 "Suricata: Alert - ..."  (built-in, level 3)
        |
        v  if_sid 86601 + alert.signature_id == 1000001
Wazuh rule 100101  "Home SOC Lab: posibles conexiones C2 recurrentes..."  (level 10)
```

## 1. Suricata signature `sid:1000001`

```
alert tcp 192.168.56.104 any -> 192.168.56.103 4445 (msg:"LAB Possible C2 - 3 established flows within 420s";
  flow:established,to_server; flowbits:isnotset,lab_c2_counted; flowbits:set,lab_c2_counted;
  detection_filter:track by_src, count 3, seconds 420; classtype:trojan-activity; sid:1000001; rev:2;)
```

**Why it works.** The beacon is a cron job that opens a new reverse-shell connection every 2 minutes.
One connection to a non-standard port is ambiguous; the same host opening a new established session to the
same port again and again is the beaconing pattern. At a 2-minute interval, 3 flows fit comfortably
inside a 420-second (7-minute) window, so the rule fires within one beacon cycle of the third check-in
while ignoring a single one-off connection.

| Keyword | Purpose |
|---|---|
| `192.168.56.104 any -> 192.168.56.103 4445` | Target → attacker listener. Scoped to lab IPs because both hosts sit in the same `/24`, so `$HOME_NET -> $EXTERNAL_NET` would not separate them |
| `flow:established,to_server` | Only count real sessions (completed handshake), not scans or SYN noise |
| `flowbits:isnotset/set,lab_c2_counted` | Count each TCP flow **once**, not every packet in it, so the counter means "flows", not "packets" |
| `detection_filter:track by_src, count 3, seconds 420` | Alert only after 3 counted flows from the same source within 420 s |
| `classtype:trojan-activity` | Maps to "A Network Trojan was detected", priority/severity 1 |

**Evidence vs. reconstruction**

- *Confirmed* (`evidence/02-wazuh-alert-json-detail.png`): `gid:1`, `sid:1000001`, `rev:2`, message text,
  category "A Network Trojan was detected", severity 1, flowbit name `lab_c2_counted`, `direction: to_server`,
  `192.168.56.104 → 192.168.56.103:4445/TCP`.
- *Inferred*: the exact keywords that implement the "3 flows within 420 s" counter (`detection_filter` +
  flowbits). The message text and the `lab_c2_counted` flowbit point to this design, but the original rule
  body was not captured.
- *Validated*: the rule loads cleanly (`suricata -T`, 1 rule loaded, 0 failed) and, replayed against a
  synthetic pcap with 4 established flows to TCP/4445 two minutes apart, it alerts on the 3rd flow with the
  same `sid`, `rev`, category, severity, flowbit and direction seen in the lab evidence.
  Tested on Suricata 7.0.3; the lab ran 8.0.3.

## 2. Wazuh `<localfile>` block

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Suricata only writes alerts to disk; Wazuh does nothing with them until logcollector is told to read the file.
`log_format json` makes each line go through Wazuh's built-in JSON decoder, which turns keys such as
`alert.signature_id`, `src_ip` and `dest_port` into fields that rules can match.

This was one of the two pipeline gaps called out in *Lessons Learned*: Suricata was generating alerts, but none
reached the dashboard until this block existed. The lesson is to verify the whole path
(sensor → log file → collector → decoder → rule → dashboard), not just that the sensor is producing output.

*Confirmed*: the alert in the evidence was collected by the manager itself (`agent.id: 000`) and carries the raw
`eve.json` line in `full_log`. *Inferred*: the default `eve.json` path.

## 3. Wazuh rule `100101`

```xml
<group name="local,suricata,home_soc_lab,">
  <rule id="100101" level="10">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">^1000001$</field>
    <description>Home SOC Lab: posibles conexiones C2 recurrentes hacia Kali por TCP/4445.</description>
    <group>possible_c2,</group>
  </rule>
</group>
```

**Why it works.** Wazuh's stock Suricata rule 86601 fires for *every* Suricata alert at level 3, which buries a
real C2 signal among routine IDS noise (`evidence/01-suricata-alert-detected.png` shows sid 1000001 landing as
86601, level 3). Rule 100101 chains off 86601 (`if_sid`) and matches only the lab signature, promoting it to
level 10 with a description an analyst can act on. Chaining keeps the stock Suricata parsing intact and adds
context instead of duplicating it. The `^...$` anchors avoid matching other SIDs that merely contain `1000001`.

- *Confirmed* (`evidence/02-wazuh-alert-json-detail.png`, `evidence/03-wazuh-dashboard-2-alerts.png`): rule ID,
  level 10, description text, groups `local, suricata, home_soc_lab, possible_c2`, and no MITRE block on the alert.
- *Inferred*: `if_sid 86601` and the `alert.signature_id` field match (86601 is the parent seen in evidence 01).

## Decoder

No custom decoder is included. The evidence shows Wazuh's built-in rule 86601 firing on the Suricata event, and
that rule only matches events decoded by the stock `json` decoder, so the lab ended up using the built-in decoder
through `log_format json`. The "missing JSON decoder" mentioned in the report's *Lessons Learned* most likely
refers to that missing `log_format json` setting rather than to a separate decoder file. **Open question:** if a
custom decoder was written during troubleshooting, it should be added here.

