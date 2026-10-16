# Log samples

Anonymized raw events from the lab so the detections can be understood without
rebuilding the environment. Each file is the exact data a rule fires on.

## How to populate

```bash
# Suricata C2 signature (sid 1000001)
sudo jq -c 'select(.alert.signature_id==1000001)' \
     /var/log/suricata/eve.json | head -3 > suricata-c2-1000001.json

# The Wazuh alert that chained off it (rule 100101)
sudo jq -c 'select(.rule.id=="100101")' \
     /var/ossec/logs/alerts/alerts.json | head -3 > wazuh-c2-100101.json
```

Suggested files:

| File | From | Notes |
|---|---|---|
| `suricata-c2-1000001.json` | eve.json | raw network alert |
| `wazuh-c2-100101.json` | alerts.json | correlated host-side alert |

## Anonymize before committing

- Keep the lab IPs (`192.168.56.0/24`) — private and part of the design.
- Remove agent keys and anything non-lab.
- Keep the JSON structure so the field paths in
  [`../docs/hunting-queries.md`](../docs/hunting-queries.md) still line up.
