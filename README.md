# AnomalyNet — Attack Test Scripts

Scripts to run on the **attacker VPS** to test AnomalyNet IDS detection on the victim VPS.

## Quick start

```bash
# 1. Install tools on attacker VPS
curl -fsSL https://raw.githubusercontent.com/DimaFi/AnomalyNet-test/main/setup.sh | bash

# 2. Run attack suite
python3 attack.py --target <VICTIM_IP> --mode quick

# 3. Check detection stats
python3 attack.py --target <VICTIM_IP> --mode check
```

## Attack modes

| Mode    | Duration | Description |
|---------|----------|-------------|
| `quick` | 10s each | All attacks, fast |
| `all`   | 30s each | All attacks, thorough |
| `check` | —        | Just show current stats from AnomalyNet API |
| `syn`   | 15s      | SYN flood → DoS |
| `udp`   | 15s      | UDP flood → DDoS |
| `icmp`  | 15s      | ICMP flood → DoS |
| `scan`  | 30s      | Port scan → Recon |
| `http`  | 15s      | HTTP flood → WebAttack |
| `brute` | 15s      | SSH brute force → BruteForce |

## What to expect (AnomalyNet Advanced mode)

| Attack | Expected label | Expected class |
|--------|----------------|----------------|
| SYN flood | anomaly | DoS |
| UDP flood | anomaly | DoS / DDoS |
| Port scan | warning / anomaly | Recon |
| HTTP flood | warning | WebAttack |
| SSH brute | warning / anomaly | BruteForce |
| Normal browse | normal | — |

> In **Simple mode** attack_class will be null — only label (anomaly/warning/normal).
> In **Advanced mode** (Stage3) you get the specific attack class.

## Check results via API

```bash
curl http://<VICTIM_IP>:8000/api/debug/stats | python3 -m json.tool
curl http://<VICTIM_IP>:8000/api/history?limit=20 | python3 -m json.tool
```
