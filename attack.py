#!/usr/bin/env python3
"""
AnomalyNet Attack Simulator
Run on the ATTACKER VPS to generate traffic toward the VICTIM VPS.

Usage:
    python3 attack.py --target 1.2.3.4 --mode quick
    python3 attack.py --target 1.2.3.4 --mode all --reset-victim --victim-key ~/.ssh/id_rsa
    python3 attack.py --target 1.2.3.4 --mode all --unblock-victim --victim-key ~/.ssh/id_rsa
    python3 attack.py --target 1.2.3.4 --mode full --reset-victim --victim-export export.json
    python3 attack.py --target 1.2.3.4 --mode check

Auto-block workflow (recommended for flood attacks):
    1. Enable auto_block on victim in Settings
    2. Run: python3 attack.py --target VICTIM --mode all --unblock-victim --reset-victim --victim-key ~/.ssh/id_rsa
    3. Before each attack: attacker IP is unblocked
    4. Attack runs → AnomalyNet detects → auto_block fires → flood stops naturally
    5. After victim service restart: counters reset, ready for next attack
"""

import argparse
import subprocess
import sys
import time
import json
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Colors ────────────────────────────────────────────────────
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
CYAN   = "\033[0;36m"
YELLOW = "\033[1;33m"
BOLD   = "\033[1m"
NC     = "\033[0m"

def log(msg):  print(f"{CYAN}>  {msg}{NC}")
def ok(msg):   print(f"{GREEN}[OK] {msg}{NC}")
def warn(msg): print(f"{YELLOW}[!!] {msg}{NC}")
def err(msg):  print(f"{RED}[ERR] {msg}{NC}", file=sys.stderr)
def header(msg): print(f"\n{BOLD}{msg}{NC}")


# ── Victim SSH helpers ────────────────────────────────────────
def _ssh_run(target: str, command: str, user: str = "root",
             ssh_port: int = 22, ssh_key: str | None = None,
             timeout: int = 20) -> tuple[bool, str]:
    """Run a command on the victim via SSH. Returns (success, stderr)."""
    cmd = ["ssh",
           "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=10",
           "-p", str(ssh_port)]
    if ssh_key:
        cmd += ["-i", ssh_key]
    cmd += [f"{user}@{target}", command]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return result.returncode == 0, result.stderr.decode().strip()
    except subprocess.TimeoutExpired:
        return False, "SSH timed out"
    except FileNotFoundError:
        return False, "ssh not found"


def reset_victim_service(target: str, user: str = "root", ssh_port: int = 22,
                         ssh_key: str | None = None) -> bool:
    """SSH to victim and restart anomalynet service to reset stats counters."""
    log(f"Resetting victim service via SSH ({user}@{target})...")
    ok_flag, err_msg = _ssh_run(
        target,
        "systemctl restart anomalynet && sleep 4",
        user, ssh_port, ssh_key, timeout=25,
    )
    if ok_flag:
        ok("Victim service restarted — counters cleared")
    else:
        warn(f"SSH reset failed: {err_msg}")
    return ok_flag


def unblock_victim_ips(target: str, api_port: int = 8000, user: str = "root",
                       ssh_port: int = 22, ssh_key: str | None = None) -> bool:
    """SSH to victim and remove all blocked IPs via API (DELETE /api/blocked-ips/all)."""
    log(f"Unblocking all IPs on victim ({user}@{target})...")
    ok_flag, err_msg = _ssh_run(
        target,
        f"curl -s -X DELETE http://localhost:{api_port}/api/blocked-ips/all",
        user, ssh_port, ssh_key, timeout=15,
    )
    if ok_flag:
        ok("All blocked IPs removed on victim")
    else:
        warn(f"Unblock SSH failed: {err_msg}")
    return ok_flag


def fetch_victim_export(target: str, port: int = 8000) -> dict | None:
    """Fetch full event export from victim's /api/export endpoint."""
    if not HAS_REQUESTS:
        return None
    url = f"http://{target}:{port}/api/export"
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        warn(f"Could not fetch victim export: {e}")
        return None


# ── API helpers ───────────────────────────────────────────────
def fetch_stats(target: str, port: int = 8000, retries: int = 2) -> dict | None:
    """Fetch stats from AnomalyNet API with retry on failure."""
    if not HAS_REQUESTS:
        return None
    url = f"http://{target}:{port}/api/debug/stats"
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                warn(f"API timeout (attempt {attempt+1}/{retries}), retrying in 5s...")
                time.sleep(5)
            else:
                warn(f"API timeout after {retries} attempts: {url}")
        except requests.exceptions.ConnectionError as e:
            if attempt < retries - 1:
                warn(f"API connection error (attempt {attempt+1}/{retries}): {e}, retrying in 5s...")
                time.sleep(5)
            else:
                warn(f"API unreachable: {e}")
        except Exception as e:
            warn(f"API error: {type(e).__name__}: {e}")
            break
    return None


def print_stats(stats: dict, label: str = ""):
    if not stats:
        warn("Could not reach AnomalyNet API")
        return
    header(f"=== Stats {label} ===")
    total = stats.get("uptime_events_total", 0)
    labels = stats.get("events_by_label", {})
    classes = stats.get("events_by_attack_class", {})
    protos = stats.get("events_by_protocol", {})

    print(f"  Total events   : {total}")
    print(f"  normal         : {labels.get('normal', 0)}")
    print(f"  warning        : {labels.get('warning', 0)}")
    print(f"  anomaly        : {labels.get('anomaly', 0)}")
    print(f"  avg score      : {stats.get('avg_score', 0):.3f}")
    print(f"  max score      : {stats.get('max_score', 0):.3f}")
    print(f"  detection mode : {stats.get('detection_mode', '?')}")
    print(f"  active model   : {stats.get('active_model_id', '?')}")

    if classes:
        print(f"\n  Attack classes detected:")
        for cls, cnt in sorted(classes.items(), key=lambda x: -x[1]):
            print(f"    {cls:<15} {cnt}")
    if protos:
        print(f"\n  By protocol:")
        for p, cnt in sorted(protos.items(), key=lambda x: -x[1]):
            print(f"    {p:<10} {cnt}")

    top_ips = stats.get("top_src_ips", {})
    if top_ips:
        print(f"\n  Top source IPs:")
        for ip, cnt in list(top_ips.items())[:5]:
            print(f"    {ip:<20} {cnt}")
    print()


def print_attack_result(name: str, desc: str, stats_before: dict | None, stats_after: dict | None):
    """Print clear diff: what was detected DURING this specific attack phase."""
    if not stats_before or not stats_after:
        return

    b_total  = stats_before.get("uptime_events_total", 0)
    a_total  = stats_after.get("uptime_events_total", 0)
    b_labels = stats_before.get("events_by_label", {})
    a_labels = stats_after.get("events_by_label", {})
    b_cls    = stats_before.get("events_by_attack_class", {})
    a_cls    = stats_after.get("events_by_attack_class", {})

    new_total   = a_total - b_total
    new_normal  = a_labels.get("normal", 0)  - b_labels.get("normal", 0)
    new_warning = a_labels.get("warning", 0) - b_labels.get("warning", 0)
    new_anomaly = a_labels.get("anomaly", 0) - b_labels.get("anomaly", 0)

    # Class diff
    new_cls = {}
    for cls in set(list(b_cls.keys()) + list(a_cls.keys())):
        diff = a_cls.get(cls, 0) - b_cls.get(cls, 0)
        if diff > 0:
            new_cls[cls] = diff

    detected = new_warning + new_anomaly
    rate = (detected / new_total * 100) if new_total > 0 else 0

    print(f"\n  ┌─ РЕЗУЛЬТАТ [{name.upper()}] {desc}")
    print(f"  │  Новых событий  : {new_total}")
    print(f"  │  Норма          : {new_normal}")
    print(f"  │  Предупреждение : {new_warning}")
    print(f"  │  Аномалия       : {new_anomaly}")
    print(f"  │  Обнаружено     : {detected}/{new_total} ({rate:.0f}%)")
    if new_cls:
        cls_str = ", ".join(f"{c}:{n}" for c, n in sorted(new_cls.items(), key=lambda x: -x[1]))
        print(f"  │  Классы атак    : {cls_str}")
    else:
        print(f"  │  Классы атак    : —")
    if detected > 0:
        print(f"  └─ {GREEN}[ОБНАРУЖЕНО]{NC}")
    else:
        print(f"  └─ {YELLOW}[НЕ ОБНАРУЖЕНО]{NC}")
    print()


# ── Attack functions ──────────────────────────────────────────
def run_cmd(cmd: list[str], duration: int, label: str):
    log(f"Running {label} for {duration}s...")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(duration)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        ok(f"{label} done")
    except FileNotFoundError:
        warn(f"{cmd[0]} not found — skipping {label} (run setup.sh first)")
    except KeyboardInterrupt:
        proc.terminate()
        raise


def attack_syn(target: str, duration: int):
    """SYN flood — should trigger DoS detection.
    Uses -i u500 (2000 pps) instead of --flood to keep the victim API responsive."""
    run_cmd(
        ["hping3", "--syn", "-p", "80", "-i", "u500", "-q", target],
        duration, "SYN Flood"
    )


def attack_udp(target: str, duration: int):
    """UDP flood — should trigger DoS/DDoS detection."""
    run_cmd(
        ["hping3", "--udp", "-p", "53", "-i", "u500", "-q", target],
        duration, "UDP Flood"
    )


def attack_icmp(target: str, duration: int):
    """ICMP flood (ping flood) — should trigger DoS detection."""
    run_cmd(
        ["hping3", "--icmp", "-i", "u500", "-q", target],
        duration, "ICMP Flood"
    )


def attack_scan(target: str, duration: int):
    """Port scan — should trigger Recon detection (especially in Advanced mode)"""
    log("Running Port Scan (nmap SYN scan, top 1000 ports)...")
    try:
        result = subprocess.run(
            ["nmap", "-sS", "-T4", "--top-ports", "1000", "-q", target],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=max(duration, 30)
        )
        ok("Port scan done")
    except FileNotFoundError:
        warn("nmap not found — skipping scan (run setup.sh first)")
    except subprocess.TimeoutExpired:
        ok("Port scan timeout (expected)")


def attack_http(target: str, duration: int, port: int = 80):
    """HTTP flood — many GET requests; should trigger WebAttack/DoS"""
    log(f"Running HTTP Flood on {target}:{port} for {duration}s...")
    if not HAS_REQUESTS:
        warn("requests not installed — skipping HTTP flood (pip3 install requests)")
        return
    deadline = time.time() + duration
    sent = 0
    while time.time() < deadline:
        try:
            requests.get(f"http://{target}:{port}/", timeout=1)
        except Exception:
            pass
        sent += 1
    ok(f"HTTP flood done ({sent} requests)")


def attack_http_api(target: str, duration: int):
    """HTTP flood against AnomalyNet API port (8000) — generates known HTTP traffic"""
    attack_http(target, duration, port=8000)


def attack_brute(target: str, duration: int):
    """SSH brute force simulation — should trigger BruteForce detection"""
    log(f"Running SSH brute force simulation for {duration}s...")
    if not HAS_REQUESTS:
        # Fallback: hping3 TCP to port 22
        run_cmd(
            ["hping3", "--syn", "-p", "22", "--flood", "-q", target],
            duration, "SSH BruteForce (SYN)"
        )
        return

    # Send many fast TCP connections to port 22
    import socket
    deadline = time.time() + duration
    attempts = 0
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect((target, 22))
            s.close()
        except Exception:
            pass
        attempts += 1
    ok(f"Brute force done ({attempts} connection attempts)")


def attack_normal(target: str, duration: int, api_port: int = 8000):
    """Generate normal/benign traffic — realistic HTTP browsing simulation"""
    log(f"Generating normal traffic for {duration}s...")
    if not HAS_REQUESTS:
        warn("requests not installed — skipping (pip3 install requests)")
        return

    import socket
    endpoints = [
        f"http://{target}:{api_port}/api/health",
        f"http://{target}:{api_port}/api/stream/snapshot",
        f"http://{target}:{api_port}/api/models",
        f"http://{target}:{api_port}/api/debug/stats",
        f"http://{target}:{api_port}/",
    ]
    # Also do some TCP browsing to port 80 with realistic timing
    deadline = time.time() + duration
    sent = 0
    while time.time() < deadline:
        url = endpoints[sent % len(endpoints)]
        try:
            requests.get(url, timeout=3)
        except Exception:
            pass
        sent += 1
        # Realistic inter-request delay: 0.5–1.5s
        time.sleep(0.5 + (sent % 3) * 0.3)

    # Also a few short-lived TCP flows to port 80 (simulate web browsing)
    for _ in range(min(10, duration // 3)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, 80))
            s.send(b"GET / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
            s.recv(256)
            s.close()
        except Exception:
            pass
        time.sleep(1.0)

    ok(f"Normal traffic done ({sent} requests)")


# ── Report saving ─────────────────────────────────────────────
def save_report(filepath: str, phases: list[dict]):
    """Save structured JSON report with stats from each test phase."""
    report = {
        "generated_at": datetime.now().isoformat(),
        "phases": phases,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    ok(f"Report saved → {filepath}")


# Expected detection classes per attack type
EXPECTED_CLASSES: dict[str, list[str]] = {
    "syn":   ["DoS"],
    "udp":   ["DoS", "DDoS"],
    "icmp":  ["DoS"],
    "scan":  ["Recon"],
    "http":  ["DoS", "WebAttack"],
    "brute": ["BruteForce"],
}


def print_comparison_table(attack_results: list[dict]):
    """Print thesis-ready comparison table: attack vs what AnomalyNet detected."""
    if not attack_results:
        return
    header("=== ИТОГОВАЯ ТАБЛИЦА: Атака vs Обнаружение ===")
    COL = [14, 18, 22, 10, 8]
    sep = "+" + "+".join("-" * (c + 2) for c in COL) + "+"
    def row(*cells):
        parts = []
        for cell, w in zip(cells, COL):
            parts.append(f" {str(cell):<{w}} ")
        print("|" + "|".join(parts) + "|")

    print(sep)
    row("Атака", "Ожид. класс", "Обнаружен класс", "Событий", "Детекция")
    print(sep)

    for r in attack_results:
        name     = r.get("name", "?")
        detected = r.get("detected", 0)
        total    = r.get("total", 0)
        classes  = r.get("new_classes", {})
        expected = EXPECTED_CLASSES.get(name, ["?"])

        cls_str = ", ".join(f"{c}:{n}" for c, n in sorted(classes.items(), key=lambda x: -x[1])) if classes else "—"
        exp_str = "/".join(expected)
        rate    = f"{detected/total*100:.0f}%" if total > 0 else "—"

        # Check if detected expected class
        hit = any(e in classes for e in expected)
        mark = f"{GREEN}✓{NC}" if hit else f"{YELLOW}✗{NC}"
        row(f"{mark} {name}", exp_str, cls_str[:22], f"{detected}/{total}", rate)

    print(sep)
    print()


# ── Attack plan ───────────────────────────────────────────────
ATTACK_PLAN = [
    ("syn",   attack_syn,      "SYN Flood → DoS"),
    ("udp",   attack_udp,      "UDP Flood → DoS/DDoS"),
    ("icmp",  attack_icmp,     "ICMP Flood → DoS"),
    ("scan",  attack_scan,     "Port Scan → Recon (Advanced mode)"),
    ("http",  attack_http_api, "HTTP Flood → WebAttack"),
    ("brute", attack_brute,    "SSH Brute → BruteForce"),
]


def run_all(target: str, duration: int, api_port: int = 8000, save: str | None = None,
            reset_victim: bool = False, unblock_victim: bool = False,
            victim_user: str = "root", victim_ssh_port: int = 22,
            victim_ssh_key: str | None = None):
    header(f"Starting full attack sequence → {target}")
    flags = []
    if reset_victim:   flags.append("reset-victim: ON")
    if unblock_victim: flags.append("unblock-victim: ON (auto_block mode)")
    header(f"Each attack: {duration}s | API port: {api_port}"
           + (f" | {', '.join(flags)}" if flags else ""))

    if unblock_victim:
        log("AUTO-BLOCK MODE: victim will block attacker → flood stops naturally → unblock before each round")

    phases = []

    if reset_victim:
        reset_victim_service(target, victim_user, victim_ssh_port, victim_ssh_key)
    stats_before = fetch_stats(target, api_port)
    print_stats(stats_before, "BEFORE ATTACKS")
    if stats_before:
        phases.append({"phase": "before_attacks", "timestamp": datetime.now().isoformat(), "stats": stats_before})

    attack_results = []
    for name, fn, desc in ATTACK_PLAN:
        header(f"[{name.upper()}] {desc}")
        t_start = datetime.now().isoformat()

        # Unblock first so attacker isn't still blocked from previous round
        if unblock_victim:
            unblock_victim_ips(target, api_port, victim_user, victim_ssh_port, victim_ssh_key)
            time.sleep(1)  # brief pause for iptables rule removal

        # Reset counters before each attack for clean per-attack stats
        if reset_victim:
            reset_victim_service(target, victim_user, victim_ssh_port, victim_ssh_key)

        stats_phase_before = fetch_stats(target, api_port)
        fn(target, duration)

        # Flood attacks: wait for auto_block to fire and API to recover
        # Port scan / http: 5s is enough; flood: need up to 15s
        wait_s = 15 if name in ("syn", "udp", "icmp") else 5
        if unblock_victim and name in ("syn", "udp", "icmp"):
            log(f"Waiting {wait_s}s for auto_block to fire and API to recover...")
        time.sleep(wait_s)

        stats_phase_after = fetch_stats(target, api_port)
        if stats_phase_after is None and unblock_victim:
            # API still recovering — try once more after extra wait
            warn("API still recovering, retrying in 10s...")
            time.sleep(10)
            stats_phase_after = fetch_stats(target, api_port)

        if stats_phase_after:
            phases.append({"phase": f"after_{name}", "attack": name, "started_at": t_start,
                           "finished_at": datetime.now().isoformat(), "stats": stats_phase_after})
        print_attack_result(name, desc, stats_phase_before, stats_phase_after)

        # Collect for comparison table
        if stats_phase_before and stats_phase_after:
            b_cls = stats_phase_before.get("events_by_attack_class", {})
            a_cls = stats_phase_after.get("events_by_attack_class", {})
            b_lbl = stats_phase_before.get("events_by_label", {})
            a_lbl = stats_phase_after.get("events_by_label", {})
            new_cls = {c: a_cls.get(c, 0) - b_cls.get(c, 0) for c in set(list(b_cls) + list(a_cls)) if a_cls.get(c, 0) - b_cls.get(c, 0) > 0}
            total   = stats_phase_after.get("uptime_events_total", 0) - stats_phase_before.get("uptime_events_total", 0)
            detected = (a_lbl.get("warning", 0) - b_lbl.get("warning", 0)) + (a_lbl.get("anomaly", 0) - b_lbl.get("anomaly", 0))
            attack_results.append({"name": name, "desc": desc, "total": total, "detected": detected, "new_classes": new_cls})

    time.sleep(3)
    stats_after = fetch_stats(target, api_port)
    print_stats(stats_after, "AFTER ALL ATTACKS")
    if stats_after:
        phases.append({"phase": "after_all_attacks", "timestamp": datetime.now().isoformat(), "stats": stats_after})

    # Summary
    header("=== SUMMARY ===")
    if stats_before and stats_after:
        before_anomalies = stats_before.get("events_by_label", {}).get("anomaly", 0)
        after_anomalies  = stats_after.get("events_by_label", {}).get("anomaly", 0)
        new_anomalies    = after_anomalies - before_anomalies
        before_total     = stats_before.get("uptime_events_total", 0)
        after_total      = stats_after.get("uptime_events_total", 0)
        new_total        = after_total - before_total

        print(f"  New events processed : {new_total}")
        print(f"  New anomalies        : {new_anomalies}")
        classes_after = stats_after.get("events_by_attack_class", {})
        if classes_after:
            print(f"  Attack classes seen  : {', '.join(classes_after.keys())}")
        print()

        if new_anomalies > 0:
            ok("AnomalyNet detected attacks!")
        else:
            warn("No anomalies detected — check that capture is running and mode is correct")

    print_comparison_table(attack_results)

    if save:
        save_report(save, phases)

    return phases


def run_full(target: str, duration: int, api_port: int = 8000, save: str | None = None,
             reset_victim: bool = False, unblock_victim: bool = False,
             victim_user: str = "root", victim_ssh_port: int = 22,
             victim_ssh_key: str | None = None):
    """Full test: normal baseline → all attacks → normal again → save structured report."""
    header(f"Full test (normal + attacks + normal) → {target}")
    phases = []

    # Phase 1: normal baseline
    header("[NORMAL] Baseline normal traffic")
    t0 = datetime.now().isoformat()
    attack_normal(target, max(duration, 20), api_port)
    time.sleep(3)
    stats_normal_before = fetch_stats(target, api_port)
    print_stats(stats_normal_before, "AFTER NORMAL (baseline)")
    if stats_normal_before:
        phases.append({"phase": "normal_baseline", "started_at": t0,
                       "finished_at": datetime.now().isoformat(), "stats": stats_normal_before})

    # Phase 2: all attacks
    attack_phases = run_all(target, duration, api_port, save=None,
                            reset_victim=reset_victim, unblock_victim=unblock_victim,
                            victim_user=victim_user, victim_ssh_port=victim_ssh_port,
                            victim_ssh_key=victim_ssh_key)
    phases.extend(attack_phases)

    # Phase 3: normal traffic again
    header("[NORMAL] Post-attack normal traffic")
    t1 = datetime.now().isoformat()
    attack_normal(target, max(duration, 20), api_port)
    time.sleep(3)
    stats_normal_after = fetch_stats(target, api_port)
    print_stats(stats_normal_after, "AFTER NORMAL (post-attack)")
    if stats_normal_after:
        phases.append({"phase": "normal_post_attack", "started_at": t1,
                       "finished_at": datetime.now().isoformat(), "stats": stats_normal_after})

    if save:
        save_report(save, phases)
    else:
        auto_name = f"anomalynet_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_report(auto_name, phases)
        print(f"  Tip: copy report with:  scp root@{target}:{auto_name} .")


def run_single(name: str, target: str, duration: int):
    fn = None
    for aname, afn, _ in ATTACK_PLAN:
        if aname == name:
            fn = afn
            break
    if fn is None:
        err(f"Unknown attack: {name}. Choose: {[a[0] for a in ATTACK_PLAN]}")
        sys.exit(1)
    fn(target, duration)


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="AnomalyNet Attack Simulator — run on the ATTACKER VPS"
    )
    parser.add_argument("--target", "-t", required=True, help="Victim VPS IP address")
    parser.add_argument("--mode", "-m", default="quick",
        choices=["quick", "all", "full", "check", "normal",
                 "syn", "udp", "icmp", "scan", "http", "brute"],
        help="Attack mode (default: quick). 'full' = normal+attacks+normal+report")
    parser.add_argument("--duration", "-d", type=int, default=None,
        help="Duration per attack in seconds (default: 10 for quick, 30 for all/full)")
    parser.add_argument("--api-port", type=int, default=8000,
        help="AnomalyNet API port on victim (default: 8000)")
    parser.add_argument("--save", "-s", type=str, default=None,
        help="Save JSON report to file (default: auto-named for --mode full)")
    parser.add_argument("--reset-victim", action="store_true",
        help="SSH to victim and restart anomalynet before each attack (clean counters)")
    parser.add_argument("--unblock-victim", action="store_true",
        help="SSH to victim and unblock all IPs before each attack (for auto_block mode). "
             "Use when victim has auto_block enabled — attacker gets blocked, flood stops, "
             "then this flag unblocks before the next attack automatically.")
    parser.add_argument("--victim-user", type=str, default="root",
        help="SSH user on victim (default: root)")
    parser.add_argument("--victim-ssh-port", type=int, default=22,
        help="SSH port on victim (default: 22)")
    parser.add_argument("--victim-key", type=str, default=None,
        help="Path to SSH private key for victim (default: system default)")
    parser.add_argument("--victim-export", type=str, default=None,
        help="Save full event export from victim /api/export to this file")
    args = parser.parse_args()

    ssh_kwargs = dict(
        reset_victim=args.reset_victim,
        unblock_victim=args.unblock_victim,
        victim_user=args.victim_user,
        victim_ssh_port=args.victim_ssh_port,
        victim_ssh_key=args.victim_key,
    )

    print()
    print(f"  {'='*44}")
    print(f"  AnomalyNet Attack Simulator")
    print(f"  Target         : {args.target}")
    print(f"  Mode           : {args.mode}")
    print(f"  Reset victim   : {'YES (SSH restart)' if args.reset_victim else 'no'}")
    print(f"  Unblock victim : {'YES (auto_block mode)' if args.unblock_victim else 'no'}")
    print(f"  Time           : {datetime.now().strftime('%H:%M:%S')}")
    print(f"  {'='*44}")
    print()

    if args.mode == "check":
        stats = fetch_stats(args.target, args.api_port)
        print_stats(stats, "CURRENT")
        if args.save and stats:
            save_report(args.save, [{"phase": "check", "timestamp": datetime.now().isoformat(), "stats": stats}])

    elif args.mode == "normal":
        duration = args.duration or 30
        attack_normal(args.target, duration, args.api_port)
        time.sleep(2)
        stats = fetch_stats(args.target, args.api_port)
        print_stats(stats, "after normal traffic")
        if args.save and stats:
            save_report(args.save, [{"phase": "normal", "timestamp": datetime.now().isoformat(), "stats": stats}])

    elif args.mode in ("quick", "all"):
        duration = args.duration or (10 if args.mode == "quick" else 30)
        run_all(args.target, duration, args.api_port, save=args.save, **ssh_kwargs)

    elif args.mode == "full":
        duration = args.duration or 30
        run_full(args.target, duration, args.api_port, save=args.save, **ssh_kwargs)

    else:
        duration = args.duration or 15
        if args.unblock_victim:
            unblock_victim_ips(args.target, args.api_port, args.victim_user,
                               args.victim_ssh_port, args.victim_key)
        if args.reset_victim:
            reset_victim_service(args.target, args.victim_user,
                                 args.victim_ssh_port, args.victim_key)
        run_single(args.mode, args.target, duration)
        time.sleep(2)
        stats = fetch_stats(args.target, args.api_port)
        print_stats(stats, f"after {args.mode}")
        if args.save and stats:
            save_report(args.save, [{"phase": args.mode, "timestamp": datetime.now().isoformat(), "stats": stats}])

    # Fetch full victim export if requested
    if args.victim_export:
        log(f"Fetching full event export from victim...")
        export = fetch_victim_export(args.target, args.api_port)
        if export:
            with open(args.victim_export, "w", encoding="utf-8") as f:
                json.dump(export, f, ensure_ascii=False, indent=2)
            ok(f"Victim export saved → {args.victim_export}")
        else:
            warn("Could not fetch victim export")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{NC}")
        sys.exit(0)
