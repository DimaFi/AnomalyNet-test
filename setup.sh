#!/usr/bin/env bash
# ============================================================
#  AnomalyNet Attack Simulator — Setup Script
#  Run this on the ATTACKER VPS (not the victim)
#
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/DimaFi/AnomalyNet-test/main/setup.sh | bash
#  or:
#    chmod +x setup.sh && ./setup.sh
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}>  $*${NC}"; }
ok()  { echo -e "${GREEN}[OK] $*${NC}"; }

log "Installing attack tools..."

apt-get update -qq
apt-get install -y -qq \
    hping3 \
    nmap \
    python3 python3-pip \
    curl wget \
    net-tools 2>/dev/null || true

pip3 install requests --quiet 2>/dev/null || true

ok "Setup complete. Now run:"
echo ""
echo "  python3 attack.py --target <VICTIM_IP> --mode quick"
echo ""
echo "  Modes:"
echo "    quick      — all attacks, 10 seconds each"
echo "    syn        — SYN flood only"
echo "    udp        — UDP flood only"
echo "    icmp       — ICMP flood only"
echo "    scan       — port scan (nmap)"
echo "    http       — HTTP flood"
echo "    all        — all attacks, 30 seconds each (full test)"
echo ""
