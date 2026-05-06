#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  ORION IDS — Kali Linux Deployment Script
# ═══════════════════════════════════════════════════════════════════════════
#  Usage:
#    chmod +x setup_kali.sh
#    sudo ./setup_kali.sh
#
#  What this script does:
#    1. Installs system dependencies (libpcap, tcpdump, python3-venv)
#    2. Creates a Python virtual environment
#    3. Installs all Python packages from requirements.txt
#    4. Detects network interface and configures .env
#    5. Trains the ML model (if model.pkl is missing)
#    6. Prints next-steps for launching ORION
# ═══════════════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║       ORION IDS — Kali Linux Setup Script               ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check root ────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root (sudo ./setup_kali.sh)${NC}"
    exit 1
fi

# ── Step 1: System dependencies ───────────────────────────────────────────
echo -e "${YELLOW}[1/6] Installing system dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv libpcap-dev tcpdump net-tools 2>/dev/null
echo -e "${GREEN}[+] System dependencies installed.${NC}"

# ── Step 2: Create virtual environment ────────────────────────────────────
echo -e "${YELLOW}[2/6] Setting up Python virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment created at ./venv${NC}"
else
    echo -e "${GREEN}[+] Virtual environment already exists.${NC}"
fi

# Activate venv
source venv/bin/activate
echo -e "${GREEN}[+] Activated venv: $(which python3)${NC}"

# ── Step 3: Install Python packages ──────────────────────────────────────
echo -e "${YELLOW}[3/6] Installing Python requirements...${NC}"
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "${GREEN}[+] All Python packages installed.${NC}"

# ── Step 4: Detect network interface and configure .env ──────────────────
echo -e "${YELLOW}[4/6] Detecting network interface...${NC}"

# Find the default route interface
DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
if [ -z "$DEFAULT_IFACE" ]; then
    # Fallback: find first non-loopback interface that is UP
    DEFAULT_IFACE=$(ip -o link show up | grep -v 'lo:' | awk -F': ' '{print $2}' | head -1)
fi

# Detect LAN IP
KALI_IP=$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [ -z "$KALI_IP" ]; then
    KALI_IP=$(hostname -I | awk '{print $1}')
fi

echo -e "${GREEN}[+] Detected interface: ${CYAN}$DEFAULT_IFACE${NC}"
echo -e "${GREEN}[+] Detected Kali IP:   ${CYAN}$KALI_IP${NC}"

# Update .env with detected values
cat > .env << ENVEOF
# ── AI Analyst ──────────────────────────────────────────────
# Option 1: Ollama (local, free — run 'ollama serve' + 'ollama pull mistral')
AI_ANALYST_PROVIDER=ollama
OLLAMA_MODEL=mistral
OLLAMA_BASE_URL=http://localhost:11434

# Option 2: Gemini (cloud — uncomment and add your API key)
# AI_ANALYST_PROVIDER=gemini
# GEMINI_API_KEY=YOUR_KEY_HERE

# ── Network Capture ──────────────────────────────────────────
# Auto-detected by setup_kali.sh on $(date '+%Y-%m-%d %H:%M')
ORION_CAPTURE_IFACE=${DEFAULT_IFACE}

# Kali LAN IP (auto-detected) — Metasploitable 2 attacks will target this
ORION_TARGET_IP=${KALI_IP}

# ── Alert Settings ───────────────────────────────────────────
ORION_ALERT_SUPPRESS_SECONDS=10
ORION_GEOLOOKUP_ENABLED=false
ENVEOF

echo -e "${GREEN}[+] .env configured with interface=$DEFAULT_IFACE, target_ip=$KALI_IP${NC}"

# ── Step 5: Train ML model (if needed) ──────────────────────────────────
echo -e "${YELLOW}[5/6] Checking ML model...${NC}"
if [ ! -f "model.pkl" ]; then
    echo -e "${YELLOW}    Training ML model (this may take 30-90 seconds)...${NC}"
    python3 train_model.py
    echo -e "${GREEN}[+] ML model trained successfully.${NC}"
else
    echo -e "${GREEN}[+] model.pkl already exists ($(du -h model.pkl | cut -f1)).${NC}"
fi

# ── Step 6: Summary ─────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ ORION IDS is ready for deployment on Kali Linux!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${YELLOW}Kali IP Address :${NC} $KALI_IP"
echo -e "  ${YELLOW}Capture Interface:${NC} $DEFAULT_IFACE"
echo -e "  ${YELLOW}Python (venv)    :${NC} $(which python3)"
echo ""
echo -e "  ${CYAN}── HOW TO RUN ──────────────────────────────────────────${NC}"
echo -e "  ${GREEN}cd $SCRIPT_DIR${NC}"
echo -e "  ${GREEN}source venv/bin/activate${NC}"
echo -e "  ${GREEN}sudo -E venv/bin/python3 main.py${NC}"
echo ""
echo -e "  ${CYAN}── THEN IN THE ORION MENU ──────────────────────────────${NC}"
echo -e "  Press ${GREEN}4${NC} for Full Deployment (API + Engine + Simulator)"
echo -e "  Or press ${GREEN}1${NC}, then ${GREEN}2${NC} to start API and Engine separately."
echo ""
echo -e "  ${CYAN}── ATTACK FROM METASPLOITABLE 2 ────────────────────────${NC}"
echo -e "  From the Metasploit terminal, target ${YELLOW}$KALI_IP${NC}:"
echo -e "  ${GREEN}nmap -sS -sV $KALI_IP${NC}"
echo -e "  ${GREEN}nmap -A -T4 $KALI_IP${NC}"
echo -e "  ${GREEN}hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$KALI_IP${NC}"
echo -e "  ${GREEN}nikto -h http://$KALI_IP:8000${NC}"
echo ""
echo -e "  ${CYAN}── DASHBOARD ──────────────────────────────────────────${NC}"
echo -e "  Open in browser: ${GREEN}http://$KALI_IP:8000${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
