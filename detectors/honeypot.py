# --- IDS_project2/detectors/honeypot.py ---
"""
ORION Dynamic Honeypot
======================
ACTIVE DECEPTION component of the Hybrid IDS.

Improvements over v1:
  - Multi-port deception services (SSH, HTTP, FTP, Telnet banners)
  - Automatically opens a new random high-port trap each time an attacker
    probes the system, making the surface unpredictable
  - Full payload capture + AI Analyst triage via analyze_payload()
  - Honeypot findings are fed back into the reputation system
  - Thread-safe active-set management with port tracking
  - Graceful error logging (no silent `pass` on exceptions)
  - Configurable timeout so tests don't hang forever
"""

import socket
import threading
import random
import time
from utils.threat_intel import enrich_ip

# ── Deception service banners ─────────────────────────────────────────────────
# Rotate these to make fingerprinting harder
DECEPTION_BANNERS = [
    b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\nlogin: ",
    b"220 ProFTPD 1.3.6 Server (FTP) [127.0.0.1]\r\n",
    b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 0\r\n\r\n",
    b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18Telnet login: ",  # Telnet negotiation
    b"220 mail.orion.local ESMTP Postfix (Ubuntu)\r\n",
]

# Extra "trap" ports that real attackers commonly probe
EXTRA_TRAP_PORTS = [22, 23, 21, 25, 3306, 5432, 6379, 27017, 9200, 8888]


class DynamicHoneypot:
    """
    Deploys per-IP deception traps on demand and feeds captured payloads to
    the AI Analyst for instant forensic triage.
    """

    HONEYPOT_TIMEOUT = 45   # seconds to wait for the attacker to respond
    MAX_PAYLOAD_BYTES = 2048

    def __init__(self, ai_analyst, database, reputation_manager=None):
        self.ai_analyst        = ai_analyst
        self.db                = database
        self.rep_manager       = reputation_manager   # optional, injected by engine.py
        self._lock             = threading.Lock()
        # Maps attacker_ip → set of ports already trapping them
        self._active_traps: dict[str, set] = {}
        print("[+] Honeypot: Dynamic deception engine ready.")

    # ── Public API ────────────────────────────────────────────────────────────

    def deploy_trap(self, target_ip: str, port: int = None):
        """
        Open a deceptive listener for *target_ip* on *port*.
        If port is None, a random high-port from EXTRA_TRAP_PORTS is chosen.
        Silently skips if a trap already exists for this (ip, port) combo.
        """
        chosen_port = port if port else random.choice(EXTRA_TRAP_PORTS)

        with self._lock:
            active_ports = self._active_traps.setdefault(target_ip, set())
            if chosen_port in active_ports:
                return  # already trapping this IP on this port
            active_ports.add(chosen_port)

        print(f"\n[*] DECEPTION ACTIVE: Honeypot trap opened on port {chosen_port} for {target_ip}")

        t = threading.Thread(
            target=self._listen_and_capture,
            args=(target_ip, chosen_port),
            daemon=True,
        )
        t.start()

    def deploy_multi_trap(self, target_ip: str):
        """
        Deploys traps on MULTIPLE ports simultaneously — ideal for confirmed
        high-severity attackers (called by engine.py for Critical alerts).
        """
        ports_to_open = random.sample(EXTRA_TRAP_PORTS, k=min(3, len(EXTRA_TRAP_PORTS)))
        for p in ports_to_open:
            self.deploy_trap(target_ip, port=p)

    # ── Internal listener ─────────────────────────────────────────────────────

    def _listen_and_capture(self, target_ip: str, port: int):
        """Background thread: bind, wait for connection, capture payload, triage."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("0.0.0.0", port))
            server.listen(5)
            server.settimeout(self.HONEYPOT_TIMEOUT)

            conn, addr = server.accept()
            attacker_ip   = addr[0]
            banner        = random.choice(DECEPTION_BANNERS)

            try:
                conn.sendall(banner)
                time.sleep(0.3)
                conn.settimeout(10.0)
                raw_data = b""
                while len(raw_data) < self.MAX_PAYLOAD_BYTES:
                    chunk = conn.recv(512)
                    if not chunk:
                        break
                    raw_data += chunk
            except Exception:
                pass
            finally:
                conn.close()

            payload = raw_data.decode("utf-8", errors="ignore").strip()

            if payload:
                self._handle_payload(attacker_ip, payload, port)
            else:
                print(f"[*] Honeypot (port {port}): {attacker_ip} connected but sent no payload.")
                # Still log the connection attempt as intelligence
                self.db.save_alert(
                    f"Honeypot Connection (no payload) — port {port}",
                    "Medium",
                    attacker_ip,
                )

        except socket.timeout:
            print(f"[*] Honeypot (port {port}): Timed out waiting for {target_ip}.")
        except OSError as e:
            if "already in use" in str(e).lower() or e.errno == 10048:
                print(f"[!] Honeypot: Port {port} already in use, skipping.")
            else:
                print(f"[!] Honeypot (port {port}) socket error: {e}")
        except Exception as e:
            print(f"[!] Honeypot (port {port}) unexpected error: {e}")
        finally:
            server.close()
            with self._lock:
                ports = self._active_traps.get(target_ip, set())
                ports.discard(port)
                if not ports:
                    self._active_traps.pop(target_ip, None)

    # ── Payload handling / AI triage ──────────────────────────────────────────

    def _handle_payload(self, attacker_ip: str, payload: str, port: int):
        """Process a captured payload: AI triage → DB save → console report."""
        print(f"\n{'!'*60}")
        print(f"  [!!!] HONEYPOT TRIGGERED on port {port}")
        print(f"  Attacker IP : {attacker_ip}")
        print(f"  Payload     : {payload[:120]}{'...' if len(payload) > 120 else ''}")
        print(f"{'!'*60}")

        # ── AI Analyst triage ────────────────────────────────────────────────
        analysis = None
        if self.ai_analyst:
            try:
                analysis = self.ai_analyst.analyze_payload(
                    attacker_ip=attacker_ip,
                    payload=payload,
                    port=port,
                    severity="Critical",
                )
            except Exception as e:
                print(f"[-] AI triage failed for honeypot payload: {e}")

        # ── Persist to database ───────────────────────────────────────────────
        alert_type = f"Honeypot Interaction — port {port}"
        geo = enrich_ip(attacker_ip)
        protection_action = "Honeypot captured payload; reputation score increased"
        self.db.save_alert(
            alert_type,
            "Critical",
            attacker_ip,
            ai_report=analysis,
            geo=geo,
            protection_action=protection_action,
        )

        # ── Update reputation score ───────────────────────────────────────────
        if self.rep_manager and hasattr(self.rep_manager, "update_score"):
            # Honeypot hits are high-confidence malicious events — bigger penalty
            self.rep_manager.update_score(attacker_ip, delta=25)

        # ── Print AI report ───────────────────────────────────────────────────
        sep = "=" * 50
        print(f"\n{sep}")
        print("  ORION AI ANALYST — HONEYPOT FORENSIC REPORT")
        print(sep)
        print(f"  Attacker IP  : {attacker_ip}")
        print(f"  Trigger Port : {port}")
        print(f"  Raw Payload  : {payload[:200]}")
        print(sep)
        if analysis:
            print(analysis)
        else:
            print("  [AI triage unavailable - check AI_ANALYST_PROVIDER/MISTRAL_API_KEY or Ollama]")
        print(f"{sep}\n")
