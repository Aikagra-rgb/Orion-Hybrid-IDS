# --- IDS_project2/engine.py ---
"""
ORION Hybrid IDS Engine
=======================
Fuses NIDS (network packet inspection) and HIDS (host file integrity) into a
single detection pipeline, with an AI Analyst performing async triage on every
confirmed alert.

Detection layers (in order):
  1. Signature Detector  — Known-bad pattern matching (fastest)
  2. ML Anomaly Detector — Statistical anomaly + behavioral rate/port tracker
  3. FIM (HIDS loop)     — SHA-256 file-integrity checks (background thread)
  4. Honeypot            — Active deception traps (spun up on confirmed threats)
  5. AI Analyst          — Async Gemini triage for every alert

Simulator integration:
  simulate_attacks.py sends packets to the machine's LAN IP (auto-detected).
  On Windows, Scapy's loopback driver (NPF_Loopback) is required to sniff
  loopback traffic; alternatively set ORION_TARGET_IP + ORION_CAPTURE_IFACE.
"""

import sys
import os
import threading
import time
from scapy.all import sniff, IP

# ── Core Utility Modules ──────────────────────────────────────────────────────
from utils.database   import DatabaseManager
from utils.reputation import ReputationManager

# ── Detector Modules ──────────────────────────────────────────────────────────
from detectors.ai_analyst  import AIAnalyst
from detectors.anomaly     import AnomalyDetector
from detectors.honeypot    import DynamicHoneypot
from detectors.fim         import FileIntegrityMonitor
from detectors.signatures  import SignatureDetector

# ═════════════════════════════════════════════════════════════════════════════
#  BANNER
# ═════════════════════════════════════════════════════════════════════════════

def print_banner():
    banner = r"""
======================================================================
  ORION: Operational Risk Identification and Observation Network
  Hybrid NIDS + HIDS | AI-Powered Triage
======================================================================
    """
    print(banner)


# ═════════════════════════════════════════════════════════════════════════════
#  MODULE INITIALISATION
# ═════════════════════════════════════════════════════════════════════════════

print_banner()
print("[*] Initializing ORION Core Modules...")

db           = DatabaseManager()
rep_manager  = ReputationManager(db)
ai_analyst   = AIAnalyst()

print("[*] Initializing Hybrid Detector Modules...")

signature_detector = SignatureDetector(signatures_file="signatures.json")
anomaly_detector   = AnomalyDetector(model_path="model.pkl")
fim                = FileIntegrityMonitor()

# Pass rep_manager so honeypot can update IP reputation scores
honeypot = DynamicHoneypot(ai_analyst, db, reputation_manager=rep_manager)

# ═════════════════════════════════════════════════════════════════════════════
#  HIDS BACKGROUND LOOP (File Integrity Monitor)
# ═════════════════════════════════════════════════════════════════════════════

def fim_monitor_loop():
    """Runs continuously in the background, scanning monitored files every 15 s."""
    while True:
        time.sleep(15)
        alerts = fim.check_files()
        for alert in alerts:
            a_type    = alert["type"]
            a_sev     = alert["severity"]
            filepath  = alert.get("filepath", "unknown")
            change    = alert.get("change_type", a_type)

            print(f"\n[!!!] HIDS ALERT [{a_sev}]: {a_type}")
            alert_id = db.save_alert(a_type, a_sev, "localhost")

            # Async AI triage for HIDS alerts
            def _hids_triage(aid, fp, ct):
                try:
                    report = ai_analyst.analyze_hids(fp, ct)
                    if report:
                        db.update_ai_report(aid, report)
                        print(f"[+] HIDS AI Triage completed for Alert #{aid}")
                        print(f"    {report[:200]}...")
                except Exception as e:
                    print(f"[-] HIDS AI triage failed: {e}")

            threading.Thread(
                target=_hids_triage,
                args=(alert_id, filepath, change),
                daemon=True,
            ).start()


threading.Thread(target=fim_monitor_loop, daemon=True).start()
print("[+] HIDS: File Integrity Monitor running in background (15s cycle).")

# ═════════════════════════════════════════════════════════════════════════════
#  NIDS PACKET PROCESSOR
# ═════════════════════════════════════════════════════════════════════════════

def process_packet(packet):
    """
    Core NIDS callback — every sniffed IP packet flows through here.

    Detection pipeline:
      Phase 1 → Signature check  (payload patterns, SYN scan, large UDP)
      Phase 2 → ML Anomaly check (only runs if Phase 1 found nothing)
      Phase 3 → Alert orchestration (reputation, DB, AI triage, honeypot)
    """
    if not packet.haslayer(IP):
        return

    source_ip  = packet[IP].src
    threat_type = None
    severity    = "Low"
    confidence  = None
    features    = None

    # ── Phase 1: Signature Detection ──────────────────────────────────────────
    sig_alert = signature_detector.check(packet)
    if sig_alert:
        threat_type = sig_alert["type"]
        severity    = sig_alert["severity"]
        # Print immediately so simulator output is visible in real-time
        print(f"[SIG]  [{severity:8s}] {source_ip:15s} → {threat_type}")

    # ── Phase 2: ML / Behavioral Anomaly Detection ────────────────────────────
    if not threat_type:
        ml_alert = anomaly_detector.check(packet)
        if ml_alert:
            threat_type = ml_alert["type"]
            severity    = ml_alert["severity"]
            confidence  = ml_alert.get("confidence")
            features    = ml_alert.get("features")

            conf_str = f" [{confidence:.1%}]" if confidence is not None else ""
            print(f"[ML]   [{severity:8s}] {source_ip:15s} → {threat_type}{conf_str}")

    # ── Phase 3: Alert Orchestration ──────────────────────────────────────────
    if not threat_type:
        return  # Clean packet — nothing to do

    # 3a. Update reputation score (small incremental penalty)
    if hasattr(rep_manager, "update_score"):
        rep_manager.update_score(source_ip)

    # 3b. Save alert to DB, capture the row ID for AI report attachment
    alert_id = db.save_alert(threat_type, severity, source_ip)

    # 3c. Async AI triage ──────────────────────────────────────────────────────
    def _background_ai_triage(a_id, t_type, s_ip, sev, conf, feats):
        try:
            if feats and "ML Anomaly" in t_type:
                # Richer, anomaly-specific analysis
                report = ai_analyst.analyze_anomaly(s_ip, feats, conf or 0.0)
            else:
                report = ai_analyst.analyze(
                    alert_type   = t_type,
                    attacker_ip  = s_ip,
                    severity     = sev,
                    confidence   = conf,
                )

            if report:
                db.update_ai_report(a_id, report)
                print(f"[AI]   Triage completed for Alert #{a_id} ({t_type})")
        except Exception as e:
            print(f"[-]    AI triage failed for Alert #{a_id}: {e}")

    threading.Thread(
        target=_background_ai_triage,
        args=(alert_id, threat_type, source_ip, severity, confidence, features),
        daemon=True,
    ).start()

    # 3d. Active deception — deploy honeypot based on severity ─────────────────
    if severity == "Critical":
        # Critical alerts → multi-port trap for maximum intelligence gathering
        honeypot.deploy_multi_trap(source_ip)
    elif severity in ("High", "Medium"):
        honeypot.deploy_trap(source_ip, port=8080)


# ═════════════════════════════════════════════════════════════════════════════
#  SNIFFER ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main():
    """
    Configure and start the Scapy sniffer.

    Interface selection (in priority order):
      1. ORION_CAPTURE_IFACE environment variable (explicit override)
      2. Scapy's default interface

    On Windows, set ORION_CAPTURE_IFACE to "\\Device\\NPF_Loopback" to capture
    loopback packets generated by simulate_attacks.py, or set ORION_TARGET_IP
    to your LAN IP so the simulator sends packets over a real adapter.
    """
    try:
        sniff_kwargs: dict = {
            "prn"   : process_packet,
            "store" : False,
            "filter": "ip",
        }

        capture_iface = os.getenv("ORION_CAPTURE_IFACE")
        if capture_iface:
            sniff_kwargs["iface"] = capture_iface
            print(f"\n[i] Capture interface (env): {capture_iface}")
        else:
            print("\n[i] Using Scapy default interface.")
            print("[i] TIP: Set ORION_CAPTURE_IFACE=\\Device\\NPF_Loopback to capture")
            print("         loopback traffic from simulate_attacks.py on Windows.")
            print("[i] TIP: Or set ORION_TARGET_IP=<your LAN IP> in simulate_attacks.py")
            print("         so packets travel over the real network adapter.\n")

        print("[+] ===========================================================")
        print("[+]  ORION Hybrid Engine is LIVE — sniffing traffic...")
        print("[+]  Signature rules | ML anomaly | HIDS | AI Analyst | Honeypot")
        print("[+] ===========================================================\n")

        sniff(**sniff_kwargs)

    except KeyboardInterrupt:
        print("\n[-] ORION Sniffer stopped gracefully. Goodbye.")
        sys.exit(0)
    except Exception as e:
        import traceback
        print(f"\n[!] Fatal error in sniffer: {e}")
        traceback.print_exc()
        input("\n[!] CRASHED — Press Enter to close...")


if __name__ == "__main__":
    main()
