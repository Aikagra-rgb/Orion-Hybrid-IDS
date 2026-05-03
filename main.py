# --- IDS_project2/main.py ---
"""
ORION Command Center — Interactive CLI
=======================================
Single entry-point to launch and manage all ORION subsystems:
  • API / Dashboard server (uvicorn)
  • Hybrid IDS Engine (NIDS + HIDS)
  • Attack Simulator
  • ML Model Trainer

Press Ctrl+C at any time to return to the menu or exit.
"""

import subprocess
import sys
import time
import os
import atexit

# ─── Process registry ────────────────────────────────────────────────────────
_procs: dict[str, subprocess.Popen | None] = {
    "api"      : None,
    "engine"   : None,
    "simulator": None,
}


# ═════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def _is_alive(key: str) -> bool:
    p = _procs.get(key)
    return p is not None and p.poll() is None


def _status_badge(key: str) -> str:
    return "[ \033[92mONLINE\033[0m  ]" if _is_alive(key) else "[ \033[91mOFFLINE\033[0m ]"


def _new_console_flags() -> dict:
    """Return Popen kwargs that open a new visible terminal on Windows."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_CONSOLE}
    return {}


# ═════════════════════════════════════════════════════════════════════════════
#  SUBSYSTEM LAUNCHERS
# ═════════════════════════════════════════════════════════════════════════════

def start_api():
    if _is_alive("api"):
        print("  [-] API is already running.")
        return
    print("  [*] Starting ORION API & Dashboard Server...")
    _procs["api"] = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    time.sleep(1.5)
    if _is_alive("api"):
        print("  [+] API Online → http://127.0.0.1:8000")
    else:
        print("  [!] API failed to start. Check api.py and uvicorn installation.")


def start_engine():
    if _is_alive("engine"):
        print("  [-] Engine is already running.")
        return
    print("  [*] Booting Hybrid IDS Engine (NIDS + HIDS + AI Analyst)...")
    _procs["engine"] = subprocess.Popen(
        [sys.executable, "engine.py"],
        **_new_console_flags(),
    )
    time.sleep(0.5)
    if _is_alive("engine"):
        print("  [+] Engine Online! (Running in a separate window — watch it for live alerts)")
    else:
        print("  [!] Engine failed to start. Check engine.py for import errors.")


def start_simulator():
    if _is_alive("simulator"):
        print("  [-] Simulator is already running.")
        return
    print("  [*] Launching Attack Simulation Suite...")
    _procs["simulator"] = subprocess.Popen(
        [sys.executable, "simulate_attacks.py"],
        **_new_console_flags(),
    )
    time.sleep(0.5)
    if _is_alive("simulator"):
        print("  [+] Simulator Online! (Running in a separate window)")
    else:
        print("  [!] Simulator failed to start.")


def train_model():
    print("  [*] Starting ML Model Training (this may take 30-90 seconds)...")
    print("  [*] Output will appear in a new terminal window.\n")
    proc = subprocess.Popen(
        [sys.executable, "train_model.py"],
        **_new_console_flags(),
    )
    proc.wait()
    print("  [+] Training complete. Restart the engine to load the new model.")


def stop_all():
    print("\n  [!] Initiating ORION Global Shutdown...")
    for name, proc in _procs.items():
        if proc is not None and proc.poll() is None:
            proc.terminate()
            print(f"  [-] Terminated {name.upper()}.")
    print("  [+] All systems offline. Goodbye.\n")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER & MENU
# ═════════════════════════════════════════════════════════════════════════════

def _print_banner():
    _clear()
    print(r"""
     ██████╗ ██████╗ ██╗ ██████╗ ███╗   ██╗    ██╗██████╗ ███████╗
    ██╔═══██╗██╔══██╗██║██╔═══██╗████╗  ██║    ██║██╔══██╗██╔════╝
    ██║   ██║██████╔╝██║██║   ██║██╔██╗ ██║    ██║██║  ██║███████╗
    ██║   ██║██╔══██╗██║██║   ██║██║╚██╗██║    ██║██║  ██║╚════██║
    ╚██████╔╝██║  ██║██║╚██████╔╝██║ ╚████║    ██║██████╔╝███████║
     ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝╚═════╝ ╚══════╝
         Hybrid Intrusion Detection System — Command Center v2.0
    """)


def _print_menu():
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │  SYSTEM STATUS                                          │")
    print(f"  │  API / Dashboard  :  {_status_badge('api')}                        │")
    print(f"  │  Hybrid Engine    :  {_status_badge('engine')}                        │")
    print(f"  │  Attack Simulator :  {_status_badge('simulator')}                        │")
    print("  ├─────────────────────────────────────────────────────────┤")
    print("  │  COMMANDS                                               │")
    print("  │   1  →  Start API & Dashboard Server                   │")
    print("  │   2  →  Start Hybrid IDS Engine                        │")
    print("  │   3  →  Launch Attack Simulator                        │")
    print("  │   4  →  Full Deployment (API + Engine + Simulator)     │")
    print("  │   5  →  Train / Retrain ML Model                       │")
    print("  │   6  →  Stop All & Exit                                │")
    print("  └─────────────────────────────────────────────────────────┘")
    print()


def _tip():
    tips = [
        "TIP: Watch the engine window for real-time [SIG] / [ML] / [AI] alerts.",
        "TIP: Set ORION_CAPTURE_IFACE=\\Device\\NPF_Loopback to capture loopback on Windows.",
        "TIP: Set ORION_TARGET_IP=<your LAN IP> so the simulator sends over the real NIC.",
        "TIP: Run option 5 to retrain the ML model whenever you add new signatures.",
        "TIP: Dashboard at http://127.0.0.1:8000 — start option 1 first.",
    ]
    import random
    print(f"  \033[33m{random.choice(tips)}\033[0m\n")


# ═════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE LOOP
# ═════════════════════════════════════════════════════════════════════════════

def interactive_menu():
    atexit.register(stop_all)

    while True:
        _print_banner()
        _print_menu()
        _tip()

        try:
            choice = input("  ORION> ").strip()
        except (KeyboardInterrupt, EOFError):
            stop_all()
            break

        print()

        if choice == "1":
            start_api()
        elif choice == "2":
            start_engine()
        elif choice == "3":
            start_simulator()
        elif choice == "4":
            start_api()
            start_engine()
            start_simulator()
        elif choice == "5":
            train_model()
        elif choice == "6":
            stop_all()
            break
        else:
            print("  [!] Invalid option. Enter 1–6.")

        input("\n  Press Enter to return to menu...")


# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        interactive_menu()
    except KeyboardInterrupt:
        sys.exit(0)