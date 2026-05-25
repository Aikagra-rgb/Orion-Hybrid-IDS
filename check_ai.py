"""
Run this from your Orion-Hybrid-IDS folder:
    python check_ai.py

This checks the AI Analyst provider configuration without exposing API keys.
Set AI_ANALYST_LIVE_TEST=true if you want it to make one real LLM request.
"""

import os
import sys


print("\n" + "=" * 60)
print("  ORION AI ANALYST - DIAGNOSTIC CHECK")
print("=" * 60)


try:
    from dotenv import load_dotenv

    load_dotenv()
    print("[OK] python-dotenv loaded")
except ImportError:
    print("[FAIL] python-dotenv not installed - run: pip install python-dotenv")
    sys.exit(1)


try:
    import httpx

    print(f"[OK] httpx installed (v{httpx.__version__})")
except ImportError:
    print("[FAIL] httpx not installed - run: pip install httpx")
    sys.exit(1)


provider = os.getenv("AI_ANALYST_PROVIDER", "auto").strip().lower()
ollama_model = os.getenv("OLLAMA_MODEL", "mistral").strip()
ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").strip()

print("\n--- Configuration ---")
print(f"AI_ANALYST_PROVIDER: {provider}")
print(f"OLLAMA_MODEL       : {ollama_model}")
print(f"OLLAMA_BASE_URL    : {ollama_base_url}")


if provider == "ollama" and not ollama_model:
    print("[WARN] Ollama selected but OLLAMA_MODEL is not set.")

if provider == "auto":
    if os.getenv("OLLAMA_MODEL") or os.getenv("OLLAMA_BASE_URL"):
        print("[OK] auto mode will use local Ollama.")
    else:
        print("[OK] auto mode will use the built-in offline fallback.")


print("\n--- Import test ---")
try:
    from detectors.ai_analyst import AIAnalyst

    analyst = AIAnalyst()
    print(f"[OK] AIAnalyst imported; active provider: {analyst._active_provider}")
except Exception as e:
    print(f"[FAIL] AIAnalyst import/init failed: {type(e).__name__}: {e}")
    sys.exit(1)


if os.getenv("AI_ANALYST_LIVE_TEST", "").strip().lower() in {"1", "true", "yes", "on"}:
    print("\n--- Live analysis test ---")
    report = analyst.analyze(
        alert_type="Test Port Scan",
        attacker_ip="127.0.0.1",
        severity="Low",
        extra_context="Diagnostic run only.",
    )
    print(report)
else:
    print("\n--- Live analysis test skipped ---")
    print("Set AI_ANALYST_LIVE_TEST=true to make one real provider request.")


print("\n" + "=" * 60 + "\n")
