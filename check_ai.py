"""
Run this from your Orion-Hybrid-IDS folder:
    python check_ai.py
It will tell you exactly what is wrong with your AI setup.
"""
import os, sys

print("\n" + "="*55)
print("  ORION AI ANALYST — DIAGNOSTIC CHECK")
print("="*55)

# 1. dotenv
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("[OK] python-dotenv loaded")
except ImportError:
    print("[FAIL] python-dotenv not installed — run: pip install python-dotenv")
    sys.exit(1)

# 2. anthropic SDK
try:
    import anthropic
    print(f"[OK] anthropic SDK installed (v{anthropic.__version__})")
except ImportError:
    print("[FAIL] anthropic not installed — run: pip install anthropic")
    sys.exit(1)

# 3. API key present
key = os.getenv("ANTHROPIC_API_KEY", "").strip()
if not key:
    print("[FAIL] ANTHROPIC_API_KEY is not set in your .env file")
    print("       Add this line to Orion-Hybrid-IDS/.env :")
    print("       ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxx")
    sys.exit(1)

if key == "your_anthropic_api_key_here":
    print("[FAIL] ANTHROPIC_API_KEY is still the placeholder value")
    print("       Get your real key → https://console.anthropic.com/settings/keys")
    sys.exit(1)

if not key.startswith("sk-ant-"):
    print(f"[WARN] Key starts with '{key[:12]}...' — expected 'sk-ant-...'")
else:
    print(f"[OK] Key found: {key[:16]}...{key[-4:]}")

# 4. Live API test
print("\n--- Testing API connection ---")
client = anthropic.Anthropic(api_key=key)

for model in ("claude-haiku-4-5-20251001", "claude-3-haiku-20240307"):
    print(f"Trying model: {model}  ...", end=" ", flush=True)
    try:
        r = client.messages.create(
            model=model,
            max_tokens=20,
            messages=[{"role": "user", "content": "Say OK"}],
        )
        print(f"SUCCESS → '{r.content[0].text.strip()}'")
        break
    except anthropic.AuthenticationError as e:
        print(f"FAIL — Invalid API key: {e}")
        print("\n  Fix: Regenerate your key at https://console.anthropic.com/settings/keys")
        sys.exit(1)
    except anthropic.RateLimitError as e:
        print(f"RATE LIMITED — but key is valid. {e}")
        break
    except anthropic.BadRequestError as e:
        print(f"BAD REQUEST (400) — {e}")
    except Exception as e:
        print(f"ERROR — {type(e).__name__}: {e}")

print("\n" + "="*55 + "\n")