# --- IDS_project2/detectors/ai_analyst.py ---
"""
ORION AI Analyst — Powered by Anthropic Claude
"""

import anthropic
import os
import time
import threading
from dotenv import load_dotenv

SEVERITY_CONTEXT = {
    "Critical": "CRITICAL severity — treat as active compromise. Immediate escalation required.",
    "High":     "HIGH severity — likely active exploitation attempt. Investigate within minutes.",
    "Medium":   "MEDIUM severity — suspicious activity. Review within the hour.",
    "Low":      "LOW severity — reconnaissance or noise. Log and monitor.",
}

MITRE_HINTS = {
    "SYN":         "T1046 – Network Service Scanning",
    "Scan":        "T1046 – Network Service Scanning",
    "Brute Force": "T1110 – Brute Force",
    "SQL":         "T1190 – Exploit Public-Facing Application",
    "XSS":         "T1059.007 – JavaScript scripting",
    "RFI":         "T1105 – Ingress Tool Transfer",
    "LFI":         "T1083 – File and Directory Discovery",
    "Shellshock":  "T1203 – Exploitation for Client Execution",
    "Log4Shell":   "T1190 – Exploit Public-Facing Application",
    "Exfil":       "T1048 – Exfiltration Over Alternative Protocol",
    "UDP":         "T1048 – Exfiltration Over Alternative Protocol",
    "File":        "T1565 – Data Manipulation / Integrity Attack",
    "HIDS":        "T1565 – Data Manipulation (Host-based)",
    "Honeypot":    "T1071 – Application Layer Protocol (C2)",
    "ML Anomaly":  "T1499 – Endpoint Denial of Service / Unknown Zero-Day",
    "Command":     "T1059 – Command and Scripting Interpreter",
    "AWS":         "T1552.005 – Cloud Instance Metadata API",
    "SSH Key":     "T1552.004 – Private Keys",
}

MODEL_ID          = "claude-haiku-4-5-20251001"
FALLBACK_MODEL_ID = "claude-3-haiku-20240307"
DAILY_CALL_LIMIT  = 200


class AIAnalyst:
    RATE_LIMIT_SECONDS = 120
    MAX_RETRIES        = 1
    RETRY_DELAY        = 5.0

    def __init__(self):
        load_dotenv()
        self.api_key    = os.getenv("ANTHROPIC_API_KEY", "").strip()
        self.client     = None
        self._init_error = None

        self._rate_cache         = {}
        self._lock               = threading.Lock()
        self._daily_count        = 0
        self._day_start          = time.time()
        self._quota_parked_until = 0

        # ── Step 1: basic key sanity checks ──────────────────────────────────
        if not self.api_key or self.api_key in ("your_anthropic_api_key_here", ""):
            self._init_error = (
                "ANTHROPIC_API_KEY is missing or still set to the placeholder. "
                "Edit your .env file and add your real key from "
                "https://console.anthropic.com/settings/keys"
            )
            print(f"[-] AI Analyst: {self._init_error}")
            return

        if not self.api_key.startswith("sk-ant-"):
            self._init_error = (
                f"ANTHROPIC_API_KEY looks invalid (starts with '{self.api_key[:10]}...', "
                "expected 'sk-ant-...'). "
                "Get the correct key at https://console.anthropic.com/settings/keys"
            )
            print(f"[-] AI Analyst: {self._init_error}")
            return

        # ── Step 2: create client and do a live ping to verify the key ───────
        try:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            # small test call — verifies the key is accepted
            self.client.messages.create(
                model=FALLBACK_MODEL_ID,
                max_tokens=5,
                messages=[{"role": "user", "content": "hi"}],
            )
            print("[+] AI Analyst (Claude Haiku) initialized and API key verified.")

        except anthropic.AuthenticationError:
            self._init_error = (
                "ANTHROPIC_API_KEY was rejected by Anthropic (401). "
                "Regenerate your key at https://console.anthropic.com/settings/keys"
            )
            print(f"[-] AI Analyst: {self._init_error}")
            self.client = None

        except anthropic.RateLimitError:
            # Key is valid — just busy right now. Keep client alive.
            print("[+] AI Analyst: API key valid (rate-limited on startup ping — will proceed).")

        except Exception as e:
            err_str = str(e)
            print(f"[-] AI Analyst init warning: {err_str}")
            # Keep the client alive — the ping might fail for non-auth reasons
            if "invalid" in err_str.lower() or "auth" in err_str.lower():
                self.client = None
                self._init_error = err_str

    # ─────────────────────────────────────────────────────────────────────────

    def _reset_daily_counter_if_needed(self):
        if time.time() - self._day_start >= 86400:
            self._daily_count        = 0
            self._day_start          = time.time()
            self._quota_parked_until = 0

    def _is_rate_limited(self, ip: str, alert_type: str) -> bool:
        key = (ip, alert_type)
        with self._lock:
            self._reset_daily_counter_if_needed()
            if time.time() < self._quota_parked_until:
                remaining = int(self._quota_parked_until - time.time())
                print(f"[~] AI Analyst quota-parked for {remaining}s — skipping.")
                return True
            if self._daily_count >= DAILY_CALL_LIMIT:
                print(f"[~] AI Analyst daily cap ({DAILY_CALL_LIMIT}) reached.")
                return True
            last = self._rate_cache.get(key, 0)
            if time.time() - last < self.RATE_LIMIT_SECONDS:
                return True
            self._rate_cache[key] = time.time()
            self._daily_count    += 1
        return False

    def _find_mitre_hint(self, alert_type: str) -> str:
        for keyword, ttp in MITRE_HINTS.items():
            if keyword.lower() in alert_type.lower():
                return ttp
        return "Unknown – requires manual TTP mapping"

    def _call_claude(self, prompt: str) -> str:
        """
        Try MODEL_ID first, fall back to FALLBACK_MODEL_ID on 400.
        On 429 / auth errors: surface a clear human-readable message.
        """
        if not self.client:
            reason = self._init_error or "no valid ANTHROPIC_API_KEY"
            return f"AI Analyst offline: {reason}"

        for model in (MODEL_ID, FALLBACK_MODEL_ID):
            for attempt in range(self.MAX_RETRIES + 1):
                try:
                    msg = self.client.messages.create(
                        model=model,
                        max_tokens=512,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    if model != MODEL_ID:
                        print(f"[~] AI Analyst: used fallback model {model}")
                    return msg.content[0].text.strip()

                except anthropic.AuthenticationError as e:
                    detail = getattr(e, 'message', str(e))
                    self.client = None
                    self._init_error = "API key rejected (401) — check console.anthropic.com/settings/keys"
                    return f"AI Analyst offline: invalid API key. {detail}"

                except anthropic.RateLimitError as e:
                    with self._lock:
                        self._quota_parked_until = time.time() + 60
                    return f"AI Analysis skipped: rate limited — parked for 60s."

                except anthropic.BadRequestError as e:
                    detail = getattr(e, 'message', str(e))
                    print(f"[!] AI Analyst 400 on model={model}: {detail}")
                    break  # try fallback model

                except anthropic.APIStatusError as e:
                    detail = getattr(e, 'message', str(e))
                    if e.status_code == 529 and attempt < self.MAX_RETRIES:
                        time.sleep(self.RETRY_DELAY)
                        continue
                    print(f"[!] AI Analyst API error {e.status_code} on model={model}: {detail}")
                    break

                except Exception as e:
                    err = str(e)
                    if "429" in err or "quota" in err.lower() or "exhausted" in err.lower():
                        with self._lock:
                            self._quota_parked_until = time.time() + 60
                        return "AI Analysis skipped: quota exhausted — parked for 60s."
                    if attempt < self.MAX_RETRIES:
                        time.sleep(self.RETRY_DELAY)
                    else:
                        print(f"[!] AI Analyst unexpected error: {err}")
                        break

        return "AI Analysis unavailable — check engine console for the exact error."

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, alert_type: str, attacker_ip: str,
                severity: str = "Medium", confidence: float = None,
                extra_context: str = "") -> str:
        if self._is_rate_limited(attacker_ip, alert_type):
            return None
        severity_text = SEVERITY_CONTEXT.get(severity, SEVERITY_CONTEXT["Medium"])
        mitre_ttp     = self._find_mitre_hint(alert_type)
        conf_text     = f" (ML confidence: {confidence:.1%})" if confidence is not None else ""
        prompt = f"""You are an expert Tier-2 SOC Analyst using the ORION Hybrid IDS.
A new alert has been generated:

  Alert Type   : {alert_type}{conf_text}
  Source IP    : {attacker_ip}
  Severity     : {severity} — {severity_text}
  MITRE ATT&CK : {mitre_ttp}
{f"  Extra Context: {extra_context}" if extra_context else ""}

Write a concise, professional triage report in exactly 4 short bullet points:
• THREAT: What attack or behavior this alert represents.
• IMPACT: What damage the attacker could cause if successful.
• EVIDENCE: What the analyst should immediately examine (logs, ports, processes).
• ACTION: The single most important immediate response step.

Plain text only — no markdown headers, no bold, no code blocks."""
        return self._call_claude(prompt)

    def analyze_payload(self, attacker_ip: str, payload: str,
                        port: int = None, severity: str = "Critical") -> str:
        if self._is_rate_limited(attacker_ip, "honeypot_payload"):
            return "Duplicate honeypot interaction — AI analysis skipped."
        severity_text   = SEVERITY_CONTEXT.get(severity, SEVERITY_CONTEXT["Critical"])
        port_text       = f" on port {port}" if port else ""
        mitre_ttp       = self._find_mitre_hint(payload)
        display_payload = payload[:600] + ("…[truncated]" if len(payload) > 600 else "")
        prompt = f"""You are an expert Tier-2 SOC Analyst and Malware Reverse Engineer.
The ORION Honeypot captured a live attacker interaction{port_text}:

  Attacker IP      : {attacker_ip}
  Severity         : {severity} — {severity_text}
  Likely MITRE TTP : {mitre_ttp}
  Raw Payload:
---
{display_payload}
---

Write a forensic triage report in exactly 5 short bullet points:
• ATTACK TYPE: Classify the specific attack technique.
• PAYLOAD ANALYSIS: What the payload does step by step.
• ATTACKER INTENT: What the attacker's end goal is.
• INDICATORS: Key IOCs (strings, IPs, commands).
• REMEDIATION: The most critical immediate countermeasure.

Plain text only."""
        return self._call_claude(prompt)

    def analyze_anomaly(self, attacker_ip: str, features: dict,
                        confidence: float) -> str:
        if self._is_rate_limited(attacker_ip, "ml_anomaly"):
            return None
        feat_text = ", ".join(f"{k}={v}" for k, v in features.items())
        prompt = f"""You are an expert Tier-2 SOC Analyst specializing in traffic anomaly detection.
The ORION ML engine flagged suspicious traffic with {confidence:.1%} confidence.

  Attacker IP      : {attacker_ip}
  Traffic Features : {feat_text}
  MITRE ATT&CK     : T1499/T1071 – Possible zero-day or covert channel

Write a brief anomaly triage report in exactly 3 short bullet points:
• WHY ANOMALOUS: What feature values make this traffic statistically unusual.
• POSSIBLE CAUSE: 3 plausible explanations ranked most to least likely.
• NEXT STEP: One concrete action to confirm or dismiss this as a false positive.

Plain text only."""
        return self._call_claude(prompt)

    def analyze_hids(self, filepath: str, change_type: str) -> str:
        if self._is_rate_limited("localhost", f"hids_{filepath}"):
            return None
        prompt = f"""You are an expert Tier-2 SOC Analyst specializing in host-based intrusion detection.
The ORION HIDS detected an unauthorized change:

  File Path    : {filepath}
  Change Type  : {change_type}
  MITRE ATT&CK : T1565 – Data Manipulation / T1070 – Indicator Removal

Write a brief HIDS triage report in exactly 3 short bullet points:
• RISK: Why this file change is security-significant.
• ATTACKER GOAL: What an attacker making this change is trying to achieve.
• RESPONSE: The immediate containment or investigation step.

Plain text only."""
        return self._call_claude(prompt)