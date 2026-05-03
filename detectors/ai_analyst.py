# --- IDS_project2/detectors/ai_analyst.py ---
"""
ORION AI Analyst — Powered by Google Gemini 2.5 Pro
Provides rich, context-aware triage reports for every detected threat.
Features:
  - Context-aware prompts tailored to NIDS, HIDS, and Honeypot alerts
  - MITRE ATT&CK TTP mapping
  - Retry with exponential backoff
  - Per-IP rate limiting to avoid Gemini quota exhaustion
"""

from google import genai
from google.genai import types
import os
import time
import threading
from dotenv import load_dotenv

# ── Severity → priority text for the prompt ──────────────────────────────────
SEVERITY_CONTEXT = {
    "Critical": "CRITICAL severity — treat as active compromise. Immediate escalation required.",
    "High":     "HIGH severity — likely active exploitation attempt. Investigate within minutes.",
    "Medium":   "MEDIUM severity — suspicious activity. Review within the hour.",
    "Low":      "LOW severity — reconnaissance or noise. Log and monitor.",
}

# ── MITRE ATT&CK hint map (alert_type keyword → likely tactic) ──────────────
MITRE_HINTS = {
    "SYN":          "T1046 – Network Service Scanning",
    "Scan":         "T1046 – Network Service Scanning",
    "Brute Force":  "T1110 – Brute Force",
    "SQL":          "T1190 – Exploit Public-Facing Application",
    "XSS":          "T1059.007 – JavaScript scripting",
    "RFI":          "T1105 – Ingress Tool Transfer",
    "LFI":          "T1083 – File and Directory Discovery",
    "Shellshock":   "T1203 – Exploitation for Client Execution",
    "Log4Shell":    "T1190 – Exploit Public-Facing Application",
    "Exfil":        "T1048 – Exfiltration Over Alternative Protocol",
    "UDP":          "T1048 – Exfiltration Over Alternative Protocol",
    "File":         "T1565 – Data Manipulation / Integrity Attack",
    "HIDS":         "T1565 – Data Manipulation (Host-based)",
    "Honeypot":     "T1071 – Application Layer Protocol (Command & Control)",
    "ML Anomaly":   "T1499 – Endpoint Denial of Service / Unknown Zero-Day",
    "Command":      "T1059 – Command and Scripting Interpreter",
    "AWS":          "T1552.005 – Cloud Instance Metadata API",
    "SSH Key":      "T1552.004 – Private Keys",
}

MODEL_ID = "gemini-2.0-flash"


class AIAnalyst:
    """Context-aware Gemini 2.5 Pro-backed threat analyst."""

    # Only call the AI for each (ip, alert_type) pair at most once per N seconds
    RATE_LIMIT_SECONDS = 30
    MAX_RETRIES = 2
    RETRY_DELAY = 2.0        # seconds between retries

    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.client = None
        self._rate_cache = {}   # {(ip, alert_type): last_call_time}
        self._lock = threading.Lock()

        try:
            if not self.api_key:
                raise ValueError("GEMINI_API_KEY not found in .env file.")
            self.client = genai.Client(api_key=self.api_key)
            print(f"[+] AI Analyst (Gemini 2.0 Flash) initialized successfully.")
        except Exception as e:
            print(f"[-] AI Analyst failed to initialize: {e}")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _is_rate_limited(self, ip: str, alert_type: str) -> bool:
        """Return True if we called the AI for this (ip, type) very recently."""
        key = (ip, alert_type)
        with self._lock:
            last = self._rate_cache.get(key, 0)
            if time.time() - last < self.RATE_LIMIT_SECONDS:
                return True
            self._rate_cache[key] = time.time()
        return False

    def _find_mitre_hint(self, alert_type: str) -> str:
        for keyword, ttp in MITRE_HINTS.items():
            if keyword.lower() in alert_type.lower():
                return ttp
        return "Unknown – requires manual TTP mapping"

    def _call_gemini(self, prompt: str) -> str:
        """Call Gemini 2.5 Pro with retry logic. Returns the response text or an error string."""
        if not self.client:
            return "AI Analyst is offline (no valid Gemini API key)."

        for attempt in range(self.MAX_RETRIES + 1):
            try:
                response = self.client.models.generate_content(
                    model=MODEL_ID,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        thinking_config=types.ThinkingConfig(
                            thinking_budget=0,   # disable thinking for low-latency triage
                        )
                    ),
                )
                return response.text.strip()
            except Exception as e:
                err = str(e)
                if attempt < self.MAX_RETRIES:
                    time.sleep(self.RETRY_DELAY * (attempt + 1))
                else:
                    return f"AI Analysis failed after {self.MAX_RETRIES + 1} attempts: {err}"
        return "AI Analysis unavailable."

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, alert_type: str, attacker_ip: str,
                severity: str = "Medium", confidence: float = None,
                extra_context: str = "") -> str:
        """
        General-purpose NIDS/HIDS alert analyst.
        Called by engine.py for every detected threat.
        """
        if self._is_rate_limited(attacker_ip, alert_type):
            return None  # Silently skip; previous report still in DB

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

Write a concise, professional triage report in exactly 4 short bullet points using this format:
• THREAT: What attack or behavior this alert represents.
• IMPACT: What damage the attacker could cause if successful.
• EVIDENCE: What the analyst should immediately examine (logs, ports, processes).
• ACTION: The single most important immediate response step.

Use plain text only — no markdown headers, no bold, no code blocks."""

        return self._call_gemini(prompt)

    def analyze_payload(self, attacker_ip: str, payload: str,
                        port: int = None, severity: str = "Critical") -> str:
        """
        Deep analysis of a raw payload captured by the Honeypot.
        Provides richer output since we have the actual attacker data.
        """
        if self._is_rate_limited(attacker_ip, "honeypot_payload"):
            return "Duplicate honeypot interaction — AI analysis skipped to conserve quota."

        severity_text = SEVERITY_CONTEXT.get(severity, SEVERITY_CONTEXT["Critical"])
        port_text     = f" on port {port}" if port else ""
        mitre_ttp     = self._find_mitre_hint(payload)

        # Truncate very long payloads for the prompt
        display_payload = payload[:600] + ("…[truncated]" if len(payload) > 600 else "")

        prompt = f"""You are an expert Tier-2 SOC Analyst and Malware Reverse Engineer.
The ORION Honeypot captured a live attacker interaction{port_text}:

  Attacker IP      : {attacker_ip}
  Severity         : {severity} — {severity_text}
  Likely MITRE TTP : {mitre_ttp}
  Raw Payload      :
---
{display_payload}
---

Write a professional forensic triage report in exactly 5 short bullet points:
• ATTACK TYPE: Classify the specific attack technique being attempted.
• PAYLOAD ANALYSIS: What the payload actually does step by step.
• ATTACKER INTENT: What the attacker's end goal appears to be.
• INDICATORS: Key IOCs from this payload (strings, IPs, commands).
• REMEDIATION: The most critical immediate countermeasure.

Use plain text only — no markdown, no bold, no code blocks."""

        return self._call_gemini(prompt)

    def analyze_anomaly(self, attacker_ip: str, features: dict,
                        confidence: float) -> str:
        """
        Specialized analysis for ML Anomaly Detector hits.
        Provides more context about WHY the traffic is anomalous.
        """
        if self._is_rate_limited(attacker_ip, "ml_anomaly"):
            return None

        feat_text = ", ".join(f"{k}={v}" for k, v in features.items())

        prompt = f"""You are an expert Tier-2 SOC Analyst specializing in traffic anomaly detection.
The ORION ML engine flagged suspicious traffic with {confidence:.1%} confidence.

  Attacker IP      : {attacker_ip}
  Traffic Features : {feat_text}
  MITRE ATT&CK     : T1499/T1071 – Possible zero-day behavior or covert channel

Write a brief anomaly triage report in exactly 3 short bullet points:
• WHY ANOMALOUS: What specific feature values make this traffic statistically unusual.
• POSSIBLE CAUSE: 3 plausible explanations ranked from most to least likely.
• NEXT STEP: One concrete action to confirm or dismiss this as a false positive.

Plain text only."""

        return self._call_gemini(prompt)

    def analyze_hids(self, filepath: str, change_type: str) -> str:
        """
        Host-based alert analysis for file integrity violations.
        """
        if self._is_rate_limited("localhost", f"hids_{filepath}"):
            return None

        prompt = f"""You are an expert Tier-2 SOC Analyst specializing in host-based intrusion detection.
The ORION HIDS detected an unauthorized change:

  File Path    : {filepath}
  Change Type  : {change_type}
  MITRE ATT&CK : T1565 – Data Manipulation / T1070 – Indicator Removal

Write a brief HIDS triage report in exactly 3 short bullet points:
• RISK: Why this file change is security-significant.
• ATTACKER GOAL: What an attacker who made this change is likely trying to achieve.
• RESPONSE: The immediate containment or investigation step.

Plain text only."""

        return self._call_gemini(prompt)
