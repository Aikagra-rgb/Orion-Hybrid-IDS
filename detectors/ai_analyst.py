# --- IDS_project2/detectors/ai_analyst.py ---
"""
ORION AI Analyst - provider-neutral LLM triage.

Supported providers:
  - Mistral API: set AI_ANALYST_PROVIDER=mistral and MISTRAL_API_KEY
  - Ollama local: set AI_ANALYST_PROVIDER=ollama and run a local model
  - Offline fallback: deterministic triage with no network or key

Use AI_ANALYST_PROVIDER=auto to prefer Mistral when a key exists, otherwise
Ollama when configured, otherwise the offline fallback.
"""

import os
import threading
import time
from typing import Any

import httpx
from dotenv import load_dotenv


SEVERITY_CONTEXT = {
    "Critical": "CRITICAL severity - treat as active compromise. Immediate escalation required.",
    "High": "HIGH severity - likely active exploitation attempt. Investigate within minutes.",
    "Medium": "MEDIUM severity - suspicious activity. Review within the hour.",
    "Low": "LOW severity - reconnaissance or noise. Log and monitor.",
}

MITRE_HINTS = {
    "SYN": "T1046 - Network Service Scanning",
    "Scan": "T1046 - Network Service Scanning",
    "Brute Force": "T1110 - Brute Force",
    "SQL": "T1190 - Exploit Public-Facing Application",
    "XSS": "T1059.007 - JavaScript scripting",
    "RFI": "T1105 - Ingress Tool Transfer",
    "LFI": "T1083 - File and Directory Discovery",
    "Shellshock": "T1203 - Exploitation for Client Execution",
    "Log4Shell": "T1190 - Exploit Public-Facing Application",
    "Exfil": "T1048 - Exfiltration Over Alternative Protocol",
    "UDP": "T1048 - Exfiltration Over Alternative Protocol",
    "File": "T1565 - Data Manipulation / Integrity Attack",
    "HIDS": "T1565 - Data Manipulation (Host-based)",
    "Honeypot": "T1071 - Application Layer Protocol (C2)",
    "ML Anomaly": "T1499 - Endpoint Denial of Service / Unknown Zero-Day",
    "Command": "T1059 - Command and Scripting Interpreter",
    "AWS": "T1552.005 - Cloud Instance Metadata API",
    "SSH Key": "T1552.004 - Private Keys",
}

DEFAULT_MISTRAL_MODEL = "mistral-small-latest"
DEFAULT_OLLAMA_MODEL = "mistral"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
MISTRAL_CHAT_URL = "https://api.mistral.ai/v1/chat/completions"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class AIAnalyst:
    RATE_LIMIT_SECONDS = 120
    MAX_RETRIES = 1
    RETRY_DELAY = 5.0

    def __init__(self):
        load_dotenv()

        self.provider = os.getenv("AI_ANALYST_PROVIDER", "auto").strip().lower()
        self.mistral_api_key = os.getenv("MISTRAL_API_KEY", "").strip()
        self.mistral_model = os.getenv("MISTRAL_MODEL", DEFAULT_MISTRAL_MODEL).strip()
        self.ollama_model = os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL).strip()
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL).strip().rstrip("/")
        self.timeout = _env_float("AI_ANALYST_TIMEOUT", 30.0)
        self.daily_call_limit = _env_int("AI_ANALYST_DAILY_CALL_LIMIT", 200)
        self.verify_on_startup = _env_bool("AI_ANALYST_VERIFY_ON_STARTUP", False)

        self._init_error = None
        self._active_provider = self._select_provider()
        self._client = httpx.Client(timeout=self.timeout)

        self._rate_cache = {}
        self._lock = threading.Lock()
        self._daily_count = 0
        self._day_start = time.time()
        self._quota_parked_until = 0

        self._announce_provider()
        if self.verify_on_startup and self._active_provider != "offline":
            self._verify_provider()

    def _select_provider(self) -> str:
        if self.provider in {"mistral", "mistralai"}:
            if not self.mistral_api_key or self.mistral_api_key.startswith("your_"):
                self._init_error = "MISTRAL_API_KEY is missing or still set to a placeholder."
                return "offline"
            return "mistral"

        if self.provider == "ollama":
            return "ollama"

        if self.provider == "offline":
            return "offline"

        if self.provider != "auto":
            self._init_error = f"Unknown AI_ANALYST_PROVIDER={self.provider!r}; using offline fallback."
            return "offline"

        if self.mistral_api_key and not self.mistral_api_key.startswith("your_"):
            return "mistral"

        if os.getenv("OLLAMA_MODEL") or os.getenv("OLLAMA_BASE_URL"):
            return "ollama"

        self._init_error = "No Mistral key or Ollama config found; using offline fallback."
        return "offline"

    def _announce_provider(self):
        if self._active_provider == "mistral":
            print(f"[+] AI Analyst: using Mistral model '{self.mistral_model}'.")
        elif self._active_provider == "ollama":
            print(f"[+] AI Analyst: using local Ollama model '{self.ollama_model}' at {self.ollama_base_url}.")
        else:
            print(f"[~] AI Analyst: offline fallback active. {self._init_error or ''}".strip())

    def _verify_provider(self):
        try:
            if self._active_provider == "mistral":
                self._call_mistral("Reply with OK only.")
            elif self._active_provider == "ollama":
                self._call_ollama("Reply with OK only.")
            print("[+] AI Analyst: provider startup check passed.")
        except Exception as e:
            self._init_error = str(e)
            self._active_provider = "offline"
            print(f"[-] AI Analyst startup check failed; using offline fallback: {e}")

    def _reset_daily_counter_if_needed(self):
        if time.time() - self._day_start >= 86400:
            self._daily_count = 0
            self._day_start = time.time()
            self._quota_parked_until = 0

    def _is_rate_limited(self, ip: str, alert_type: str) -> bool:
        key = (ip, alert_type)
        with self._lock:
            self._reset_daily_counter_if_needed()
            if time.time() < self._quota_parked_until:
                remaining = int(self._quota_parked_until - time.time())
                print(f"[~] AI Analyst quota-parked for {remaining}s - skipping.")
                return True
            if self._daily_count >= self.daily_call_limit:
                print(f"[~] AI Analyst daily cap ({self.daily_call_limit}) reached.")
                return True
            last = self._rate_cache.get(key, 0)
            if time.time() - last < self.RATE_LIMIT_SECONDS:
                return True
            self._rate_cache[key] = time.time()
            self._daily_count += 1
        return False

    def _find_mitre_hint(self, alert_type: str) -> str:
        for keyword, ttp in MITRE_HINTS.items():
            if keyword.lower() in alert_type.lower():
                return ttp
        return "Unknown - requires manual TTP mapping"

    def _call_llm(self, prompt: str, offline_fallback: str) -> str:
        if self._active_provider == "offline":
            return offline_fallback

        last_error = None
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                if self._active_provider == "mistral":
                    return self._call_mistral(prompt)
                if self._active_provider == "ollama":
                    return self._call_ollama(prompt)
                return offline_fallback

            except httpx.HTTPStatusError as e:
                last_error = self._status_error_message(e)
                status = e.response.status_code
                if status in {401, 403}:
                    self._init_error = last_error
                    self._active_provider = "offline"
                    return self._with_fallback_note(offline_fallback, last_error)
                if status == 429:
                    with self._lock:
                        self._quota_parked_until = time.time() + 60
                    return self._with_fallback_note(offline_fallback, "provider rate-limited; parked for 60s")
                if status >= 500 and attempt < self.MAX_RETRIES:
                    time.sleep(self.RETRY_DELAY)
                    continue
                break

            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_error = f"{self._active_provider} connection failed: {e}"
                if attempt < self.MAX_RETRIES:
                    time.sleep(self.RETRY_DELAY)
                    continue
                break

            except Exception as e:
                last_error = str(e)
                if attempt < self.MAX_RETRIES:
                    time.sleep(self.RETRY_DELAY)
                    continue
                break

        print(f"[!] AI Analyst provider error: {last_error}")
        return self._with_fallback_note(offline_fallback, last_error or "provider unavailable")

    def _call_mistral(self, prompt: str) -> str:
        response = self._client.post(
            MISTRAL_CHAT_URL,
            headers={
                "Authorization": f"Bearer {self.mistral_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.mistral_model,
                "max_tokens": 512,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        response.raise_for_status()
        data = response.json()
        return self._extract_openai_compatible_content(data)

    def _call_ollama(self, prompt: str) -> str:
        response = self._client.post(
            f"{self.ollama_base_url}/api/chat",
            json={
                "model": self.ollama_model,
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": 512},
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        response.raise_for_status()
        data = response.json()
        content = data.get("message", {}).get("content", "")
        if not content:
            raise ValueError("Ollama returned an empty chat message.")
        return content.strip()

    def _extract_openai_compatible_content(self, data: dict[str, Any]) -> str:
        choices = data.get("choices") or []
        if not choices:
            raise ValueError("LLM response did not include choices.")
        message = choices[0].get("message", {})
        content = message.get("content", "")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        else:
            text = str(content)
        text = text.strip()
        if not text:
            raise ValueError("LLM response content was empty.")
        return text

    def _status_error_message(self, error: httpx.HTTPStatusError) -> str:
        status = error.response.status_code
        try:
            detail = error.response.json()
        except ValueError:
            detail = error.response.text
        return f"{self._active_provider} HTTP {status}: {detail}"

    def _with_fallback_note(self, fallback: str, reason: str) -> str:
        return f"{fallback}\n- LLM FALLBACK: Provider unavailable ({reason})."

    # Public API

    def analyze(
        self,
        alert_type: str,
        attacker_ip: str,
        severity: str = "Medium",
        confidence: float = None,
        extra_context: str = "",
    ) -> str:
        if self._is_rate_limited(attacker_ip, alert_type):
            return None
        severity_text = SEVERITY_CONTEXT.get(severity, SEVERITY_CONTEXT["Medium"])
        mitre_ttp = self._find_mitre_hint(alert_type)
        conf_text = f" (ML confidence: {confidence:.1%})" if confidence is not None else ""
        prompt = f"""You are an expert Tier-2 SOC Analyst using the ORION Hybrid IDS.
A new alert has been generated:

  Alert Type   : {alert_type}{conf_text}
  Source IP    : {attacker_ip}
  Severity     : {severity} - {severity_text}
  MITRE ATT&CK : {mitre_ttp}
{f"  Extra Context: {extra_context}" if extra_context else ""}

Write a concise, professional triage report in exactly 4 short bullet points:
- THREAT: What attack or behavior this alert represents.
- IMPACT: What damage the attacker could cause if successful.
- EVIDENCE: What the analyst should immediately examine (logs, ports, processes).
- ACTION: The single most important immediate response step.

Plain text only - no markdown headers, no bold, no code blocks."""
        fallback = self._offline_alert_report(alert_type, attacker_ip, severity, mitre_ttp)
        return self._call_llm(prompt, fallback)

    def analyze_payload(
        self,
        attacker_ip: str,
        payload: str,
        port: int = None,
        severity: str = "Critical",
    ) -> str:
        if self._is_rate_limited(attacker_ip, "honeypot_payload"):
            return "Duplicate honeypot interaction - AI analysis skipped."
        severity_text = SEVERITY_CONTEXT.get(severity, SEVERITY_CONTEXT["Critical"])
        port_text = f" on port {port}" if port else ""
        mitre_ttp = self._find_mitre_hint(payload)
        display_payload = payload[:600] + ("...[truncated]" if len(payload) > 600 else "")
        prompt = f"""You are an expert Tier-2 SOC Analyst and Malware Reverse Engineer.
The ORION Honeypot captured a live attacker interaction{port_text}:

  Attacker IP      : {attacker_ip}
  Severity         : {severity} - {severity_text}
  Likely MITRE TTP : {mitre_ttp}
  Raw Payload:
---
{display_payload}
---

Write a forensic triage report in exactly 5 short bullet points:
- ATTACK TYPE: Classify the specific attack technique.
- PAYLOAD ANALYSIS: What the payload does step by step.
- ATTACKER INTENT: What the attacker's end goal is.
- INDICATORS: Key IOCs (strings, IPs, commands).
- REMEDIATION: The most critical immediate countermeasure.

Plain text only."""
        fallback = self._offline_payload_report(attacker_ip, display_payload, port, mitre_ttp)
        return self._call_llm(prompt, fallback)

    def analyze_anomaly(self, attacker_ip: str, features: dict, confidence: float) -> str:
        if self._is_rate_limited(attacker_ip, "ml_anomaly"):
            return None
        feat_text = ", ".join(f"{k}={v}" for k, v in features.items())
        prompt = f"""You are an expert Tier-2 SOC Analyst specializing in traffic anomaly detection.
The ORION ML engine flagged suspicious traffic with {confidence:.1%} confidence.

  Attacker IP      : {attacker_ip}
  Traffic Features : {feat_text}
  MITRE ATT&CK     : T1499/T1071 - Possible zero-day or covert channel

Write a brief anomaly triage report in exactly 3 short bullet points:
- WHY ANOMALOUS: What feature values make this traffic statistically unusual.
- POSSIBLE CAUSE: 3 plausible explanations ranked most to least likely.
- NEXT STEP: One concrete action to confirm or dismiss this as a false positive.

Plain text only."""
        fallback = self._offline_anomaly_report(attacker_ip, feat_text, confidence)
        return self._call_llm(prompt, fallback)

    def analyze_hids(self, filepath: str, change_type: str) -> str:
        if self._is_rate_limited("localhost", f"hids_{filepath}"):
            return None
        prompt = f"""You are an expert Tier-2 SOC Analyst specializing in host-based intrusion detection.
The ORION HIDS detected an unauthorized change:

  File Path    : {filepath}
  Change Type  : {change_type}
  MITRE ATT&CK : T1565 - Data Manipulation / T1070 - Indicator Removal

Write a brief HIDS triage report in exactly 3 short bullet points:
- RISK: Why this file change is security-significant.
- ATTACKER GOAL: What an attacker making this change is trying to achieve.
- RESPONSE: The immediate containment or investigation step.

Plain text only."""
        fallback = self._offline_hids_report(filepath, change_type)
        return self._call_llm(prompt, fallback)

    def _offline_alert_report(self, alert_type: str, attacker_ip: str, severity: str, mitre_ttp: str) -> str:
        return "\n".join(
            [
                f"- THREAT: {alert_type} from {attacker_ip} maps to {mitre_ttp} and should be treated as {severity.lower()} priority.",
                "- IMPACT: Successful activity could expose services, weaken credentials, disrupt availability, or lead to follow-on compromise.",
                f"- EVIDENCE: Review IDS, firewall, web, auth, process, and port logs around source {attacker_ip}.",
                "- ACTION: Block or quarantine the source temporarily, preserve logs, and validate whether the target host shows compromise indicators.",
            ]
        )

    def _offline_payload_report(self, attacker_ip: str, payload: str, port: int, mitre_ttp: str) -> str:
        port_text = f" on port {port}" if port else ""
        return "\n".join(
            [
                f"- ATTACK TYPE: Honeypot payload from {attacker_ip}{port_text}; likely technique is {mitre_ttp}.",
                f"- PAYLOAD ANALYSIS: Captured input begins with {payload[:120]!r}; inspect for shell metacharacters, URLs, credentials, and encoded commands.",
                "- ATTACKER INTENT: The interaction likely aims to fingerprint the service, gain command execution, or stage a second payload.",
                "- INDICATORS: Treat the source IP, requested port, command strings, URLs, file paths, and unusual user agents as IOCs.",
                "- REMEDIATION: Keep the source blocked, snapshot the payload, search for matching activity, and verify the exposed service is not real production infrastructure.",
            ]
        )

    def _offline_anomaly_report(self, attacker_ip: str, feat_text: str, confidence: float) -> str:
        return "\n".join(
            [
                f"- WHY ANOMALOUS: Traffic from {attacker_ip} scored {confidence:.1%}; notable features are {feat_text or 'not provided'}.",
                "- POSSIBLE CAUSE: Most likely scan or burst traffic, then misconfigured client, then novel attack or covert channel.",
                "- NEXT STEP: Compare the flow against baseline traffic and packet captures, then block or tune the rule based on validation.",
            ]
        )

    def _offline_hids_report(self, filepath: str, change_type: str) -> str:
        return "\n".join(
            [
                f"- RISK: {change_type} on {filepath} may indicate tampering, persistence, log clearing, or configuration abuse.",
                "- ATTACKER GOAL: The likely objective is to hide activity, weaken controls, establish persistence, or alter system behavior.",
                "- RESPONSE: Isolate the host if the file is sensitive, preserve a copy, compare with a known-good baseline, and inspect recent process/user activity.",
            ]
        )
