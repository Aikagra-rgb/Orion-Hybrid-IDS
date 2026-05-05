# --- IDS_project2/detectors/anomaly.py ---
"""
ORION ML Anomaly Detector
=========================
Hybrid NIDS component — flags statistically unusual packets using a trained
Random-Forest model AND a lightweight per-IP behavioral tracker.

Feature vector (7 dimensions — must match train_model.py):
  [packet_length, protocol, ttl, dport, sport, tcp_flags, payload_size]

Behavioral Tracker:
  Tracks packet-rate and port-diversity per source IP over a sliding window.
  High rates or extreme port diversity trigger a "Behavioral Anomaly" regardless
  of the ML model's prediction, making detection more robust without retraining.
"""

import joblib
import os
import time
import warnings
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

# Silence sklearn feature-name warnings (we feed raw numpy arrays)
warnings.filterwarnings("ignore", message="X does not have valid feature names")


class AnomalyDetector:
    # ── Behavioral tracker settings ────────────────────────────────────────────
    # Sliding window (seconds) for per-IP packet-rate analysis
    RATE_WINDOW_SECONDS    = 5
    # Alert if an IP sends more than this many packets in the window
    HIGH_RATE_THRESHOLD    = 30
    # Alert if an IP hits more than this many distinct ports in the window
    PORT_DIVERSITY_THRESH  = 12
    # Minimum ML confidence to raise an alert (calibrated against real data)
    ML_CONFIDENCE_THRESHOLD = 0.65
    # Prevent one noisy source from generating an alert for every packet.
    BEHAVIOR_ALERT_COOLDOWN_SECONDS = 15

    def __init__(self, model_path="model.pkl"):
        self.model = None
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                print("[+] ML Model loaded successfully into engine.")
            except Exception as e:
                print(f"[-] Error loading model.pkl: {e}")
        else:
            print("[-] Warning: 'model.pkl' not found. ML detection disabled.")

        # Per-IP behavioral state: {ip: deque([(timestamp, dport), ...])}
        self._ip_events: dict[str, deque] = defaultdict(deque)
        self._behavior_last_alert: dict[tuple[str, str], float] = {}

    # ── Feature extraction ─────────────────────────────────────────────────────

    def extract_features(self, packet) -> list:
        """
        Extract a 7-dimensional numeric feature vector from a Scapy packet.
        Must stay in sync with train_model.py's feature list.
        """
        length       = len(packet)
        payload_size = len(packet[Raw].load) if packet.haslayer(Raw) else 0
        ttl          = packet[IP].ttl if packet.haslayer(IP) else 64

        if packet.haslayer(TCP):
            proto      = 1
            dport      = packet[TCP].dport
            sport      = packet[TCP].sport
            tcp_flags  = int(packet[TCP].flags)
        elif packet.haslayer(UDP):
            proto      = 2
            dport      = packet[UDP].dport
            sport      = packet[UDP].sport
            tcp_flags  = 0
        else:
            proto      = 0
            dport      = 0
            sport      = 0
            tcp_flags  = 0

        return [length, proto, ttl, dport, sport, tcp_flags, payload_size]

    def get_feature_dict(self, packet) -> dict:
        """Return feature vector as a labelled dict (used by AI Analyst prompts)."""
        vec = self.extract_features(packet)
        keys = ["pkt_len", "proto", "ttl", "dport", "sport", "tcp_flags", "payload_size"]
        return dict(zip(keys, vec))

    # ── Behavioral rate / diversity tracker ────────────────────────────────────

    def _update_tracker(self, src_ip: str, dport: int, now: float):
        """Slide the window and append the new event."""
        events = self._ip_events[src_ip]
        events.append((now, dport))
        # Prune events older than the window
        while events and now - events[0][0] > self.RATE_WINDOW_SECONDS:
            events.popleft()

    def _check_behavioral_anomaly(self, src_ip: str) -> dict | None:
        """
        Return an alert dict if behavioral heuristics are triggered,
        otherwise None.
        """
        events = self._ip_events.get(src_ip)
        if not events:
            return None

        packet_rate   = len(events)
        unique_ports  = len({port for _, port in events})

        if packet_rate >= self.HIGH_RATE_THRESHOLD:
            alert_type = "Behavioral Anomaly: High Packet Rate"
            if self._is_behavior_alert_suppressed(src_ip, alert_type):
                return None
            return {
                "type"      : alert_type,
                "severity"  : "High",
                "confidence": min(packet_rate / (self.HIGH_RATE_THRESHOLD * 2), 1.0),
                "features"  : {"packet_rate": packet_rate, "window_s": self.RATE_WINDOW_SECONDS}
            }

        if unique_ports >= self.PORT_DIVERSITY_THRESH:
            alert_type = "Behavioral Anomaly: Port Scan"
            if self._is_behavior_alert_suppressed(src_ip, alert_type):
                return None
            return {
                "type"      : alert_type,
                "severity"  : "High",
                "confidence": min(unique_ports / (self.PORT_DIVERSITY_THRESH * 2), 1.0),
                "features"  : {"unique_ports": unique_ports, "window_s": self.RATE_WINDOW_SECONDS}
            }

        return None

    def _is_behavior_alert_suppressed(self, src_ip: str, alert_type: str) -> bool:
        now = time.time()
        key = (src_ip, alert_type)
        last_alert = self._behavior_last_alert.get(key, 0)
        if now - last_alert < self.BEHAVIOR_ALERT_COOLDOWN_SECONDS:
            return True
        self._behavior_last_alert[key] = now
        return False

    # ── Public API ─────────────────────────────────────────────────────────────

    def check(self, packet) -> dict | None:
        """
        Main entry point called by engine.py for every packet.

        Returns a dict with keys: type, severity, confidence, features
        or None if the packet is benign / whitelisted.
        """
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src

        # Whitelist well-known safe resolvers / telemetry subnets
        if src_ip in ("8.8.8.8", "8.8.4.4") or src_ip.startswith("172.191."):
            return None

        dport = 0
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport

        now = time.time()
        self._update_tracker(src_ip, dport, now)

        # 1. Behavioral check (no model required)
        behavioral_alert = self._check_behavioral_anomaly(src_ip)
        if behavioral_alert:
            return behavioral_alert

        # 2. ML model check
        if self.model is None:
            return None

        features = self.extract_features(packet)
        try:
            probs              = self.model.predict_proba([features])[0]
            anomaly_confidence = float(probs[1])
        except AttributeError:
            # Model doesn't support predict_proba (e.g., plain IsolationForest)
            prediction = self.model.predict([features])
            anomaly_confidence = 1.0 if prediction[0] == 1 else 0.0
        except Exception:
            return None

        if anomaly_confidence >= self.ML_CONFIDENCE_THRESHOLD:
            severity = (
                "Critical" if anomaly_confidence >= 0.90 else
                "High"     if anomaly_confidence >= 0.75 else
                "Medium"
            )
            return {
                "type"      : "ML Anomaly Detected",
                "severity"  : severity,
                "confidence": anomaly_confidence,
                "features"  : self.get_feature_dict(packet)
            }

        return None
