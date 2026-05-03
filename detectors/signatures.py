import json
import os
import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

class SignatureDetector:
    SYN_SCAN_WINDOW_SECONDS = 3
    SYN_SCAN_PORT_THRESHOLD = 8
    ALERT_COOLDOWN_SECONDS = 10

    def __init__(self, signatures_file="signatures.json"):
        self.signatures = []
        self.syn_scan_activity = defaultdict(deque)
        self.syn_scan_last_alert = {}
        if os.path.exists(signatures_file):
            try:
                with open(signatures_file, "r") as f:
                    self.signatures = json.load(f)
                print(f"[+] Loaded {len(self.signatures)} payload signatures from JSON.")
            except Exception as e:
                print(f"[-] Error loading signatures.json: {e}")
        else:
            print("[-] Warning: signatures.json not found. Payload inspection disabled.")

    def _prune_syn_history(self, src_ip, now):
        events = self.syn_scan_activity[src_ip]
        while events and now - events[0][0] > self.SYN_SCAN_WINDOW_SECONDS:
            events.popleft()

        if not events:
            self.syn_scan_activity.pop(src_ip, None)

    def _check_syn_scan(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return None

        flags = int(packet[TCP].flags)
        is_syn = bool(flags & 0x02)
        has_ack = bool(flags & 0x10)
        if not is_syn or has_ack:
            return None

        src_ip = packet[IP].src
        now = time.time()
        events = self.syn_scan_activity[src_ip]
        events.append((now, packet[TCP].dport))
        self._prune_syn_history(src_ip, now)

        unique_ports = {port for _, port in self.syn_scan_activity.get(src_ip, ())}
        if len(unique_ports) < self.SYN_SCAN_PORT_THRESHOLD:
            return None

        last_alert = self.syn_scan_last_alert.get(src_ip, 0)
        if now - last_alert < self.ALERT_COOLDOWN_SECONDS:
            return None

        self.syn_scan_last_alert[src_ip] = now
        return {"type": "SYN Scan", "severity": "Medium"}

    def check(self, packet):
        # 1. Network Layer Rules (Header Inspection)
        syn_scan_alert = self._check_syn_scan(packet)
        if syn_scan_alert:
            return syn_scan_alert

        if packet.haslayer(UDP) and len(packet) > 1024:
            # Ignore standard DNS (53) and QUIC/HTTP3 (443) traffic
            excluded_ports = [53, 443]
            if packet[UDP].sport not in excluded_ports and packet[UDP].dport not in excluded_ports:
                return {"type": "Large UDP Payload", "severity": "Low"}

        # 2. Application Layer Rules (Deep Packet Inspection)
        # Search the raw bytes of the packet for your JSON patterns
        if packet.haslayer(Raw) and self.signatures:
            # Decode payload, ignoring errors to prevent crashes on binary data
            payload = packet[Raw].load.decode(errors="ignore")
            payload_lower = payload.lower()

            for sig in self.signatures:
                if sig["pattern"].lower() in payload_lower:
                    return {"type": sig["type"], "severity": sig["severity"]}

        return None
