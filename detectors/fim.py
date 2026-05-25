# --- IDS_project2/detectors/fim.py ---
import hashlib
import os

class FileIntegrityMonitor:
    def __init__(self):
        print("[+] HIDS: File Integrity Monitor initializing...")
        
        # Files to monitor for unauthorized changes
        self.files_to_monitor = [
            "signatures.json",
            "dummy_system_config.txt" 
        ]
        
        # Create a dummy file for testing so we don't break real system files
        if not os.path.exists("dummy_system_config.txt"):
            with open("dummy_system_config.txt", "w") as f:
                f.write("DO NOT MODIFY THIS CRITICAL SYSTEM FILE.")

        self.baseline_hashes = {}
        self._establish_baseline()

    def _get_sha256(self, filepath):
        """Calculates the SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except OSError:
            return None

    def _establish_baseline(self):
        """Records the trusted state of the files when the IDS starts."""
        for filepath in self.files_to_monitor:
            file_hash = self._get_sha256(filepath)
            if file_hash:
                self.baseline_hashes[filepath] = file_hash
        print(f"[+] HIDS: Baseline established for {len(self.baseline_hashes)} critical files.")

    def check_files(self) -> list[dict]:
        """
        Compare current file hashes against the baseline.
        Returns a list of alert dicts with keys:
          type, severity, filepath, change_type
        """
        alerts = []
        for filepath, baseline_hash in self.baseline_hashes.items():
            current_hash = self._get_sha256(filepath)

            if current_hash is None:
                change = "File Deleted"
                alerts.append({
                    "type"        : f"HIDS: Critical File Deleted ({filepath})",
                    "severity"    : "Critical",
                    "filepath"    : filepath,
                    "change_type" : change,
                })
            elif current_hash != baseline_hash:
                change = "Unauthorized Modification"
                alerts.append({
                    "type"        : f"HIDS: File Modified ({filepath})",
                    "severity"    : "Critical",
                    "filepath"    : filepath,
                    "change_type" : change,
                })
                # Update baseline to avoid duplicate alerts for the same change
                self.baseline_hashes[filepath] = current_hash

        return alerts