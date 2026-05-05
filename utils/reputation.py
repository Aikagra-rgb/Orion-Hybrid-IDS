import time

# IP is auto-blacklisted once its cumulative score exceeds this threshold
BLACKLIST_THRESHOLD = 100
# Blacklist duration in seconds (default: 10 minutes)
BLACKLIST_DURATION  = 600


class ReputationManager:
    """Tracks threat scores per source IP and auto-blacklists repeat offenders."""

    def __init__(self, db_manager):
        self.db = db_manager
        # {ip: blacklisted_at_timestamp}
        self.blacklisted_ips: dict[str, float] = {}
        self._load_persisted_blacklist()

    def _load_persisted_blacklist(self):
        now = time.time()
        with self.db.lock:
            self.db.cursor.execute(
                "SELECT ip FROM reputation WHERE score >= ?",
                (BLACKLIST_THRESHOLD,),
            )
            rows = self.db.cursor.fetchall()
        for row in rows:
            self.blacklisted_ips[row[0]] = now

    def update_score(self, ip: str, delta: int = 10) -> float:
        """
        Increment the reputation (threat) score for *ip* by *delta* points.
        Honeypot interactions should use a larger delta (e.g., 25).
        Auto-blacklists the IP if the score exceeds BLACKLIST_THRESHOLD.
        Returns the new cumulative score.
        """
        with self.db.lock:
            self.db.cursor.execute("SELECT score FROM reputation WHERE ip=?", (ip,))
            result = self.db.cursor.fetchone()
            new_score = (float(result[0]) + delta) if result else float(delta)

            if result:
                self.db.cursor.execute(
                    "UPDATE reputation SET score=? WHERE ip=?", (new_score, ip)
                )
            else:
                self.db.cursor.execute(
                    "INSERT INTO reputation(ip, score) VALUES (?, ?)", (ip, new_score)
                )
            self.db.conn.commit()

        # Auto-blacklist high-score offenders
        if new_score >= BLACKLIST_THRESHOLD and ip not in self.blacklisted_ips:
            self.add_to_blacklist(ip)
            print(f"[REP]  {ip} auto-blacklisted (score={new_score:.0f})")

        return new_score

    def get_score(self, ip: str) -> float:
        """Return the current cumulative threat score for *ip* (0 if unknown)."""
        with self.db.lock:
            self.db.cursor.execute("SELECT score FROM reputation WHERE ip=?", (ip,))
            result = self.db.cursor.fetchone()
        return float(result[0]) if result else 0.0

    def add_to_blacklist(self, ip: str):
        self.blacklisted_ips[ip] = time.time()

    def is_blacklisted(self, ip: str) -> bool:
        if ip in self.blacklisted_ips:
            if time.time() - self.blacklisted_ips[ip] < BLACKLIST_DURATION:
                return True
            del self.blacklisted_ips[ip]
        return False

    def protection_action_for_score(self, ip: str, score: float) -> str:
        if self.is_blacklisted(ip) or score >= BLACKLIST_THRESHOLD:
            return "Blocked by reputation threshold"
        if score >= BLACKLIST_THRESHOLD * 0.7:
            return "High-risk watchlist; block on next confirmed hit"
        if score > 0:
            return "Monitored with reputation scoring and AI triage"
        return "Observed only"
