# --- IDS_project2/utils/database.py ---
import sqlite3
import datetime
import threading

class DatabaseManager:
    def __init__(self, db_name="alerts.db"):
        self.db_name = db_name
        self.lock = threading.Lock() 

        # check_same_thread=False ensures our AI background thread 
        # can use the database simultaneously without crashing SQLite.
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row 
        self.cursor = self.conn.cursor()
        
        self._create_tables()

    def _create_tables(self):
        with self.lock:
            # 1. Create the Alerts table (with the ai_report column)
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    type TEXT,
                    severity TEXT,
                    source_ip TEXT,
                    ai_report TEXT 
                )
            ''')
            
            # 2. Create the Reputation table for tracking IP threat scores
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS reputation (
                    ip TEXT PRIMARY KEY,
                    score REAL
                )
            ''')
            self._ensure_column("alerts", "ai_report", "TEXT")
            self.conn.commit()

    def _ensure_column(self, table_name, column_name, column_type):
        self.cursor.execute(f"PRAGMA table_info({table_name})")
        columns = {row[1] for row in self.cursor.fetchall()}
        if column_name not in columns:
            self.cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")

    def save_alert(self, alert_type, severity, source_ip, ai_report=None):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            self.cursor.execute('''
                INSERT INTO alerts (timestamp, type, severity, source_ip, ai_report)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, alert_type, severity, source_ip, ai_report))
            self.conn.commit()
            
            # Returns the ID of the new alert so the AI thread knows which row to update
            return self.cursor.lastrowid 

    def update_ai_report(self, alert_id, ai_report):
        """Attaches the AI generated report to an existing alert."""
        with self.lock:
            self.cursor.execute('''
                UPDATE alerts SET ai_report = ? WHERE id = ?
            ''', (ai_report, alert_id))
            self.conn.commit()

    def get_recent_alerts(self, limit=50):
        with self.lock:
            self.cursor.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
            rows = self.cursor.fetchall()
            return [dict(row) for row in rows]
