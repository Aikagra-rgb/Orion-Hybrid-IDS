import sqlite3
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn
from utils.reputation import BLACKLIST_THRESHOLD
from utils.threat_intel import enrich_ip

app = FastAPI(title="ORION Command Center API")
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "alerts.db"
FRONTEND_DIR = BASE_DIR / "frontend" / "ids-frontend"
MODEL_PATH = BASE_DIR / "model.pkl"
MODEL_METRICS_PATH = BASE_DIR / "model_metrics.json"

# Enable CORS (Allows your frontend to talk to your backend safely)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=512)

class NoCacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

app.add_middleware(NoCacheMiddleware)

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ensure_alert_schema(conn)
    return conn

def ensure_alert_schema(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
    if cursor.fetchone() is None:
        return
    cursor.execute("PRAGMA table_info(alerts)")
    columns = {row[1] for row in cursor.fetchall()}
    required = {
        "confidence": "REAL",
        "geo_country": "TEXT",
        "geo_city": "TEXT",
        "geo_latitude": "REAL",
        "geo_longitude": "REAL",
        "vpn_risk": "TEXT",
        "protection_action": "TEXT",
    }
    for column, col_type in required.items():
        if column not in columns:
            cursor.execute(f"ALTER TABLE alerts ADD COLUMN {column} {col_type}")
    conn.commit()

def alert_to_log_row(alert_row):
    severity = alert_row["severity"] or "Low"
    
    # Safely handle the ai_report column if it exists
    row_dict = dict(alert_row)
    
    return {
        "id": alert_row["id"],
        "timestamp": alert_row["timestamp"],
        "level": severity.lower(),
        "source": "ids.engine",
        "message": f'{alert_row["type"]} detected from {alert_row["source_ip"]}',
        "source_ip": alert_row["source_ip"],
        "alert_type": alert_row["type"],
        "severity": severity,
        "ai_report": row_dict.get("ai_report", None), # Pass the AI report through if it exists
        "confidence": row_dict.get("confidence", None),
    }

def _read_model_metrics():
    if MODEL_METRICS_PATH.exists():
        with open(MODEL_METRICS_PATH, "r", encoding="utf-8") as f:
            metrics = json.load(f)
    else:
        metrics = {
            "generated_at": None,
            "model_path": str(MODEL_PATH),
            "algorithm": "StandardScaler + calibrated RandomForestClassifier",
            "data_source": "not recorded yet",
            "features": ["length", "proto", "ttl", "dport", "sport", "tcp_flags", "payload_size"],
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "cv_f1_mean": None,
            "avg_attack_probability": None,
            "note": "Run train_model.py once to generate model_metrics.json with NSL-KDD/synthetic holdout metrics.",
        }
    metrics["model_exists"] = MODEL_PATH.exists()
    metrics["model_updated_at"] = (
        MODEL_PATH.stat().st_mtime if MODEL_PATH.exists() else None
    )
    return metrics

@app.get("/api/health")
def get_health():
    return JSONResponse(
        {
            "status": "ok",
            "service": "orion-api",
            "frontend_dir": str(FRONTEND_DIR),
            "db_path": str(DB_PATH),
            "build": "2026-04-23-debugfix-2 (Hybrid AI Integration)",
        }
    )

@app.get("/api/alerts")
def get_alerts(limit: int = 100):
    """Fetches alerts including the new AI Triage reports"""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        safe_limit = max(1, min(limit, 500))
        
        # SELECT * grabs all columns, including the new ai_report
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (safe_limit,))
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/stats")
def get_stats():
    """Provides high-level numbers for the dashboard widgets."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT severity, source_ip FROM alerts ORDER BY id DESC LIMIT 1000")
        rows = cursor.fetchall()
        conn.close()
        
        total_alerts = len(rows)
        critical_alerts = sum(1 for r in rows if r['severity'] == 'Critical')
        unique_ips = len(set(r['source_ip'] for r in rows))
        
        return {
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "unique_attackers": unique_ips
        }
    except Exception as e:
         return {"error": str(e)}

@app.get("/api/model-analytics")
def get_model_analytics():
    try:
        metrics = _read_model_metrics()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT confidence, type, timestamp
            FROM alerts
            WHERE confidence IS NOT NULL
            ORDER BY id DESC
            LIMIT 200
            """
        )
        rows = cursor.fetchall()
        conn.close()

        confidences = [float(r["confidence"]) for r in rows if r["confidence"] is not None]
        latest = rows[0] if rows else None
        return {
            "metrics": metrics,
            "live": {
                "scored_alerts": len(confidences),
                "latest_probability": float(latest["confidence"]) if latest else None,
                "latest_type": latest["type"] if latest else None,
                "average_probability": sum(confidences) / len(confidences) if confidences else None,
            },
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/blocked-ips")
def get_blocked_ips(limit: int = 50):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        safe_limit = max(1, min(limit, 200))
        cursor.execute(
            """
            SELECT
                r.ip,
                r.score,
                MAX(a.timestamp) AS last_seen,
                COUNT(a.id) AS alert_count,
                COALESCE(
                    (SELECT a2.type FROM alerts a2 WHERE a2.source_ip = r.ip ORDER BY a2.id DESC LIMIT 1),
                    'No alert detail'
                ) AS latest_type
            FROM reputation r
            LEFT JOIN alerts a ON a.source_ip = r.ip
            WHERE r.score >= ?
            GROUP BY r.ip, r.score
            ORDER BY r.score DESC, last_seen DESC
            LIMIT ?
            """,
            (BLACKLIST_THRESHOLD, safe_limit),
        )
        rows = cursor.fetchall()
        conn.close()
        blocked = []
        for row in rows:
            geo = enrich_ip(row["ip"])
            blocked.append({
                "ip": row["ip"],
                "score": float(row["score"]),
                "threshold": BLACKLIST_THRESHOLD,
                "last_seen": row["last_seen"],
                "alert_count": row["alert_count"],
                "latest_type": row["latest_type"],
                "geo": geo,
                "action": "Blocked by reputation threshold",
            })
        return blocked
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/threat-intel")
def get_threat_intel(limit: int = 20):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        safe_limit = max(1, min(limit, 100))
        cursor.execute(
            """
            SELECT
                source_ip,
                MAX(id) AS latest_id,
                MAX(timestamp) AS last_seen,
                COUNT(*) AS alert_count,
                COALESCE(MAX(confidence), NULL) AS max_confidence
            FROM alerts
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY latest_id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )
        rows = cursor.fetchall()
        cursor.execute("SELECT ip, score FROM reputation")
        scores = {row["ip"]: float(row["score"]) for row in cursor.fetchall()}
        conn.close()

        attackers = []
        for row in rows:
            ip = row["source_ip"]
            score = scores.get(ip, 0.0)
            blocked = score >= BLACKLIST_THRESHOLD
            geo = enrich_ip(ip)
            attackers.append({
                "ip": ip,
                "last_seen": row["last_seen"],
                "alert_count": row["alert_count"],
                "max_probability": row["max_confidence"],
                "score": score,
                "blocked": blocked,
                "geo": geo,
                "protection": "Blocked by reputation threshold" if blocked else "Reputation scoring, alert suppression, AI triage, and honeypot escalation",
            })

        return {
            "attackers": attackers,
            "vpn_protection": [
                "Reputation threshold blocks repeat offenders after cumulative malicious score reaches 100.",
                "High-rate loopback or VPN-like bursts are suppressed to prevent log and dashboard flooding.",
                "Honeypot traps are deployed for medium/high/critical detections to capture payloads.",
                "Optional keyless geo lookup can mark public IPs with proxy/hosting indicators when ORION_GEOLOOKUP_ENABLED=true.",
            ],
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/logs")
def get_logs(limit: int = 120):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        safe_limit = max(1, min(limit, 500))

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        has_logs_table = cursor.fetchone() is not None

        if has_logs_table:
            cursor.execute(
                """
                SELECT id, timestamp, level, source, message, source_ip, alert_type, severity
                FROM logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (safe_limit,),
            )
            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows]

        # Use SELECT * here too so alert_to_log_row gets the AI data
        cursor.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
            (safe_limit,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [alert_to_log_row(row) for row in rows]
    except Exception as e:
        return {"error": str(e)}

# Note: Always keep this route at the very bottom so it doesn't hijack the /api/ routes
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

if __name__ == "__main__":
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)
