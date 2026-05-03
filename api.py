import sqlite3
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn

app = FastAPI(title="ORION Command Center API")
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "alerts.db"
FRONTEND_DIR = BASE_DIR / "frontend" / "ids-frontend"

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
    return conn

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
        "ai_report": row_dict.get("ai_report", None) # Pass the AI report through if it exists
    }

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