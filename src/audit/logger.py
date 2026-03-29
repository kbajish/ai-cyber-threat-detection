import sqlite3
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path("data/audit/audit_log.db")


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT    NOT NULL,
            ip_hash       TEXT    NOT NULL,
            prediction    TEXT    NOT NULL,
            confidence    REAL    NOT NULL,
            technique_id  TEXT,
            tactic        TEXT,
            top_features  TEXT,
            model_version TEXT
        )
    """)
    conn.commit()
    return conn


def _hash_ip(ip: str) -> str:
    """DSGVO pseudonymisation — raw IP is never stored."""
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def log_inference(
    source_ip:     str,
    prediction:    str,
    confidence:    float,
    top_features:  list,
    technique_id:  Optional[str] = None,
    tactic:        Optional[str] = None,
    model_version: str = "1.0.0"
):
    conn = _get_conn()
    conn.execute("""
        INSERT INTO audit_log
            (timestamp, ip_hash, prediction, confidence,
             technique_id, tactic, top_features, model_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        _hash_ip(source_ip),
        prediction,
        confidence,
        technique_id,
        tactic,
        json.dumps(top_features),
        model_version
    ))
    conn.commit()
    conn.close()


def get_recent_logs(limit: int = 100) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()

    cols = [
        "id", "timestamp", "ip_hash", "prediction",
        "confidence", "technique_id", "tactic",
        "top_features", "model_version"
    ]
    return [dict(zip(cols, r)) for r in rows]


if __name__ == "__main__":
    # Smoke test
    log_inference(
        source_ip    = "192.168.1.100",
        prediction   = "DDoS",
        confidence   = 0.97,
        top_features = [{"feature": "Flow Packets/s", "shap_value": 2.31}],
        technique_id = "T1498",
        tactic       = "Impact"
    )
    logs = get_recent_logs(5)
    for log in logs:
        print(log)