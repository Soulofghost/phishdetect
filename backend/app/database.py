import sqlite3
import os
import json
from contextlib import contextmanager
from app.config import settings

def get_db_path() -> str:
    return os.environ.get("PHISHDETECT_DB", settings.PHISHDETECT_DB)

@contextmanager
def get_db_connection():
    db_path = get_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True) if os.path.dirname(db_path) else None
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                threat_score REAL NOT NULL,
                classification TEXT NOT NULL,
                domain_entropy REAL NOT NULL,
                risk_factor_count INTEGER NOT NULL,
                details_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocklist (
                id TEXT PRIMARY KEY,
                pattern TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification);")

        # Seed sample blocklist rules if empty
        cursor.execute("SELECT count(*) FROM blocklist")
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO blocklist (id, pattern, reason)
                VALUES 
                ('blk-1', '*.tk', 'High-abuse free TLD commonly used in credential harvesting'),
                ('blk-2', '*paypal-security-update*', 'Known impersonation lure pattern'),
                ('blk-3', '*apple-id-verify*', 'Credential phishing lure targeting Apple accounts')
            """)
        conn.commit()
