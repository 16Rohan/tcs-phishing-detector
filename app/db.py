"""SQLite persistence layer. Plain sqlite3, no ORM."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from app.config import config

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE,
    sender TEXT,
    reply_to TEXT,
    recipient TEXT,
    subject TEXT,
    received_at TEXT,
    raw_email TEXT,
    classification TEXT,
    risk_score INTEGER,
    signals TEXT,
    explanation TEXT,
    phishbyte_confidence REAL,
    social_engineering_confidence REAL,
    processing_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER,
    url TEXT,
    domain TEXT,
    verdict TEXT,
    source TEXT,
    risk_score INTEGER,
    checked_at TEXT,
    FOREIGN KEY(email_id) REFERENCES emails(id)
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    classification TEXT,
    source TEXT,
    reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT,
    indicator_type TEXT,
    verdict TEXT,
    source TEXT,
    first_seen TEXT,
    last_seen TEXT,
    UNIQUE(indicator, indicator_type)
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER,
    severity TEXT,
    status TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    explanation TEXT,
    affected_users TEXT,
    FOREIGN KEY(email_id) REFERENCES emails(id)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    status TEXT DEFAULT 'ACTIVE',
    risk_level TEXT DEFAULT 'NONE'
);

CREATE TABLE IF NOT EXISTS safe_browsing_cache (
    url TEXT PRIMARY KEY,
    is_malicious INTEGER,
    raw_response TEXT,
    checked_at TEXT
);
"""


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(config.DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        _local.conn = conn
    return conn


@contextmanager
def cursor():
    conn = get_conn()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def init_db() -> None:
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    _seed_users()
    _seed_domains()


def _seed_users() -> None:
    with cursor() as cur:
        for email in config.SIMULATED_USERS:
            cur.execute(
                "INSERT OR IGNORE INTO users (email, status, risk_level) VALUES (?, 'ACTIVE', 'NONE')",
                (email,),
            )


TRUSTED_SEED_DOMAINS = [
    ("microsoft.com", "TRUSTED", "seed", "Well-known legitimate domain"),
    ("google.com", "TRUSTED", "seed", "Well-known legitimate domain"),
    ("company.test", "TRUSTED", "seed", "Simulated internal organization domain"),
    ("apple.com", "TRUSTED", "seed", "Well-known legitimate domain"),
    ("paypal.com", "TRUSTED", "seed", "Well-known legitimate domain"),
]

MALICIOUS_SEED_DOMAINS = [
    ("secure-login-verify.xyz", "MALICIOUS", "seed", "Known phishing kit domain (demo IOC)"),
    ("account-update-alert.top", "MALICIOUS", "seed", "Known phishing kit domain (demo IOC)"),
    ("micros0ft-support.com", "MALICIOUS", "seed", "Brand-impersonation domain (demo IOC)"),
]


def _seed_domains() -> None:
    with cursor() as cur:
        for domain, classification, source, reason in TRUSTED_SEED_DOMAINS + MALICIOUS_SEED_DOMAINS:
            cur.execute(
                """INSERT OR IGNORE INTO domains (domain, classification, source, reason)
                   VALUES (?, ?, ?, ?)""",
                (domain, classification, source, reason),
            )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_json(obj) -> str:
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return "{}"
