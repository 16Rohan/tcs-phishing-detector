"""Create incidents, persist verdicts/evidence, link to emails, find affected users."""
from __future__ import annotations

from app.db import cursor, now_iso, to_json
from app.email.parser import ParsedEmail

SEVERITY_MAP = {
    "LEGITIMATE": "NONE",
    "SUSPICIOUS": "LOW",
    "PHISHING": "HIGH",
    "CRITICAL PHISHING": "CRITICAL",
}


def save_email_record(email: ParsedEmail, verdict: dict, processing_id: str) -> int:
    with cursor() as cur:
        cur.execute(
            """INSERT INTO emails
               (message_id, sender, reply_to, recipient, subject, received_at, raw_email,
                classification, risk_score, signals, explanation, phishbyte_confidence,
                social_engineering_confidence, processing_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(message_id) DO UPDATE SET
                 classification=excluded.classification,
                 risk_score=excluded.risk_score,
                 signals=excluded.signals,
                 explanation=excluded.explanation
               """,
            (
                email.message_id or f"generated-{processing_id}",
                email.sender,
                email.reply_to,
                email.recipient,
                email.subject,
                now_iso(),
                email.raw_email,
                verdict["classification"],
                verdict["risk_score"],
                to_json(verdict.get("signals", [])),
                verdict.get("explanation", ""),
                verdict.get("phishbyte_confidence", 0.0),
                verdict.get("social_engineering_confidence", 0.0),
                processing_id,
            ),
        )
        cur.execute(
            "SELECT id FROM emails WHERE message_id = ?",
            (email.message_id or f"generated-{processing_id}",),
        )
        row = cur.fetchone()
        return row["id"] if row else cur.lastrowid


def save_urls(email_id: int, url_analysis: list[dict]) -> None:
    with cursor() as cur:
        for u in url_analysis:
            cur.execute(
                """INSERT INTO urls (email_id, url, domain, verdict, source, risk_score, checked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    email_id,
                    u["url"],
                    u["domain"],
                    "MALICIOUS" if u["safe_browsing"].get("malicious") else u["lut_classification"],
                    u["safe_browsing"].get("source", "static"),
                    u["risk_score"],
                    now_iso(),
                ),
            )


def create_incident(email_id: int, verdict: dict, explanation: str) -> int:
    severity = SEVERITY_MAP.get(verdict["classification"], "LOW")
    status = "OPEN" if severity in ("HIGH", "CRITICAL") else "CLOSED"
    with cursor() as cur:
        cur.execute(
            """INSERT INTO incidents (email_id, severity, status, explanation, affected_users)
               VALUES (?, ?, ?, ?, ?)""",
            (email_id, severity, status, explanation, to_json([])),
        )
        return cur.lastrowid


def find_affected_users(indicator_value: str) -> list[str]:
    """Search prior email records for the same IOC to find other affected recipients."""
    affected = set()
    with cursor() as cur:
        cur.execute(
            "SELECT DISTINCT recipient FROM emails WHERE sender = ? OR raw_email LIKE ?",
            (indicator_value, f"%{indicator_value}%"),
        )
        for row in cur.fetchall():
            if row["recipient"]:
                affected.add(row["recipient"])
    return sorted(affected)


def mark_users_at_risk(emails: list[str], risk_level: str) -> None:
    with cursor() as cur:
        for email in emails:
            cur.execute(
                """INSERT INTO users (email, status, risk_level) VALUES (?, 'ACTIVE', ?)
                   ON CONFLICT(email) DO UPDATE SET risk_level=excluded.risk_level""",
                (email, risk_level),
            )


def update_incident_affected_users(incident_id: int, affected_users: list[str]) -> None:
    with cursor() as cur:
        cur.execute(
            "UPDATE incidents SET affected_users = ? WHERE id = ?",
            (to_json(affected_users), incident_id),
        )
