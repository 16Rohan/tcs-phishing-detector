"""Local domain / IOC lookup table. Avoids repeated external API calls."""
from __future__ import annotations

from app.db import cursor, now_iso


def lookup_domain(domain: str) -> str:
    """Return TRUSTED / SUSPICIOUS / MALICIOUS / UNKNOWN without any network call."""
    if not domain:
        return "UNKNOWN"
    domain = domain.lower().strip()
    with cursor() as cur:
        cur.execute("SELECT classification FROM domains WHERE domain = ?", (domain,))
        row = cur.fetchone()
        if row:
            return row["classification"]
        for suffix_row in cur.execute("SELECT domain, classification FROM domains"):
            if domain.endswith("." + suffix_row["domain"]):
                return suffix_row["classification"]
    return "UNKNOWN"


def upsert_domain(domain: str, classification: str, source: str, reason: str) -> None:
    if not domain:
        return
    domain = domain.lower().strip()
    with cursor() as cur:
        cur.execute(
            """INSERT INTO domains (domain, classification, source, reason)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(domain) DO UPDATE SET
                 classification=excluded.classification,
                 source=excluded.source,
                 reason=excluded.reason""",
            (domain, classification, source, reason),
        )


def upsert_ioc(indicator: str, indicator_type: str, verdict: str, source: str) -> None:
    if not indicator:
        return
    ts = now_iso()
    with cursor() as cur:
        cur.execute(
            """INSERT INTO iocs (indicator, indicator_type, verdict, source, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(indicator, indicator_type) DO UPDATE SET
                 verdict=excluded.verdict,
                 last_seen=excluded.last_seen""",
            (indicator, indicator_type, verdict, source, ts, ts),
        )


def lookup_ioc(indicator: str, indicator_type: str) -> str | None:
    with cursor() as cur:
        cur.execute(
            "SELECT verdict FROM iocs WHERE indicator = ? AND indicator_type = ?",
            (indicator, indicator_type),
        )
        row = cur.fetchone()
        return row["verdict"] if row else None
