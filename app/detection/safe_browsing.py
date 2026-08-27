"""Google Safe Browsing threatMatches:find client, with local caching."""
from __future__ import annotations

import logging

import requests

from app.config import config
from app.db import cursor, now_iso, to_json

logger = logging.getLogger("safe_browsing")

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def _cache_get(url: str) -> bool | None:
    with cursor() as cur:
        cur.execute("SELECT is_malicious FROM safe_browsing_cache WHERE url = ?", (url,))
        row = cur.fetchone()
        return bool(row["is_malicious"]) if row else None


def _cache_set(url: str, is_malicious: bool, raw_response: dict) -> None:
    with cursor() as cur:
        cur.execute(
            """INSERT INTO safe_browsing_cache (url, is_malicious, raw_response, checked_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(url) DO UPDATE SET
                 is_malicious=excluded.is_malicious,
                 raw_response=excluded.raw_response,
                 checked_at=excluded.checked_at""",
            (url, int(is_malicious), to_json(raw_response), now_iso()),
        )


def check_url(url: str) -> dict:
    """Returns {'checked': bool, 'malicious': bool, 'source': 'cache'|'api'|'unavailable'}."""
    cached = _cache_get(url)
    if cached is not None:
        return {"checked": True, "malicious": cached, "source": "cache"}

    if not config.GOOGLE_API_KEY:
        return {"checked": False, "malicious": False, "source": "unavailable_no_key"}

    payload = {
        "client": {"clientId": "tcs-phishing-detector", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            API_URL,
            params={"key": config.GOOGLE_API_KEY},
            json=payload,
            timeout=config.HTTP_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        data = resp.json()
        is_malicious = bool(data.get("matches"))
        _cache_set(url, is_malicious, data)
        return {"checked": True, "malicious": is_malicious, "source": "api"}
    except requests.RequestException as exc:
        logger.warning("Safe Browsing unavailable for %s: %s", url, exc)
        return {"checked": False, "malicious": False, "source": "unavailable_error"}
