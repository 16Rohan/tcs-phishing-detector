"""Minimal simulated identity system. No real accounts are touched."""
from __future__ import annotations

from app.db import cursor

_SIMULATED_SESSIONS: dict[str, list[str]] = {}
_SIMULATED_DEVICES: dict[str, list[str]] = {}


def login(email: str, device_id: str = "demo-device-1") -> dict:
    _SIMULATED_SESSIONS.setdefault(email, []).append(device_id)
    return {"email": email, "status": "logged_in", "device_id": device_id}


def restrict(email: str) -> dict:
    with cursor() as cur:
        cur.execute(
            "UPDATE users SET status = 'RESTRICTED' WHERE email = ?", (email,)
        )
    return {"email": email, "status": "RESTRICTED"}


def unrestrict(email: str) -> dict:
    with cursor() as cur:
        cur.execute(
            "UPDATE users SET status = 'ACTIVE' WHERE email = ?", (email,)
        )
    return {"email": email, "status": "ACTIVE"}


def revoke_sessions(email: str) -> dict:
    revoked = _SIMULATED_SESSIONS.pop(email, [])
    return {"email": email, "sessions_revoked": len(revoked)}


def flag_device(email: str, device_id: str) -> dict:
    _SIMULATED_DEVICES.setdefault(email, []).append(device_id)
    return {"email": email, "device_id": device_id, "flagged": True}


def get_user_status(email: str) -> dict | None:
    with cursor() as cur:
        cur.execute("SELECT email, status, risk_level FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        return dict(row) if row else None
