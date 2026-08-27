"""Central configuration loaded from environment variables / .env."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    # External APIs
    GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
    NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
    NVIDIA_BASE_URL = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
    NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "openai/gpt-oss-20b")

    # Mailpit
    MAILPIT_HOST = os.environ.get("MAILPIT_HOST", "localhost")
    MAILPIT_SMTP_PORT = _int("MAILPIT_SMTP_PORT", 1025)
    MAILPIT_UI_PORT = _int("MAILPIT_UI_PORT", 8025)
    MAILPIT_API_BASE = os.environ.get(
        "MAILPIT_API_BASE", f"http://{MAILPIT_HOST}:{MAILPIT_UI_PORT}/api/v1"
    )

    # Risk thresholds
    SUSPICIOUS_THRESHOLD = _int("SUSPICIOUS_THRESHOLD", 30)
    PHISHING_THRESHOLD = _int("PHISHING_THRESHOLD", 70)
    CRITICAL_THRESHOLD = _int("CRITICAL_THRESHOLD", 90)

    # Risk engine weights (must sum to ~1.0)
    RISK_WEIGHTS = {
        "threat_intel": 0.30,
        "url_domain": 0.20,
        "sender_header": 0.15,
        "dynamic_html": 0.15,
        "phishbyte": 0.15,
        "social_engineering": 0.05,
    }

    # App
    APP_HOST = os.environ.get("APP_HOST", "0.0.0.0")
    APP_PORT = _int("APP_PORT", 5000)
    POLL_INTERVAL_SECONDS = _int("POLL_INTERVAL_SECONDS", 5)

    # Storage
    DATA_DIR = BASE_DIR / "data"
    DB_PATH = DATA_DIR / "phishing_detector.db"

    # Dynamic analysis safety limits
    HTTP_TIMEOUT_SECONDS = 6
    MAX_REDIRECTS = 3
    MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MB

    # Simulated organization
    SIMULATED_USERS = [
        "krishnaveni@company.test",
        "user1@company.test",
        "user2@company.test",
        "user3@company.test",
    ]


config = Config()
config.DATA_DIR.mkdir(parents=True, exist_ok=True)
