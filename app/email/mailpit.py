"""Mailpit HTTP API client: list messages, fetch raw source, mark read."""
from __future__ import annotations

import logging

import requests

from app.config import config

logger = logging.getLogger("mailpit")


class MailpitClient:
    def __init__(self, api_base: str | None = None, timeout: int = 5):
        self.api_base = (api_base or config.MAILPIT_API_BASE).rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            resp = requests.get(f"{self.api_base}/info", timeout=self.timeout)
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def list_messages(self, limit: int = 50) -> list[dict]:
        try:
            resp = requests.get(
                f"{self.api_base}/messages", params={"limit": limit}, timeout=self.timeout
            )
            resp.raise_for_status()
            return resp.json().get("messages", [])
        except requests.RequestException as exc:
            logger.warning("Mailpit unavailable while listing messages: %s", exc)
            return []

    def get_raw_message(self, message_id: str) -> str | None:
        try:
            resp = requests.get(f"{self.api_base}/message/{message_id}/raw", timeout=self.timeout)
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as exc:
            logger.warning("Mailpit unavailable while fetching message %s: %s", message_id, exc)
            return None

    def mark_read(self, message_id: str) -> None:
        try:
            requests.put(
                f"{self.api_base}/message/{message_id}/read", timeout=self.timeout
            )
        except requests.RequestException as exc:
            logger.warning("Failed to mark message %s read: %s", message_id, exc)
