"""Shared helpers for the demo attack scripts.

Each demo script builds a realistic malicious email, delivers it through the same
path a real attacker would use (SMTP into Mailpit), waits for the background
interceptor to process it, and then prints a summary while pointing the operator
to the live result on the web dashboard / alert popup.
"""
from __future__ import annotations

import smtplib
import sys
import time
from email import message_from_string
from email.utils import parseaddr

import requests

APP_BASE = "http://localhost:5000"
MAILPIT_HOST = "localhost"
MAILPIT_SMTP_PORT = 1025
MAILPIT_API_BASE = "http://localhost:8025/api/v1"


def _to_addr(raw_email: str) -> str:
    msg = message_from_string(raw_email)
    return parseaddr(msg.get("To", ""))[1] or "krishnaveni@company.test"


def app_is_up() -> bool:
    try:
        return requests.get(APP_BASE + "/", timeout=3).status_code == 200
    except requests.RequestException:
        return False


def mailpit_is_up() -> bool:
    try:
        return requests.get(MAILPIT_API_BASE + "/info", timeout=3).status_code == 200
    except requests.RequestException:
        return False


def deliver_via_mailpit(raw_email: str) -> str:
    to_addr = _to_addr(raw_email)
    with smtplib.SMTP(MAILPIT_HOST, MAILPIT_SMTP_PORT, timeout=10) as smtp:
        smtp.sendmail("attacker@demo-lab.test", [to_addr], raw_email)
    return to_addr


def deliver_via_api(raw_email: str) -> dict:
    """Fallback path used when Mailpit isn't running: hand the raw email straight
    to the detection pipeline through the app's own HTTP API."""
    resp = requests.post(APP_BASE + "/api/process-raw", json={"raw_email": raw_email}, timeout=60)
    resp.raise_for_status()
    return resp.json()


def find_result_for_subject(subject: str, retries: int = 10, delay: float = 1.5) -> dict | None:
    for _ in range(retries):
        try:
            resp = requests.get(APP_BASE + "/api/recent", timeout=5)
            resp.raise_for_status()
            for r in resp.json():
                if r.get("subject") == subject:
                    return r
        except requests.RequestException:
            pass
        time.sleep(delay)
    return None


def print_banner(title: str) -> None:
    print("=" * 70)
    print(title)
    print("=" * 70)


def print_result(result: dict, email_id: int | None = None) -> None:
    if not result:
        print("No result yet — the background poller may still be processing. "
              "Check the dashboard manually.")
        return
    print(f"Classification : {result.get('classification')}")
    print(f"Risk score     : {result.get('risk_score')}/100")
    print(f"Final state    : {result.get('final_state')}")
    print(f"Phish_Byte     : {round((result.get('phishbyte_confidence') or 0) * 100)}%")
    print(f"Social eng.    : {round((result.get('social_engineering_confidence') or 0) * 100)}%")
    print("Signals        :")
    for s in (result.get("signals") or [])[:10]:
        print(f"  - {s}")
    source = result.get("explanation_source", "unknown")
    tag = "LIVE NVIDIA NIM CALL" if source == "nvidia_nim" else f"fallback ({source})"
    print(f"Explanation [{tag}]:")
    print(f"  {result.get('explanation')}")
    eid = email_id or result.get("email_id")
    if eid:
        print()
        print(f"View live alert popup: {APP_BASE}/alert/{eid}")
    print(f"View full dashboard  : {APP_BASE}/")


def run_scenario(subject_hint: str, raw_email: str) -> None:
    if mailpit_is_up():
        to_addr = deliver_via_mailpit(raw_email)
        print(f"Delivered via Mailpit SMTP to {to_addr}. Waiting for the background interceptor...")
        result = find_result_for_subject(subject_hint)
        print_result(result)
    elif app_is_up():
        print("Mailpit is not running — submitting the email directly to the detection API instead.")
        result = deliver_via_api(raw_email)
        print_result(result)
    else:
        print("Neither Mailpit nor the web application appear to be running.")
        print("Start them first:")
        print("  mailpit --smtp 0.0.0.0:1025 --listen 0.0.0.0:8025")
        print("  uv run python main.py")
        sys.exit(1)
