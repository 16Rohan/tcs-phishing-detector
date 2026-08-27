"""Run every demo attack scenario back-to-back and print a summary table.

Usage:
    uv run python -m demo.run_all
"""
from __future__ import annotations

import time
from email import message_from_string

from demo import emails
from demo.common import app_is_up, deliver_via_api, deliver_via_mailpit, mailpit_is_up

SCENARIOS = [
    ("Legitimate email (control)", emails.legitimate_baseline),
    ("Social engineering (urgency/fear)", emails.social_engineering_urgency),
    ("Known-malicious URL", emails.malicious_url_threat_intel),
    ("Homoglyph domain spoofing", emails.homoglyph_domain_spoofing),
    ("Link/anchor-text mismatch", emails.link_domain_mismatch),
    ("Credential-harvesting page", emails.credential_harvesting_page),
    ("Display-name brand impersonation", emails.display_name_brand_impersonation),
]


def _subject_of(raw_email: str) -> str:
    return str(message_from_string(raw_email).get("Subject", ""))


def main() -> None:
    if not app_is_up():
        print("The web application is not running. Start it first with: uv run python main.py")
        return

    use_mailpit = mailpit_is_up()
    print(f"Delivery path: {'Mailpit SMTP (realistic)' if use_mailpit else 'direct API (Mailpit not running)'}")
    print()

    rows: list[tuple[str, dict | None]] = []
    subject_by_label = {}
    for label, builder in SCENARIOS:
        raw = builder()
        subject_by_label[label] = _subject_of(raw)
        print(f"-> Sending: {label}")
        if use_mailpit:
            deliver_via_mailpit(raw)
        else:
            rows.append((label, deliver_via_api(raw)))
        time.sleep(1)

    if use_mailpit:
        print("\nAll scenarios delivered via Mailpit. Waiting for the background "
              "interceptor to process the queue (each email involves live HTTP "
              "and LLM calls, so this can take a couple of minutes)...")
        import requests

        wanted_subjects = set(subject_by_label.values())
        by_subject: dict = {}
        for _ in range(60):  # up to ~2 minutes
            recent = requests.get("http://localhost:5000/api/recent", timeout=5).json()
            by_subject = {r.get("subject"): r for r in recent}
            if wanted_subjects <= by_subject.keys():
                break
            time.sleep(2)
        rows = [(label, by_subject.get(subject_by_label[label])) for label, _ in SCENARIOS]

    print("\n" + "=" * 90)
    print(f"{'Scenario':38s} {'Classification':20s} {'Score':>6s}  Final state")
    print("=" * 90)
    for label, result in rows:
        if not result:
            print(f"{label:38s} {'(no result yet)':20s}")
            continue
        print(
            f"{label[:38]:38s} {result.get('classification', '?'):20s} "
            f"{str(result.get('risk_score', '?')):>5}   {result.get('final_state', '?')}"
        )

    print("\nOpen the live dashboard: http://localhost:5000/")


if __name__ == "__main__":
    main()
