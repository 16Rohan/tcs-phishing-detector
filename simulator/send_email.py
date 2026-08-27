"""CLI: send simulated phishing/legitimate emails via SMTP into Mailpit.

Usage:
    python -m simulator.send_email legitimate
    python -m simulator.send_email malicious_url
    python -m simulator.send_email all
"""
from __future__ import annotations

import smtplib
import sys

from app.config import config
from simulator.scenarios import SCENARIOS


def send_raw(raw_email: str, to_addr: str) -> None:
    with smtplib.SMTP(config.MAILPIT_HOST, config.MAILPIT_SMTP_PORT, timeout=10) as smtp:
        smtp.sendmail("simulator@phishing-lab.test", [to_addr], raw_email)


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: python -m simulator.send_email <{'|'.join(SCENARIOS)}|all>")
        sys.exit(1)

    name = sys.argv[1]
    if name == "all":
        for scenario_name, builder in SCENARIOS.items():
            raw = builder()
            to_addr = _extract_to(raw)
            send_raw(raw, to_addr)
            print(f"Sent scenario '{scenario_name}' to {to_addr}")
        return

    builder = SCENARIOS.get(name)
    if not builder:
        print(f"Unknown scenario '{name}'. Available: {', '.join(SCENARIOS)}, all")
        sys.exit(1)

    raw = builder()
    to_addr = _extract_to(raw)
    send_raw(raw, to_addr)
    print(f"Sent scenario '{name}' to {to_addr}")


def _extract_to(raw_email: str) -> str:
    from email import message_from_string
    from email.utils import parseaddr

    msg = message_from_string(raw_email)
    return parseaddr(msg.get("To", ""))[1] or "krishnaveni@company.test"


if __name__ == "__main__":
    main()
