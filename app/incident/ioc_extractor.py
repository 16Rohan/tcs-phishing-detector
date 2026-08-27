"""Extract reusable indicators of compromise from a processed email."""
from __future__ import annotations

from app.detection.lut import upsert_domain, upsert_ioc
from app.email.parser import ParsedEmail


def extract_and_store_iocs(email: ParsedEmail, static_result: dict, verdict: dict) -> list[dict]:
    """Persist sender/domain/URL IOCs when the verdict is PHISHING or CRITICAL PHISHING."""
    iocs = []
    if verdict["classification"] not in ("PHISHING", "CRITICAL PHISHING"):
        return iocs

    if email.sender_domain:
        upsert_domain(
            email.sender_domain, "MALICIOUS", "incident_detection",
            f"Sender of confirmed {verdict['classification']} email",
        )
        upsert_ioc(email.sender_domain, "domain", "MALICIOUS", "incident_detection")
        iocs.append({"indicator": email.sender_domain, "type": "domain"})

    if email.sender:
        upsert_ioc(email.sender, "email_address", "MALICIOUS", "incident_detection")
        iocs.append({"indicator": email.sender, "type": "email_address"})

    for url_result in static_result.get("url_analysis", []):
        if url_result["risk_score"] >= 40:
            upsert_domain(
                url_result["domain"], "MALICIOUS", "incident_detection",
                f"URL domain implicated in {verdict['classification']} email",
            )
            upsert_ioc(url_result["domain"], "domain", "MALICIOUS", "incident_detection")
            upsert_ioc(url_result["url"], "url", "MALICIOUS", "incident_detection")
            iocs.append({"indicator": url_result["url"], "type": "url"})

    return iocs
