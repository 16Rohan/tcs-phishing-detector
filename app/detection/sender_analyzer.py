"""Static sender / header analysis: spoofing, mismatches, domain reputation."""
from __future__ import annotations

from app.detection.lut import lookup_domain
from app.detection.unicode_analyzer import analyze_domain_unicode
from app.email.parser import ParsedEmail

KNOWN_BRANDS = ["microsoft", "google", "paypal", "apple", "amazon", "bank", "netflix", "office365"]


def analyze_sender(email: ParsedEmail) -> dict:
    signals: list[str] = []
    risk_score = 0

    sender_domain = email.sender_domain
    reply_to_domain = email.reply_to.split("@")[-1].lower() if "@" in email.reply_to else ""
    return_path_domain = email.return_path.split("@")[-1].lower() if "@" in email.return_path else ""

    reply_to_mismatch = bool(reply_to_domain and sender_domain and reply_to_domain != sender_domain)
    if reply_to_mismatch:
        signals.append("reply_to_mismatch")
        risk_score += 20

    return_path_mismatch = bool(
        return_path_domain and sender_domain and return_path_domain != sender_domain
    )
    if return_path_mismatch:
        signals.append("return_path_mismatch")
        risk_score += 10

    display_name = (email.sender_display_name or "").lower()
    display_name_spoof = False
    for brand in KNOWN_BRANDS:
        if brand in display_name and brand not in sender_domain:
            display_name_spoof = True
            signals.append("display_name_spoofing")
            risk_score += 25
            break

    domain_classification = lookup_domain(sender_domain)
    if domain_classification == "MALICIOUS":
        signals.append("known_malicious_sender_domain")
        risk_score += 60
    elif domain_classification == "SUSPICIOUS":
        signals.append("suspicious_sender_domain")
        risk_score += 25
    elif domain_classification == "TRUSTED":
        signals.append("trusted_sender_domain")

    unicode_result = analyze_domain_unicode(sender_domain)
    if unicode_result["anomaly_detected"]:
        signals.append("homoglyph_detected")
        risk_score += 30

    return {
        "sender": email.sender,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "display_name_spoofing": display_name_spoof,
        "domain_classification": domain_classification,
        "unicode_anomaly": unicode_result,
        "signals": signals,
        "risk_score": min(risk_score, 100),
    }
