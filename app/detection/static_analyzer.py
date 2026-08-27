"""Coordinates sender/header, URL and Unicode static analysis (no network requests to
the suspicious destination itself — Safe Browsing is threat-intel, not visiting the site)."""
from __future__ import annotations

from app.detection.sender_analyzer import analyze_sender
from app.detection.url_analyzer import analyze_urls
from app.email.parser import ParsedEmail

# Strong deterministic evidence that should short-circuit straight to FLAGGED.
IMMEDIATE_FLAG_SIGNALS = {
    "known_malicious_sender_domain",
    "known_malicious_domain",
    "google_safe_browsing_match",
}
IMMEDIATE_FLAG_MIN_SCORE = 85


def run_static_analysis(email: ParsedEmail) -> dict:
    sender_result = analyze_sender(email)
    url_results = analyze_urls(email.urls, sender_domain=email.sender_domain)

    all_signals = list(sender_result["signals"])
    for u in url_results:
        all_signals.extend(f"url:{s}" for s in u["signals"])

    url_risk = max((u["risk_score"] for u in url_results), default=0)
    combined_score = round(min(sender_result["risk_score"] * 0.5 + url_risk * 0.5, 100))

    has_immediate_signal = bool(IMMEDIATE_FLAG_SIGNALS & set(sender_result["signals"])) or any(
        set(u["signals"]) & IMMEDIATE_FLAG_SIGNALS for u in url_results
    )
    flagged = has_immediate_signal and combined_score >= IMMEDIATE_FLAG_MIN_SCORE

    status = "flagged" if flagged else ("suspicious" if combined_score >= 30 else "pass")

    return {
        "status": status,
        "flagged": flagged,
        "risk_score": combined_score,
        "sender_analysis": sender_result,
        "url_analysis": url_results,
        "signals": all_signals,
        "requires_dynamic_analysis": not flagged and any(
            u.get("requires_dynamic_analysis") for u in url_results
        ),
    }
