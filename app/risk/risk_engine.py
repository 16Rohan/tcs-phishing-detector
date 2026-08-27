"""Final decision-maker: combines deterministic + ML signals into a risk score.

MUST NOT call the LLM. The LLM only explains what this engine has already decided.
"""
from __future__ import annotations

from app.config import config

DETERMINISTIC_OVERRIDE_SIGNALS = {
    "known_malicious_domain",
    "known_malicious_sender_domain",
    "google_safe_browsing_match",
}
DETERMINISTIC_OVERRIDE_SCORE = 95


def classify(score: int) -> str:
    if score >= config.CRITICAL_THRESHOLD:
        return "CRITICAL PHISHING"
    if score >= config.PHISHING_THRESHOLD:
        return "PHISHING"
    if score >= config.SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "LEGITIMATE"


def compute_final_verdict(
    static_result: dict,
    dynamic_result: dict | None,
    phishbyte_result: dict,
    social_result: dict,
) -> dict:
    weights = config.RISK_WEIGHTS

    threat_intel_score = 0
    all_static_signals = set(static_result.get("signals", []))
    flat_signals = {s.split(":", 1)[-1] for s in all_static_signals}
    if flat_signals & DETERMINISTIC_OVERRIDE_SIGNALS:
        threat_intel_score = 100
    else:
        for u in static_result.get("url_analysis", []):
            if u["safe_browsing"].get("malicious") or u["lut_classification"] == "MALICIOUS":
                threat_intel_score = max(threat_intel_score, 100)
        if "homoglyph_detected" in flat_signals or "display_name_spoofing" in flat_signals:
            # Brand impersonation — via confusable Unicode or a spoofed display
            # name — is itself a strong, deterministic-style indicator even
            # absent an external LUT/API match.
            threat_intel_score = max(threat_intel_score, 45)

    url_domain_score = max(
        (u["risk_score"] for u in static_result.get("url_analysis", [])), default=0
    )
    sender_score = static_result.get("sender_analysis", {}).get("risk_score", 0)
    dynamic_score = (dynamic_result or {}).get("risk_score", 0)
    phishbyte_confidence = phishbyte_result.get("confidence", 0.0)
    phishbyte_score = phishbyte_confidence * 100
    social_confidence = social_result.get("social_engineering_confidence", 0.0)
    social_score = social_confidence * 100

    weighted = (
        threat_intel_score * weights["threat_intel"]
        + url_domain_score * weights["url_domain"]
        + sender_score * weights["sender_header"]
        + dynamic_score * weights["dynamic_html"]
        + phishbyte_score * weights["phishbyte"]
        + social_score * weights["social_engineering"]
    )
    risk_score = round(min(weighted, 100))

    deterministic_override = False
    if flat_signals & DETERMINISTIC_OVERRIDE_SIGNALS and risk_score < DETERMINISTIC_OVERRIDE_SCORE:
        risk_score = DETERMINISTIC_OVERRIDE_SCORE
        deterministic_override = True

    classification = classify(risk_score)

    signals = list(static_result.get("signals", []))
    if dynamic_result:
        signals.extend(f"dynamic:{s}" for s in dynamic_result.get("signals", []))
    signals.extend(f"social:{s}" for s in social_result.get("signals", []))
    if phishbyte_result.get("label") == "phishing":
        signals.append(f"phishbyte:phishing_confidence_{round(phishbyte_confidence * 100)}pct")

    return {
        "classification": classification,
        "risk_score": risk_score,
        "phishbyte_confidence": round(phishbyte_confidence, 4),
        "social_engineering_confidence": round(social_confidence, 4),
        "signals": signals,
        "deterministic_override": deterministic_override,
        "component_scores": {
            "threat_intel": threat_intel_score,
            "url_domain": url_domain_score,
            "sender_header": sender_score,
            "dynamic_html": dynamic_score,
            "phishbyte": round(phishbyte_score, 2),
            "social_engineering": round(social_score, 2),
        },
    }
