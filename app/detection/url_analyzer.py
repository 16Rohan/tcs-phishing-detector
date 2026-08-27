"""Static + threat-intel URL analysis: heuristics, LUT, Safe Browsing."""
from __future__ import annotations

import re

from app.detection.lut import lookup_domain, upsert_ioc
from app.detection.safe_browsing import check_url
from app.detection.unicode_analyzer import analyze_domain_unicode
from app.email.parser import ExtractedUrl

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "loan", "click", "gq", "tk", "ml", "cf", "work", "zip"}
CREDENTIAL_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "account", "secure", "update",
    "password", "confirm", "banking", "authenticate", "reset",
]
IP_URL_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _is_ip(domain: str) -> bool:
    return bool(IP_URL_REGEX.match(domain))


def _tld_of(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return parts[-1].lower() if len(parts) > 1 else ""


def _subdomain_count(domain: str) -> int:
    return max(domain.count(".") - 1, 0)


def analyze_url(extracted: ExtractedUrl, sender_domain: str = "") -> dict:
    signals: list[str] = []
    risk_score = 0
    url = extracted.original_url
    domain = extracted.domain

    if extracted.scheme != "https":
        signals.append("non_https_url")
        risk_score += 10

    if _is_ip(domain):
        signals.append("ip_based_url")
        risk_score += 30

    if domain in SHORTENER_DOMAINS:
        signals.append("url_shortener")
        risk_score += 15

    if _subdomain_count(domain) >= 3:
        signals.append("excessive_subdomains")
        risk_score += 15

    if domain.count("-") >= 3:
        signals.append("excessive_hyphens")
        risk_score += 10

    if _tld_of(domain) in SUSPICIOUS_TLDS:
        signals.append("suspicious_tld")
        risk_score += 15

    if len(url) > 100:
        signals.append("long_url")
        risk_score += 5

    lowered_path = url.lower()
    if any(kw in lowered_path for kw in CREDENTIAL_KEYWORDS):
        signals.append("credential_related_path")
        risk_score += 10

    unicode_result = analyze_domain_unicode(domain)
    if unicode_result["anomaly_detected"]:
        signals.append("homoglyph_detected")
        risk_score += 30

    if extracted.anchor_text:
        anchor_lower = extracted.anchor_text.lower()
        if ("http" in anchor_lower or "www." in anchor_lower or "." in anchor_lower) and domain not in anchor_lower:
            signals.append("anchor_text_mismatch")
            risk_score += 20

    if sender_domain and domain and sender_domain != domain and domain not in sender_domain:
        known_brand_terms = ["microsoft", "google", "paypal", "apple", "amazon", "bank"]
        if any(term in sender_domain for term in known_brand_terms) or any(
            term in extracted.anchor_text.lower() for term in known_brand_terms
        ):
            signals.append("sender_domain_mismatch")
            risk_score += 15

    lut_classification = lookup_domain(domain)
    if lut_classification == "MALICIOUS":
        signals.append("known_malicious_domain")
        risk_score += 70
    elif lut_classification == "SUSPICIOUS":
        signals.append("suspicious_lut_domain")
        risk_score += 25

    sb_result = {"checked": False, "malicious": False, "source": "not_queried"}
    should_query_safe_browsing = lut_classification == "UNKNOWN" and extracted.scheme in ("http", "https")
    if should_query_safe_browsing:
        sb_result = check_url(url)
        if sb_result["malicious"]:
            signals.append("google_safe_browsing_match")
            risk_score += 70
            upsert_ioc(domain, "domain", "MALICIOUS", "google_safe_browsing")
            upsert_ioc(url, "url", "MALICIOUS", "google_safe_browsing")

    return {
        "url": url,
        "domain": domain,
        "scheme": extracted.scheme,
        "anchor_text": extracted.anchor_text,
        "source": extracted.source,
        "lut_classification": lut_classification,
        "safe_browsing": sb_result,
        "unicode_anomaly": unicode_result,
        "signals": signals,
        "risk_score": min(risk_score, 100),
        "requires_dynamic_analysis": risk_score >= 20 and not sb_result.get("malicious"),
    }


def analyze_urls(urls: list[ExtractedUrl], sender_domain: str = "") -> list[dict]:
    return [analyze_url(u, sender_domain) for u in urls]
