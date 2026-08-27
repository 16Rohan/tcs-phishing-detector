"""Unicode / homoglyph / punycode detection for domains.

This is an indicator, not an automatic verdict.
"""
from __future__ import annotations

import unicodedata

# Cyrillic / Greek characters commonly used to impersonate Latin look-alikes.
CONFUSABLE_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "һ": "h", "ԁ": "d", "ѡ": "w", "ⅰ": "i",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "κ": "k",
}


def _script_of(char: str) -> str:
    try:
        name = unicodedata.name(char)
    except ValueError:
        return "UNKNOWN"
    if "CYRILLIC" in name:
        return "CYRILLIC"
    if "GREEK" in name:
        return "GREEK"
    if "LATIN" in name:
        return "LATIN"
    return "OTHER"


def analyze_domain_unicode(domain: str) -> dict:
    result = {
        "anomaly_detected": False,
        "reasons": [],
        "is_punycode": False,
        "mixed_script": False,
        "confusable_chars": [],
    }
    if not domain:
        return result

    labels = domain.split(".")
    if any(label.startswith("xn--") for label in labels):
        result["is_punycode"] = True
        result["anomaly_detected"] = True
        result["reasons"].append("Punycode-encoded label detected")

    scripts_seen = set()
    confusables = []
    for char in domain:
        if char.isascii():
            continue
        scripts_seen.add(_script_of(char))
        if char in CONFUSABLE_MAP:
            confusables.append(char)

    if len(scripts_seen - {"UNKNOWN"}) >= 1 and any(c.isascii() and c.isalpha() for c in domain):
        result["mixed_script"] = True
        result["anomaly_detected"] = True
        result["reasons"].append("Mixed Latin/non-Latin scripts in domain")

    if confusables:
        result["confusable_chars"] = confusables
        result["anomaly_detected"] = True
        result["reasons"].append(
            f"Visually confusable characters resembling Latin letters: {confusables}"
        )

    return result
