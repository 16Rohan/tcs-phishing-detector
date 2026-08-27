"""Content analysis: social-engineering signal scoring + Phish_Byte ML invocation."""
from __future__ import annotations

import logging
import re

from app.email.parser import ParsedEmail

logger = logging.getLogger("content_analyzer")

URGENCY_KEYWORDS = [
    "urgent", "immediately", "right away", "as soon as possible", "act now",
    "within 24 hours", "expire", "final notice", "last chance", "asap",
]
FEAR_KEYWORDS = [
    "suspended", "suspend your account", "locked", "unauthorized access",
    "unusual activity", "compromised", "security alert", "closed permanently",
    "legal action", "penalty",
]
AUTHORITY_KEYWORDS = [
    "it department", "security team", "administrator", "support team",
    "help desk", "official notice", "compliance", "hr department",
]
FINANCIAL_KEYWORDS = [
    "invoice", "payment", "refund", "bank account", "wire transfer",
    "tax", "billing", "overdue",
]
CREDENTIAL_REQUEST_KEYWORDS = [
    "verify your password", "confirm your password", "enter your credentials",
    "update your password", "verify your identity", "confirm your account",
    "click here to verify", "log in to verify", "provide your login",
]
REWARD_KEYWORDS = [
    "you have won", "claim your prize", "congratulations", "lottery",
    "free gift", "reward", "selected winner",
]

SIGNAL_WEIGHTS = {
    "urgency": 0.20,
    "fear": 0.20,
    "authority": 0.10,
    "financial_pressure": 0.15,
    "credential_request": 0.20,
    "reward_claim": 0.10,
    "deadline": 0.05,
}

DEADLINE_REGEX = re.compile(
    r"\b(within \d+\s*(hours|hrs|days|minutes)|by (today|tomorrow|end of day|midnight))\b",
    re.IGNORECASE,
)


def _count_hits(text: str, keywords: list[str]) -> int:
    text_lower = text.lower()
    return sum(1 for kw in keywords if kw in text_lower)


def analyze_social_engineering(email: ParsedEmail) -> dict:
    combined_text = f"{email.subject}\n{email.text_body}\n{email.html_body}"
    if not combined_text.strip():
        return {"social_engineering_confidence": 0.0, "signals": []}

    signals = []
    score = 0.0

    urgency_hits = _count_hits(combined_text, URGENCY_KEYWORDS)
    if urgency_hits:
        signals.append("urgency")
        score += SIGNAL_WEIGHTS["urgency"] * min(urgency_hits / 2, 1.0)

    fear_hits = _count_hits(combined_text, FEAR_KEYWORDS)
    if fear_hits:
        signals.append("fear_or_threat")
        score += SIGNAL_WEIGHTS["fear"] * min(fear_hits / 2, 1.0)

    authority_hits = _count_hits(combined_text, AUTHORITY_KEYWORDS)
    if authority_hits:
        signals.append("authority_impersonation")
        score += SIGNAL_WEIGHTS["authority"] * min(authority_hits / 2, 1.0)

    financial_hits = _count_hits(combined_text, FINANCIAL_KEYWORDS)
    if financial_hits:
        signals.append("financial_pressure")
        score += SIGNAL_WEIGHTS["financial_pressure"] * min(financial_hits / 2, 1.0)

    credential_hits = _count_hits(combined_text, CREDENTIAL_REQUEST_KEYWORDS)
    if credential_hits:
        signals.append("credential_request")
        score += SIGNAL_WEIGHTS["credential_request"] * min(credential_hits / 2, 1.0)

    reward_hits = _count_hits(combined_text, REWARD_KEYWORDS)
    if reward_hits:
        signals.append("reward_or_prize_claim")
        score += SIGNAL_WEIGHTS["reward_claim"] * min(reward_hits / 2, 1.0)

    if DEADLINE_REGEX.search(combined_text):
        signals.append("artificial_deadline")
        score += SIGNAL_WEIGHTS["deadline"]

    confidence = round(min(score, 1.0), 4)
    return {"social_engineering_confidence": confidence, "signals": signals}


# ---------------------------------------------------------------------------
# Phish_Byte ML integration
# ---------------------------------------------------------------------------

_phishbyte_engine = None
_phishbyte_load_attempted = False


def _load_phishbyte_engine():
    global _phishbyte_engine, _phishbyte_load_attempted
    if _phishbyte_load_attempted:
        return _phishbyte_engine
    _phishbyte_load_attempted = True
    try:
        from phishbyte import PhishByteEngine  # type: ignore

        _phishbyte_engine = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
        logger.info("Phish_Byte pretrained engine loaded successfully.")
    except Exception as exc:
        logger.warning(
            "Phish_Byte engine unavailable (%s). Falling back to heuristic ML substitute.", exc
        )
        _phishbyte_engine = None
    return _phishbyte_engine


def _normalize_phishbyte_output(raw_output) -> dict:
    """Adapt whatever shape the upstream repo returns into {label, confidence}."""
    if isinstance(raw_output, dict):
        label = raw_output.get("label") or raw_output.get("verdict") or raw_output.get("classification")
        confidence = raw_output.get("confidence") or raw_output.get("score") or raw_output.get("probability")
    else:
        label = getattr(raw_output, "label", None) or getattr(raw_output, "verdict", None)
        confidence = getattr(raw_output, "confidence", None) or getattr(raw_output, "score", None)

    if confidence is None:
        confidence = 0.0
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0
    if confidence > 1.0:
        confidence = confidence / 100.0

    label = str(label).lower() if label else ("phishing" if confidence >= 0.5 else "legitimate")
    return {"label": label, "confidence": round(confidence, 4)}


_HEURISTIC_ML_KEYWORDS = (
    URGENCY_KEYWORDS + FEAR_KEYWORDS + CREDENTIAL_REQUEST_KEYWORDS + REWARD_KEYWORDS
)


def _heuristic_phishbyte_fallback(raw_email: str) -> dict:
    """Deterministic keyword/structure heuristic used only when the pretrained
    Phish_Byte model cannot be loaded (e.g. offline hackathon environment).
    This is explicitly a fallback signal, not a replacement model."""
    text_lower = raw_email.lower()
    hits = sum(1 for kw in _HEURISTIC_ML_KEYWORDS if kw in text_lower)
    has_ip_url = bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text_lower))
    has_login_form_hint = "type=\"password\"" in text_lower or "type='password'" in text_lower

    score = min(hits * 0.08, 0.7)
    if has_ip_url:
        score += 0.15
    if has_login_form_hint:
        score += 0.15
    confidence = round(min(score, 0.97), 4)
    label = "phishing" if confidence >= 0.5 else "legitimate"
    return {"label": label, "confidence": confidence}


def run_phishbyte_analysis(raw_email: str) -> dict:
    engine = _load_phishbyte_engine()
    if engine is None:
        result = _heuristic_phishbyte_fallback(raw_email)
        result["engine"] = "heuristic_fallback"
        return result
    try:
        verdict = engine.analyze(raw_email)
        result = _normalize_phishbyte_output(verdict)
        result["engine"] = "phishbyte_pretrained"
        return result
    except Exception as exc:
        logger.warning("Phish_Byte analysis failed at runtime (%s); using heuristic fallback.", exc)
        result = _heuristic_phishbyte_fallback(raw_email)
        result["engine"] = "heuristic_fallback_runtime_error"
        return result
