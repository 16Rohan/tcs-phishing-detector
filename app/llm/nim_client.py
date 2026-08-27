"""NVIDIA NIM explanation generator. Direct HTTP requests only, no LangChain."""
from __future__ import annotations

import logging

import requests

from app.config import config

logger = logging.getLogger("nim_client")

SYSTEM_PROMPT = (
    "You are a security analyst assistant that explains phishing-detection verdicts "
    "to end users in plain, concise language. You are given structured evidence that "
    "was already computed by deterministic and machine-learning detectors. "
    "You do NOT decide the verdict or score — they are provided to you as fact. "
    "Write a short (3-5 sentence) explanation suitable for a non-technical end user "
    "reading a security alert popup. Be specific about which signals matter most. "
    "Do not invent evidence that was not provided."
)


def _build_user_prompt(email_summary: dict, verdict: dict) -> str:
    lines = [
        f"Sender: {email_summary.get('sender')}",
        f"Subject: {email_summary.get('subject')}",
        "",
        f"Classification: {verdict['classification']}",
        f"Risk score: {verdict['risk_score']}/100",
        f"Phish_Byte ML confidence: {round(verdict['phishbyte_confidence'] * 100)}%",
        f"Social engineering confidence: {round(verdict['social_engineering_confidence'] * 100)}%",
        "",
        "Detection signals:",
    ]
    for s in verdict.get("signals", [])[:20]:
        lines.append(f"- {s}")
    return "\n".join(lines)


def _fallback_explanation(verdict: dict) -> str:
    signals = verdict.get("signals", [])
    top_signals = ", ".join(s.replace("_", " ").replace(":", " - ") for s in signals[:5]) or "no strong signals"
    return (
        f"This email was classified as {verdict['classification']} with a risk score of "
        f"{verdict['risk_score']}/100. Key indicators: {top_signals}. "
        f"Phish_Byte model confidence was {round(verdict['phishbyte_confidence'] * 100)}% and "
        f"social-engineering confidence was {round(verdict['social_engineering_confidence'] * 100)}%. "
        f"(Automated fallback explanation — NVIDIA NIM was unavailable.)"
    )


def generate_explanation(email_summary: dict, verdict: dict) -> dict:
    if not config.NVIDIA_API_KEY:
        return {"explanation": _fallback_explanation(verdict), "source": "fallback_no_key"}

    payload = {
        "model": config.NVIDIA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(email_summary, verdict)},
        ],
        "temperature": 0.3,
        "max_tokens": 600,
        # gpt-oss models spend part of the token budget on hidden reasoning before
        # the final answer; "low" keeps that short so replies stay fast and the
        # visible "content" field doesn't get truncated to empty.
        "chat_template_kwargs": {"reasoning_effort": "low"},
    }

    try:
        resp = requests.post(
            f"{config.NVIDIA_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {config.NVIDIA_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        content = (data["choices"][0]["message"].get("content") or "").strip()
        if not content:
            raise ValueError("Empty content in NIM response")
        return {"explanation": content, "source": "nvidia_nim"}
    except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
        logger.warning("NVIDIA NIM unavailable, using fallback explanation: %s", exc)
        return {"explanation": _fallback_explanation(verdict), "source": "fallback_error"}
