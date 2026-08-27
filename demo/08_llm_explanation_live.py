"""Demo: prove the NVIDIA NIM call is real, live, and fast.

This bypasses the full detection pipeline and calls app.llm.nim_client
directly with a pre-built verdict, so you can show the jury the exact
request going out over HTTPS to https://integrate.api.nvidia.com/v1 and the
model's response coming back — no Mailpit, no dashboard, just the LLM call.

Usage:
    uv run python -m demo.08_llm_explanation_live
"""
from __future__ import annotations

import time

from app.config import config
from app.llm.nim_client import generate_explanation

SAMPLE_EMAIL = {
    "sender": "delivery@shipping-notice.top",
    "subject": "Delivery Failed - Action Required",
}

SAMPLE_VERDICT = {
    "classification": "CRITICAL PHISHING",
    "risk_score": 95,
    "phishbyte_confidence": 0.62,
    "social_engineering_confidence": 0.31,
    "signals": [
        "url:non_https_url",
        "url:suspicious_tld",
        "url:credential_related_path",
        "url:known_malicious_domain",
        "dynamic:dynamic_fetch_failed",
    ],
}


def main() -> None:
    print("=" * 70)
    print("DEMO 8 — Live NVIDIA NIM explanation call")
    print("=" * 70)
    print(f"Endpoint : {config.NVIDIA_BASE_URL}/chat/completions")
    print(f"Model    : {config.NVIDIA_MODEL}")
    print(f"API key  : {'set (' + config.NVIDIA_API_KEY[:8] + '...)' if config.NVIDIA_API_KEY else 'MISSING'}")
    print()
    print("Sending structured evidence (already decided by the risk engine) and")
    print("asking NVIDIA NIM to write the end-user-facing explanation...\n")

    t0 = time.perf_counter()
    result = generate_explanation(SAMPLE_EMAIL, SAMPLE_VERDICT)
    elapsed = time.perf_counter() - t0

    print(f"Response received in {elapsed:.2f}s")
    print(f"Source: {result['source']} "
          f"({'REAL live call to NVIDIA NIM' if result['source'] == 'nvidia_nim' else 'fallback — NIM was unreachable'})")
    print()
    print("Explanation returned by the model:")
    print("-" * 70)
    print(result["explanation"])
    print("-" * 70)

    if result["source"] != "nvidia_nim":
        print("\nNote: this ran the graceful-degradation fallback path, not a live "
              "call. Check NVIDIA_API_KEY / network connectivity in .env if you "
              "expected a live response.")


if __name__ == "__main__":
    main()
