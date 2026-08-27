"""Central orchestrator implementing the email-processing state machine.

RECEIVED -> PARSED -> STATIC_ANALYSIS -> [FLAGGED] -> DYNAMIC_ANALYSIS -> ML_ANALYSIS
-> SOCIAL_ENGINEERING_ANALYSIS -> FINAL_VERDICT (risk engine) -> LLM_EXPLANATION
-> DELIVERED / WARNING / QUARANTINED -> POST_DETECTION
"""
from __future__ import annotations

import itertools
import logging
import threading
import time
import uuid

from app.config import config
from app.containment.containment_engine import run_containment
from app.detection.content_analyzer import analyze_social_engineering, run_phishbyte_analysis
from app.detection.dynamic_analyzer import run_dynamic_analysis
from app.detection.static_analyzer import run_static_analysis
from app.email.mailpit import MailpitClient
from app.email.parser import parse_email
from app.incident.incident_manager import (
    create_incident,
    find_affected_users,
    mark_users_at_risk,
    save_email_record,
    save_urls,
    update_incident_affected_users,
)
from app.incident.ioc_extractor import extract_and_store_iocs
from app.llm.nim_client import generate_explanation
from app.risk.risk_engine import compute_final_verdict

logger = logging.getLogger("interceptor")

_processed_message_ids: set[str] = set()
_processing_lock = threading.Lock()
_counter = itertools.count(1)

# In-memory feed of recent processing results for the dashboard / live popup.
_recent_results: list[dict] = []
_MAX_RECENT = 100


def get_recent_results() -> list[dict]:
    with _processing_lock:
        return list(reversed(_recent_results))


def _log_state(processing_id: str, state_name: str, **extra) -> None:
    logger.info("[%s] %s %s", processing_id, state_name, extra if extra else "")


def process_raw_email(raw_email: str) -> dict:
    processing_id = f"EMAIL-{next(_counter):06d}"
    _log_state(processing_id, "RECEIVED")

    email = parse_email(raw_email)
    _log_state(processing_id, "PARSED", sender=email.sender, subject=email.subject)
    if email.parse_errors:
        logger.warning("[%s] Parse errors: %s", processing_id, email.parse_errors)

    static_result = run_static_analysis(email)
    _log_state(processing_id, "STATIC_ANALYSIS", status=static_result["status"], score=static_result["risk_score"])

    dynamic_result = None
    if static_result["status"] != "flagged" and static_result.get("requires_dynamic_analysis"):
        urls_to_check = [
            u["url"] for u in static_result["url_analysis"] if u.get("requires_dynamic_analysis")
        ][:5]
        dynamic_result = run_dynamic_analysis(urls_to_check)
        _log_state(processing_id, "DYNAMIC_ANALYSIS", score=dynamic_result["risk_score"])

    phishbyte_result = run_phishbyte_analysis(raw_email)
    _log_state(processing_id, "ML_ANALYSIS", confidence=phishbyte_result["confidence"], engine=phishbyte_result["engine"])

    social_result = analyze_social_engineering(email)
    _log_state(
        processing_id, "SOCIAL_ENGINEERING_ANALYSIS",
        confidence=social_result["social_engineering_confidence"],
    )

    verdict = compute_final_verdict(static_result, dynamic_result, phishbyte_result, social_result)
    _log_state(processing_id, "RISK_CALCULATED", classification=verdict["classification"], score=verdict["risk_score"])

    llm_result = generate_explanation(
        {"sender": email.sender, "subject": email.subject}, verdict
    )
    verdict["explanation"] = llm_result["explanation"]
    verdict["explanation_source"] = llm_result["source"]
    _log_state(processing_id, "LLM_EXPLANATION", source=llm_result["source"])

    final_state = {
        "LEGITIMATE": "DELIVERED",
        "SUSPICIOUS": "WARNING",
        "PHISHING": "QUARANTINED",
        "CRITICAL PHISHING": "QUARANTINED",
    }.get(verdict["classification"], "WARNING")
    _log_state(processing_id, "FINAL_VERDICT", state=final_state)

    email_id = save_email_record(email, verdict, processing_id)
    save_urls(email_id, static_result.get("url_analysis", []))

    incident_id = None
    affected_users: list[str] = []
    containment_result = None
    if final_state in ("QUARANTINED", "WARNING"):
        iocs = extract_and_store_iocs(email, static_result, verdict)
        incident_id = create_incident(email_id, verdict, verdict["explanation"])
        _log_state(processing_id, "INCIDENT_CREATED", incident_id=incident_id, iocs=len(iocs))

        affected_users = find_affected_users(email.sender)
        if email.recipient and email.recipient not in affected_users:
            affected_users.append(email.recipient)
        risk_level = "CRITICAL" if final_state == "QUARANTINED" and verdict["classification"] == "CRITICAL PHISHING" else "HIGH"
        mark_users_at_risk(affected_users, risk_level)
        update_incident_affected_users(incident_id, affected_users)

        if final_state == "QUARANTINED":
            containment_result = run_containment(affected_users, verdict, dynamic_result)
            _log_state(processing_id, "POST_DETECTION", stage=containment_result["stage"])

    result = {
        "processing_id": processing_id,
        "email_id": email_id,
        "incident_id": incident_id,
        "sender": email.sender,
        "recipient": email.recipient,
        "subject": email.subject,
        "final_state": final_state,
        "static_analysis": static_result,
        "dynamic_analysis": dynamic_result,
        "phishbyte": phishbyte_result,
        "social_engineering": social_result,
        "verdict": verdict,
        "affected_users": affected_users,
        "containment": containment_result,
    }

    with _processing_lock:
        _recent_results.append(result)
        if len(_recent_results) > _MAX_RECENT:
            _recent_results.pop(0)

    return result


def poll_mailpit_once(client: MailpitClient | None = None) -> list[dict]:
    client = client or MailpitClient()
    if not client.is_available():
        logger.debug("Mailpit not reachable; skipping poll cycle.")
        return []

    results = []
    for message in client.list_messages():
        message_id = message.get("ID") or message.get("id")
        if not message_id:
            continue
        with _processing_lock:
            if message_id in _processed_message_ids:
                continue
            _processed_message_ids.add(message_id)

        raw = client.get_raw_message(message_id)
        if raw is None:
            continue
        try:
            result = process_raw_email(raw)
            results.append(result)
        except Exception:
            logger.exception("Unhandled error processing message %s", message_id)
        finally:
            client.mark_read(message_id)

    return results


def run_polling_loop(stop_event: threading.Event) -> None:
    client = MailpitClient()
    logger.info("Interceptor polling loop started (interval=%ss)", config.POLL_INTERVAL_SECONDS)
    while not stop_event.is_set():
        try:
            poll_mailpit_once(client)
        except Exception:
            logger.exception("Unhandled error in polling loop")
        stop_event.wait(config.POLL_INTERVAL_SECONDS)


def start_background_poller() -> threading.Event:
    stop_event = threading.Event()
    thread = threading.Thread(target=run_polling_loop, args=(stop_event,), daemon=True)
    thread.start()
    return stop_event
