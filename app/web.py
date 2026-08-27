"""Flask web application: dashboard, simulated end-user alert popup, and a minimal
simulated identity-service demo UI. Server-rendered with Jinja2 (no SPA framework)."""
from __future__ import annotations

import logging

from flask import Flask, jsonify, render_template, request

from app.containment import identity_service
from app.db import cursor, init_db
from app.email.interceptor import get_recent_results, poll_mailpit_once, process_raw_email
from app.email.mailpit import MailpitClient

logger = logging.getLogger("web")


def create_app() -> Flask:
    app = Flask(__name__, template_folder="../frontend/templates", static_folder="../frontend/static")
    init_db()

    @app.get("/")
    def dashboard():
        with cursor() as cur:
            cur.execute(
                """SELECT e.id, e.sender, e.recipient, e.subject, e.classification,
                          e.risk_score, e.received_at, e.processing_id, i.id as incident_id, i.severity
                   FROM emails e LEFT JOIN incidents i ON i.email_id = e.id
                   ORDER BY e.id DESC LIMIT 100"""
            )
            emails = [dict(row) for row in cur.fetchall()]

            cur.execute("SELECT domain, classification, source, reason FROM domains ORDER BY id DESC LIMIT 50")
            domains = [dict(row) for row in cur.fetchall()]

            cur.execute("SELECT email, status, risk_level FROM users ORDER BY id")
            users = [dict(row) for row in cur.fetchall()]

            # Organization Summary Statistics
            total_emails = len(emails)
            phishing_count = sum(1 for e in emails if e.get("classification") in ("PHISHING", "CRITICAL PHISHING"))
            suspicious_count = sum(1 for e in emails if e.get("classification") == "SUSPICIOUS")
            legit_count = sum(1 for e in emails if e.get("classification") == "LEGITIMATE")
            restricted_users = sum(1 for u in users if u.get("status") == "RESTRICTED")

            threat_count = phishing_count + suspicious_count
            posture_score = round(100.0 * (1.0 - (phishing_count / total_emails)), 1) if total_emails > 0 else 100.0

            stats = {
                "total_emails": total_emails,
                "phishing_count": phishing_count,
                "suspicious_count": suspicious_count,
                "legit_count": legit_count,
                "total_users": len(users),
                "restricted_users": restricted_users,
                "total_domains": len(domains),
                "posture_score": posture_score,
            }

        return render_template("dashboard.html", emails=emails, domains=domains, users=users, stats=stats)

    @app.get("/alert/<int:email_id>")
    def alert(email_id: int):
        with cursor() as cur:
            cur.execute("SELECT * FROM emails WHERE id = ?", (email_id,))
            email_row = cur.fetchone()
            if not email_row:
                return "Email not found", 404
            email_data = dict(email_row)
            email_data["signals"] = _safe_json_list(email_data.get("signals"))

            cur.execute("SELECT * FROM incidents WHERE email_id = ?", (email_id,))
            incident_row = cur.fetchone()
            incident_data = dict(incident_row) if incident_row else None
            if incident_data:
                incident_data["affected_users"] = _safe_json_list(incident_data.get("affected_users"))

        return render_template("alert.html", email=email_data, incident=incident_data)

    @app.get("/login")
    def login_page():
        return render_template("login.html")

    @app.post("/api/login")
    def api_login():
        data = request.get_json(force=True, silent=True) or {}
        email = data.get("email", "")
        status = identity_service.get_user_status(email)
        if status and status["status"] == "RESTRICTED":
            return jsonify({"success": False, "reason": "Account restricted due to a security incident."}), 403
        result = identity_service.login(email)
        return jsonify({"success": True, **result})

    @app.post("/api/users/toggle-status")
    def toggle_user_status():
        data = request.get_json(force=True, silent=True) or {}
        email = data.get("email", "")
        if not email:
            return jsonify({"error": "email is required"}), 400
        
        with cursor() as cur:
            cur.execute("SELECT status FROM users WHERE email = ?", (email,))
            user = cur.fetchone()
            if not user:
                return jsonify({"error": "User not found"}), 404
            
            new_status = "RESTRICTED" if user["status"] == "ACTIVE" else "ACTIVE"
            new_risk = "HIGH" if new_status == "RESTRICTED" else "NONE"
            cur.execute("UPDATE users SET status = ?, risk_level = ? WHERE email = ?", (new_status, new_risk, email))
        
        return jsonify({"success": True, "email": email, "new_status": new_status, "new_risk": new_risk})

    @app.post("/api/incidents/<int:email_id>/report")
    def report_phishing(email_id: int):
        with cursor() as cur:
            cur.execute("UPDATE incidents SET status = 'CONFIRMED_BY_USER' WHERE email_id = ?", (email_id,))
        return jsonify({"success": True})

    @app.post("/api/incidents/<int:email_id>/delete")
    def delete_email(email_id: int):
        with cursor() as cur:
            cur.execute("UPDATE incidents SET status = 'DELETED' WHERE email_id = ?", (email_id,))
        return jsonify({"success": True})

    @app.post("/api/poll-now")
    def poll_now():
        results = poll_mailpit_once(MailpitClient())
        return jsonify({"processed": len(results), "processing_ids": [r["processing_id"] for r in results]})

    @app.post("/api/process-raw")
    def process_raw():
        """Manual trigger for the simulator / demo: submit a raw RFC822 email directly."""
        data = request.get_json(force=True, silent=True) or {}
        raw_email = data.get("raw_email", "")
        if not raw_email:
            return jsonify({"error": "raw_email is required"}), 400
        result = process_raw_email(raw_email)
        return jsonify(_serialize_result(result))

    @app.get("/api/recent")
    def recent():
        return jsonify([_serialize_result(r) for r in get_recent_results()])

    return app


def _safe_json_list(value) -> list:
    import json

    if not value:
        return []
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return []


def _serialize_result(result: dict) -> dict:
    """Strip non-JSON-serializable / overly large fields for API responses."""
    verdict = result.get("verdict", {})
    return {
        "processing_id": result["processing_id"],
        "email_id": result.get("email_id"),
        "incident_id": result.get("incident_id"),
        "sender": result.get("sender"),
        "recipient": result.get("recipient"),
        "subject": result.get("subject"),
        "final_state": result.get("final_state"),
        "classification": verdict.get("classification"),
        "risk_score": verdict.get("risk_score"),
        "signals": verdict.get("signals"),
        "explanation": verdict.get("explanation"),
        "explanation_source": verdict.get("explanation_source"),
        "phishbyte_confidence": verdict.get("phishbyte_confidence"),
        "social_engineering_confidence": verdict.get("social_engineering_confidence"),
        "affected_users": result.get("affected_users"),
        "containment": result.get("containment"),
    }
