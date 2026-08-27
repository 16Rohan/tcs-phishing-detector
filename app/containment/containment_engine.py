"""Simulated post-detection containment. Demonstrates what a real identity-provider
integration (Entra/Okta/Workspace) would perform — no real account action is taken."""
from __future__ import annotations

from app.containment import identity_service

STAGE_ORDER = ["RECEIVED_ONLY", "USER_CLICKED", "CREDENTIAL_SUBMISSION_DETECTED"]


def determine_stage(verdict: dict, dynamic_result: dict | None) -> str:
    if dynamic_result and any(
        i.get("has_password_field") for i in dynamic_result.get("inspections", [])
    ):
        return "CREDENTIAL_SUBMISSION_DETECTED"
    if verdict["classification"] in ("PHISHING", "CRITICAL PHISHING"):
        return "USER_CLICKED"
    return "RECEIVED_ONLY"


def run_containment(affected_users: list[str], verdict: dict, dynamic_result: dict | None) -> dict:
    stage = determine_stage(verdict, dynamic_result)
    actions = []

    if stage == "RECEIVED_ONLY":
        actions.append({"action": "no_account_action", "detail": "Email received but no interaction detected."})
    elif stage == "USER_CLICKED":
        for user in affected_users:
            identity_service.login(user)
        actions.append({"action": "mfa_monitor_warning", "users": affected_users})
    elif stage == "CREDENTIAL_SUBMISSION_DETECTED":
        for user in affected_users:
            identity_service.restrict(user)
            identity_service.revoke_sessions(user)
            identity_service.flag_device(user, "unknown-device")
        actions.append(
            {
                "action": "account_restricted_sessions_revoked_device_flagged",
                "users": affected_users,
            }
        )

    return {"stage": stage, "actions": actions, "affected_users": affected_users}
