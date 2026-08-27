"""Test email scenarios for the phishing detector demo (PRD section 44)."""
from __future__ import annotations

from email.message import EmailMessage
from email.utils import formatdate, make_msgid

DEFAULT_RECIPIENT = "krishnaveni@company.test"


def _build(
    *,
    from_addr: str,
    from_name: str,
    reply_to: str = "",
    to_addr: str = DEFAULT_RECIPIENT,
    subject: str,
    text_body: str,
    html_body: str = "",
) -> str:
    msg = EmailMessage()
    msg["Message-ID"] = make_msgid()
    msg["Date"] = formatdate(localtime=True)
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to_addr
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    return msg.as_string()


def scenario_1_legitimate() -> str:
    return _build(
        from_addr="notifications@microsoft.com",
        from_name="Microsoft Account Team",
        subject="Your monthly Microsoft 365 usage summary",
        text_body=(
            "Hi,\n\nHere is your monthly usage summary for Microsoft 365. "
            "No action is required. You can review your usage at any time by "
            "signing in to https://account.microsoft.com/ from your browser.\n\n"
            "Thanks,\nThe Microsoft Account Team"
        ),
    )


def scenario_2_social_engineering() -> str:
    return _build(
        from_addr="it-support@company.test",
        from_name="IT Support Team",
        subject="URGENT: Your account will be suspended within 24 hours",
        text_body=(
            "Dear employee,\n\nWe have detected unusual activity on your account. "
            "Your account will be suspended within 24 hours unless you verify your "
            "identity immediately. This is your final notice.\n\n"
            "Please confirm your password and account details by replying to this email "
            "as soon as possible to avoid permanent suspension.\n\n"
            "IT Support Team"
        ),
    )


def scenario_3_malicious_url() -> str:
    html_body = (
        "<html><body><p>Your package could not be delivered.</p>"
        "<p><a href='http://secure-login-verify.xyz/track'>Track your package</a></p>"
        "</body></html>"
    )
    return _build(
        from_addr="delivery@shipping-notice.top",
        from_name="Delivery Notification",
        subject="Delivery Failed - Action Required",
        text_body="Your package could not be delivered. Track it at http://secure-login-verify.xyz/track",
        html_body=html_body,
    )


def scenario_4_homoglyph() -> str:
    # 'о' (Cyrillic) and 'ѕ' below are Cyrillic look-alikes for Latin 'o'/'s'.
    spoofed_domain = "micrоsоft-security.com"
    return _build(
        from_addr=f"alerts@{spoofed_domain}",
        from_name="Microsoft Security",
        subject="Security alert for your Microsoft account",
        text_body=(
            "We detected a sign-in attempt from a new device. "
            "If this wasn't you, secure your account immediately by visiting "
            f"http://{spoofed_domain}/verify"
        ),
    )


def scenario_5_link_mismatch() -> str:
    html_body = (
        "<html><body><p>Please review your PayPal account statement.</p>"
        "<p><a href='http://account-update-alert.top/paypal-verify'>https://www.paypal.com/myaccount</a></p>"
        "</body></html>"
    )
    return _build(
        from_addr="service@paypal-alerts.com",
        from_name="PayPal",
        reply_to="response@paypal-alerts.com",
        subject="Your PayPal account statement is ready",
        text_body="Please review your PayPal account statement at https://www.paypal.com/myaccount",
        html_body=html_body,
    )


def scenario_6_credential_harvesting_page() -> str:
    html_body = (
        "<html><body><p>Your mailbox is almost full.</p>"
        "<p><a href='http://account-update-alert.top/webmail-login'>Increase your storage now</a></p>"
        "</body></html>"
    )
    return _build(
        from_addr="admin@account-update-alert.top",
        from_name="Mail Administrator",
        subject="Mailbox storage limit reached - Increase storage now",
        text_body=(
            "Your mailbox has exceeded its storage limit. Click here to increase your "
            "storage immediately: http://account-update-alert.top/webmail-login"
        ),
        html_body=html_body,
    )


SCENARIOS = {
    "legitimate": scenario_1_legitimate,
    "social_engineering": scenario_2_social_engineering,
    "malicious_url": scenario_3_malicious_url,
    "homoglyph": scenario_4_homoglyph,
    "link_mismatch": scenario_5_link_mismatch,
    "credential_harvesting": scenario_6_credential_harvesting_page,
}
