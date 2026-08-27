"""Raw RFC822 email builders for each demo attack scenario. Kept separate from
simulator/scenarios.py so the Demo folder is self-contained and easy to read
attack-by-attack."""
from __future__ import annotations

from email.message import EmailMessage
from email.utils import formatdate, make_msgid

RECIPIENT = "krishnaveni@company.test"


def build(*, from_addr, from_name, subject, text_body, html_body="", reply_to="", to_addr=RECIPIENT):
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


def legitimate_baseline() -> str:
    """Not an attack — used as a control to show the pipeline clearing clean mail."""
    return build(
        from_addr="notifications@microsoft.com",
        from_name="Microsoft Account Team",
        subject="[DEMO] Your monthly Microsoft 365 usage summary",
        text_body=(
            "Hi,\n\nHere is your monthly usage summary for Microsoft 365. "
            "No action is required. Review your usage anytime at "
            "https://account.microsoft.com/\n\nThanks,\nThe Microsoft Account Team"
        ),
    )


def social_engineering_urgency() -> str:
    """Attack type: social engineering — urgency, fear, authority, credential request."""
    return build(
        from_addr="it-support@company.test",
        from_name="IT Support Team",
        subject="[DEMO] URGENT: Your account will be suspended within 24 hours",
        text_body=(
            "Dear employee,\n\nWe have detected unusual activity on your account. "
            "Your account will be suspended within 24 hours unless you verify your "
            "identity immediately. This is your final notice.\n\n"
            "Please confirm your password and account details by replying to this "
            "email as soon as possible to avoid permanent suspension.\n\n"
            "IT Support Team"
        ),
    )


def malicious_url_threat_intel() -> str:
    """Attack type: known-malicious URL matched against the local threat-intel LUT
    (and, when reachable, Google Safe Browsing)."""
    html_body = (
        "<html><body><p>Your package could not be delivered.</p>"
        "<p><a href='http://secure-login-verify.xyz/track'>Track your package</a></p>"
        "</body></html>"
    )
    return build(
        from_addr="delivery@shipping-notice.top",
        from_name="Delivery Notification",
        subject="[DEMO] Delivery Failed - Action Required",
        text_body="Your package could not be delivered. Track it at http://secure-login-verify.xyz/track",
        html_body=html_body,
    )


def homoglyph_domain_spoofing() -> str:
    """Attack type: Unicode/homoglyph domain impersonation of a trusted brand."""
    # 'о' below is U+043E CYRILLIC SMALL LETTER O, a visual look-alike for Latin 'o'.
    spoofed_domain = "micrоsoft-security.com"
    return build(
        from_addr=f"alerts@{spoofed_domain}",
        from_name="Microsoft Security",
        subject="[DEMO] Security alert for your Microsoft account",
        text_body=(
            "We detected a sign-in attempt from a new device. If this wasn't you, "
            f"secure your account immediately by visiting http://{spoofed_domain}/verify"
        ),
    )


def link_domain_mismatch() -> str:
    """Attack type: visible anchor text claims a trusted brand while the real
    href points to an unrelated attacker-controlled domain."""
    html_body = (
        "<html><body><p>Please review your PayPal account statement.</p>"
        "<p><a href='http://account-update-alert.top/paypal-verify'>https://www.paypal.com/myaccount</a></p>"
        "</body></html>"
    )
    return build(
        from_addr="service@paypal-alerts.com",
        from_name="PayPal",
        reply_to="response@paypal-alerts.com",
        subject="[DEMO] Your PayPal account statement is ready",
        text_body="Please review your PayPal account statement at https://www.paypal.com/myaccount",
        html_body=html_body,
    )


def credential_harvesting_page() -> str:
    """Attack type: link resolves (in a real deployment) to a page with a live
    login/password form — dynamic HTML analysis territory."""
    html_body = (
        "<html><body><p>Your mailbox is almost full.</p>"
        "<p><a href='http://account-update-alert.top/webmail-login'>Increase your storage now</a></p>"
        "</body></html>"
    )
    return build(
        from_addr="admin@account-update-alert.top",
        from_name="Mail Administrator",
        subject="[DEMO] Mailbox storage limit reached - Increase storage now",
        text_body=(
            "Your mailbox has exceeded its storage limit. Click here to increase "
            "your storage immediately: http://account-update-alert.top/webmail-login"
        ),
        html_body=html_body,
    )


def display_name_brand_impersonation() -> str:
    """Attack type: display-name spoofing — the friendly name claims a known
    brand while the actual sending domain has nothing to do with it."""
    return build(
        from_addr="noreply@mailer-service-42.top",
        from_name="Apple Support",
        subject="[DEMO] Your Apple ID has been locked for security reasons",
        text_body=(
            "Dear Customer,\n\nYour Apple ID has been locked due to too many failed "
            "login attempts. To restore access, verify your identity now by "
            "confirming your password and billing details: "
            "http://mailer-service-42.top/apple-id-verify\n\n"
            "Apple Support Team"
        ),
    )
