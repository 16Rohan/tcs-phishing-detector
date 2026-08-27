"""Parse raw RFC822 email content into a normalized internal object."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string, policy
from email.utils import getaddresses, parseaddr

from bs4 import BeautifulSoup

URL_REGEX = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)


@dataclass
class ExtractedUrl:
    original_url: str
    normalized_url: str
    domain: str
    scheme: str
    anchor_text: str = ""
    source: str = "unknown"  # text_body | html_href | html_image | html_ref


@dataclass
class ParsedEmail:
    message_id: str = ""
    sender: str = ""
    sender_display_name: str = ""
    sender_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    recipient: str = ""
    subject: str = ""
    text_body: str = ""
    html_body: str = ""
    urls: list[ExtractedUrl] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    raw_email: str = ""
    parse_errors: list[str] = field(default_factory=list)


def _domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(">").strip()


def _normalize_url(url: str) -> str:
    return url.strip().rstrip(".,);]'\"")


def _urls_from_text(text: str) -> list[ExtractedUrl]:
    found = []
    for match in URL_REGEX.finditer(text or ""):
        raw = _normalize_url(match.group(0))
        domain = _extract_domain(raw)
        found.append(ExtractedUrl(raw, raw, domain, _scheme_of(raw), source="text_body"))
    return found


def _scheme_of(url: str) -> str:
    return url.split("://", 1)[0].lower() if "://" in url else ""


def _extract_domain(url: str) -> str:
    try:
        rest = url.split("://", 1)[-1]
        domain = rest.split("/", 1)[0]
        domain = domain.split("@")[-1]  # userinfo@host
        domain = domain.split(":")[0]  # strip port
        return domain.lower()
    except Exception:
        return ""


def _urls_from_html(html: str) -> list[ExtractedUrl]:
    urls: list[ExtractedUrl] = []
    try:
        soup = BeautifulSoup(html or "", "html.parser")
    except Exception:
        return urls

    for a in soup.find_all("a", href=True):
        href = _normalize_url(a["href"])
        if not href.lower().startswith(("http://", "https://")):
            continue
        urls.append(
            ExtractedUrl(
                href, href, _extract_domain(href), _scheme_of(href),
                anchor_text=a.get_text(strip=True), source="html_href",
            )
        )

    for img in soup.find_all("img", src=True):
        src = _normalize_url(img["src"])
        if src.lower().startswith(("http://", "https://")):
            urls.append(ExtractedUrl(src, src, _extract_domain(src), _scheme_of(src), source="html_image"))

    for tag in soup.find_all(["link", "area", "base"]):
        ref = tag.get("href") or tag.get("src")
        if ref and ref.lower().startswith(("http://", "https://")):
            ref = _normalize_url(ref)
            urls.append(ExtractedUrl(ref, ref, _extract_domain(ref), _scheme_of(ref), source="html_ref"))

    return urls


def parse_email(raw_email: str) -> ParsedEmail:
    parsed = ParsedEmail(raw_email=raw_email)
    try:
        msg = message_from_string(raw_email, policy=policy.default)
    except Exception as exc:
        parsed.parse_errors.append(f"MIME parse failure: {exc}")
        return parsed

    parsed.headers = {k: str(v) for k, v in msg.items()}
    parsed.message_id = str(msg.get("Message-ID", "")).strip()
    parsed.subject = str(msg.get("Subject", ""))

    display_name, sender_addr = parseaddr(str(msg.get("From", "")))
    parsed.sender = sender_addr
    parsed.sender_display_name = display_name
    parsed.sender_domain = _domain_of(sender_addr)

    reply_to_addrs = getaddresses([str(msg.get("Reply-To", ""))])
    parsed.reply_to = reply_to_addrs[0][1] if reply_to_addrs and reply_to_addrs[0][1] else ""

    parsed.return_path = parseaddr(str(msg.get("Return-Path", "")))[1]

    to_addrs = getaddresses([str(msg.get("To", ""))])
    parsed.recipient = to_addrs[0][1] if to_addrs and to_addrs[0][1] else ""

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in disposition:
                    filename = part.get_filename()
                    if filename:
                        parsed.attachments.append(filename)
                    continue
                try:
                    payload = part.get_content()
                except Exception:
                    continue
                if content_type == "text/plain" and isinstance(payload, str):
                    parsed.text_body += payload
                elif content_type == "text/html" and isinstance(payload, str):
                    parsed.html_body += payload
        else:
            try:
                payload = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True)
                payload = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
            if msg.get_content_type() == "text/html":
                parsed.html_body = payload or ""
            else:
                parsed.text_body = payload or ""
    except Exception as exc:
        parsed.parse_errors.append(f"Body extraction failure: {exc}")

    urls = _urls_from_text(parsed.text_body) + _urls_from_html(parsed.html_body)
    seen = set()
    deduped = []
    for u in urls:
        if u.original_url not in seen:
            seen.add(u.original_url)
            deduped.append(u)
    parsed.urls = deduped

    return parsed
