"""Dynamic screening: safe, bounded HTTP inspection of suspicious URLs.

Hard rules (see PRD section 16/29):
- No JavaScript execution, no browser automation.
- No form submission, no credential sending.
- Timeouts, redirect limits, response-size limits enforced.
- Private/loopback network targets are refused.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from app.config import config

logger = logging.getLogger("dynamic_analyzer")

SAFE_UA = "Mozilla/5.0 (compatible; PhishingDetectorBot/1.0; +internal-security-scan)"


def _is_private_target(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return True
        except ValueError:
            continue
    return False


def _validate_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "invalid_scheme"
    if not parsed.hostname:
        return "no_hostname"
    if _is_private_target(parsed.hostname):
        return "private_network_target_blocked"
    return None


def fetch_and_inspect(url: str) -> dict:
    result = {
        "url": url,
        "reachable": False,
        "final_url": url,
        "redirect_count": 0,
        "status_code": None,
        "error": None,
        "has_password_field": False,
        "has_login_form": False,
        "form_action_domain_mismatch": False,
        "suspicious_form_actions": [],
        "external_link_domains": [],
        "title": "",
        "signals": [],
        "risk_score": 0,
    }

    validation_error = _validate_url(url)
    if validation_error:
        result["error"] = validation_error
        result["signals"].append(f"dynamic_analysis_blocked:{validation_error}")
        return result

    try:
        resp = requests.get(
            url,
            timeout=config.HTTP_TIMEOUT_SECONDS,
            allow_redirects=True,
            headers={"User-Agent": SAFE_UA},
            stream=True,
        )
        content = b""
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > config.MAX_RESPONSE_BYTES:
                result["signals"].append("response_size_limit_exceeded")
                break
            if len(resp.history) > config.MAX_REDIRECTS:
                result["signals"].append("redirect_limit_exceeded")
                break

        result["reachable"] = True
        result["final_url"] = resp.url
        result["redirect_count"] = len(resp.history)
        result["status_code"] = resp.status_code

        if result["redirect_count"] > config.MAX_REDIRECTS:
            result["signals"].append("excessive_redirects")
            result["risk_score"] += 15

        original_domain = urlparse(url).hostname or ""
        final_domain = urlparse(resp.url).hostname or ""
        if original_domain != final_domain:
            result["signals"].append("redirect_domain_change")
            result["risk_score"] += 10

        html = content.decode(resp.encoding or "utf-8", errors="replace")
        _inspect_html(html, final_domain, result)

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        result["signals"].append("dynamic_fetch_timeout")
    except requests.exceptions.TooManyRedirects:
        result["error"] = "too_many_redirects"
        result["signals"].append("redirect_limit_exceeded")
        result["risk_score"] += 15
    except requests.RequestException as exc:
        result["error"] = str(exc)
        result["signals"].append("dynamic_fetch_failed")

    result["risk_score"] = min(result["risk_score"], 100)
    return result


def _inspect_html(html: str, page_domain: str, result: dict) -> None:
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:
        result["signals"].append("html_parse_failed")
        logger.warning("Failed to parse dynamic HTML: %s", exc)
        return

    if soup.title and soup.title.string:
        result["title"] = soup.title.string.strip()[:200]

    password_fields = soup.find_all("input", {"type": "password"})
    if password_fields:
        result["has_password_field"] = True
        result["signals"].append("credential_harvesting_indicator")
        result["risk_score"] += 40

    forms = soup.find_all("form")
    if forms and password_fields:
        result["has_login_form"] = True
        result["signals"].append("login_form_detected")
        result["risk_score"] += 20

    for form in forms:
        action = form.get("action", "")
        if not action:
            continue
        action_parsed = urlparse(action)
        action_domain = action_parsed.hostname
        if action_domain and page_domain and action_domain != page_domain:
            result["suspicious_form_actions"].append(action)
            result["form_action_domain_mismatch"] = True
            result["signals"].append("form_action_domain_mismatch")
            result["risk_score"] += 25

    external_domains = set()
    for a in soup.find_all("a", href=True):
        link_domain = urlparse(a["href"]).hostname
        if link_domain and page_domain and link_domain != page_domain:
            external_domains.add(link_domain)
    result["external_link_domains"] = sorted(external_domains)


def run_dynamic_analysis(urls_needing_check: list[str]) -> dict:
    inspections = [fetch_and_inspect(url) for url in urls_needing_check]
    max_risk = max((i["risk_score"] for i in inspections), default=0)
    all_signals = []
    for i in inspections:
        all_signals.extend(i["signals"])
    return {
        "inspections": inspections,
        "risk_score": max_risk,
        "signals": all_signals,
    }
