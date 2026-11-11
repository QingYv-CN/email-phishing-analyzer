"""日志接口通用工具：token、白名单、URL 归一化、常量。"""

import json
import logging
import os
import random
import re
import time

import httpx

from config import TRUSTED_DOMAINS

logger = logging.getLogger("log_query.common")


LOG_BASE_URL = os.getenv("LOG_BASE_URL", "https://mail.example.com")
LOG_CLIENT_ID = os.getenv("LOG_CLIENT_ID", "")
LOG_CLIENT_SECRET = os.getenv("LOG_CLIENT_SECRET", "")


WHITELIST_SENDER_EMAILS = {
    e.strip().lower()
    for e in os.getenv("WHITELIST_SENDER_EMAILS", "").split(",")
    if e.strip()
}
WHITELIST_SENDER_DOMAINS = TRUSTED_DOMAINS | {
    d.strip().lower()
    for d in os.getenv("WHITELIST_SENDER_DOMAINS", "").split(",")
    if d.strip()
}

BANNED_EXTENSIONS = {
    "*.zip", "*.rar", "*.pdf", "*.docx", "*.xlsx", "*.pptx",
    "*.7z", "*.tar", "*.gz", "*.doc", "*.xls",
}

_MAX_TOTAL_RECORDS = 10000
_MAX_PAGES = 50
_SAMPLE_SIZE = 30
_MAX_USER_PER_BATCH = 500

_cached_token = None
_token_expire_at = 0


def _random_sample(items: list, k: int = _SAMPLE_SIZE) -> list:
    if not items:
        return []
    if len(items) <= k:
        return list(items)
    return random.sample(items, k)


async def _get_log_token() -> str:
    global _cached_token, _token_expire_at
    if _cached_token and time.time() < _token_expire_at - 300:
        return _cached_token

    url = f"{LOG_BASE_URL}/rpc/oauth2/v2.0/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "client_credentials",
        "client_id": LOG_CLIENT_ID,
        "client_secret": LOG_CLIENT_SECRET,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, headers=headers, data=data, timeout=10.0)
        resp.raise_for_status()
        res_data = resp.json()
        _cached_token = res_data.get("access_token") or res_data.get("token")
        _token_expire_at = time.time() + res_data.get("expires_in", 3600)
        return _cached_token


def _extract_email(addr: str) -> str:
    if not addr:
        return ""
    match = re.search(r'<([^>]+)>', addr)
    if match:
        return match.group(1).strip().lower()
    return addr.strip().lower()


def _get_domain(addr: str) -> str:
    email = _extract_email(addr)
    if "@" not in email:
        return ""
    return email.split("@")[-1].lower().strip("<> ").strip()


def _is_whitelist_mailfrom(mail_from: str) -> bool:
    if not mail_from:
        return False
    email = _extract_email(mail_from)
    domain = _get_domain(mail_from)
    if email in WHITELIST_SENDER_EMAILS:
        return True
    for wd in WHITELIST_SENDER_DOMAINS:
        if domain == wd or domain.endswith("." + wd):
            return True
    return False


def _contains_internal_domain(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    for wd in WHITELIST_SENDER_DOMAINS:
        if wd in lower:
            return True
    return False


def _normalize_url(raw_url: str, default_scheme: str = "http") -> str:
    if not raw_url:
        return ""
    s = raw_url.strip().strip('"').strip("'")
    if not s:
        return ""
    if s.startswith("//"):
        return f"{default_scheme}:{s}"
    if "://" in s:
        return s
    if s.startswith("/"):
        return ""
    if "." in s.split("/")[0]:
        return f"{default_scheme}://{s}"
    return ""


def _extract_urls_from_href(html: str) -> list[str]:
    if not html:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
        raw = m.group(1).strip()
        normalized = _normalize_url(raw)
        if normalized:
            key = normalized.lower()
            if key not in seen:
                seen.add(key)
                out.append(normalized)
    return out