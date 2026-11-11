"""程序化补充 IOC URL —— 严格过滤，正常网站不会被误补。"""

import logging
import urllib.parse

from config import TRUSTED_DOMAINS, SUPPLEMENT_UNDETECTED_URLS
from tools.safe_domain_whitelist import is_whitelisted

logger = logging.getLogger("analysis.ioc")


def supplement_ioc_urls(data: dict, llm_urls: list) -> list[dict]:
    """程序化补充 ioc_details.urls。"""
    seen = set()
    for u in llm_urls or []:
        if isinstance(u, dict):
            real = u.get("real") or u.get("url") or u.get("text") or ""
        elif isinstance(u, str):
            real = u
        else:
            real = ""
        if real:
            seen.add(real.strip().lower())

    domain_intel = data.get("domain_intel", {})
    supplemented: list[dict] = []

    for url in data.get("urls", []) or []:
        if not url:
            continue
        url_key = url.strip().lower()
        if url_key in seen:
            continue

        try:
            d = urllib.parse.urlparse(url).netloc.lower()
            if d.startswith("www."):
                d = d[4:]
            if not d:
                continue

            if is_whitelisted(d):
                continue
            if any(d == wd or d.endswith("." + wd) for wd in TRUSTED_DOMAINS):
                continue

            intel = domain_intel.get(d, {})

            if intel.get("is_safe", False):
                continue

            worst = (intel.get("worst_category") or "unknown").lower()

            if worst == "harmless":
                continue

            if worst in ("malicious", "suspicious", "phishing"):
                supplemented.append({
                    "display": "",
                    "real": url,
                    "suspicious": True,
                    "source": "program_supplement",
                    "vt_category": worst,
                })
            elif worst in ("undetected", "unknown") and SUPPLEMENT_UNDETECTED_URLS:
                supplemented.append({
                    "display": "",
                    "real": url,
                    "suspicious": False,
                    "source": "program_supplement",
                    "vt_category": worst,
                })
        except Exception:
            continue

    return supplemented