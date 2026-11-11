"""IOC 提取与锚点判定。纯函数，无 async、无 LLM。"""

import re
import urllib.parse
from collections import Counter

from tools.safe_domain_whitelist import is_whitelisted
from config import TRUSTED_DOMAINS


WHITELIST_DOMAINS = TRUSTED_DOMAINS | {
    "w3.org", "google.com", "microsoft.com", "adobe.com",
    "qq.com", "163.com", "gmail.com",
}


def _ioc_get(item, key: str) -> str:
    if isinstance(item, dict):
        v = item.get(key, "")
        return str(v) if v is not None else ""
    if isinstance(item, str):
        return item
    return ""


def extract_iocs(mail: dict, domain_intel: dict, ip_intel: dict) -> set[str]:
    iocs = set()
    res = mail.get("result", {})
    meta = mail.get("meta", {}) or {}
    ioc_details = res.get("ioc_details", {})

    def add_domain(url_str):
        if not url_str:
            return
        raw = str(url_str).strip()
        if not raw:
            return
        try:
            target = raw if "://" in raw else "http://" + raw
            parsed = urllib.parse.urlparse(target)
            domain = (parsed.netloc or "").lower()
            if "@" in domain:
                domain = domain.split("@")[-1]
            if ":" in domain:
                domain = domain.split(":")[0]
            if domain.startswith("www."):
                domain = domain[4:]
            if not domain or "." not in domain or not domain.isascii() or any(c.isspace() for c in domain):
                return
            parts = domain.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return
            if domain in WHITELIST_DOMAINS or is_whitelisted(domain):
                return
            intel = domain_intel.get(domain, {})
            if not intel.get("is_safe", False):
                iocs.add(f"domain:{domain}")
        except Exception:
            pass

    def add_ip(ip_str):
        if not ip_str:
            return
        intel = ip_intel.get(ip_str, {})
        if not intel.get("is_safe", False):
            iocs.add(f"ip:{ip_str}")

    for u in ioc_details.get("urls", []) or []:
        add_domain(_ioc_get(u, "real") or _ioc_get(u, "url") or _ioc_get(u, "text"))

    for raw_url in meta.get("raw_urls", []) or []:
        add_domain(raw_url)

    for a in ioc_details.get("attachments", []) or []:
        fn = _ioc_get(a, "filename").lower()
        if fn:
            iocs.add(f"attachment:{fn}")

    for qr in ioc_details.get("qr_codes", []) or []:
        add_domain(_ioc_get(qr, "content") or _ioc_get(qr, "text"))

    for img in ioc_details.get("image_texts", []) or []:
        ocr_text = _ioc_get(img, "ocr_text") or _ioc_get(img, "text")
        urls = re.findall(r'https?://[^\s]+', ocr_text)
        for url in urls:
            add_domain(url)

    for ip in res.get("ips", []) or []:
        add_ip(ip)

    return iocs


def determine_anchor(group_mails: list[dict], domain_intel: dict, ip_intel: dict
                    ) -> tuple[str, str, list[str]]:
    if not group_mails:
        return "none", "low", []

    if len(group_mails) == 1:
        m = group_mails[0]
        iocs = extract_iocs(m, domain_intel, ip_intel)
        domains = [i.replace("domain:", "") for i in iocs if i.startswith("domain:")]
        ips = [i.replace("ip:", "") for i in iocs if i.startswith("ip:")]
        atts = [i.replace("attachment:", "") for i in iocs if i.startswith("attachment:")]
        if domains:
            return "domains", "medium", domains
        if ips:
            return "ips", "medium", ips
        if atts:
            return "attachment_names", "medium", atts
        meta = m.get("meta", {})
        mail_from = (meta.get("envelope_from") or meta.get("mail_from") or "").strip()
        from_name = (meta.get("sender_name") or "").strip()
        if mail_from:
            return "mailFrom", "medium", [mail_from]
        if from_name:
            return "from", "low", [from_name]
        return "none", "low", []

    ioc_counter: Counter = Counter()
    for m in group_mails:
        for ioc in extract_iocs(m, domain_intel, ip_intel):
            ioc_counter[ioc] += 1

    shared = [(ioc, cnt) for ioc, cnt in ioc_counter.items() if cnt >= 2]

    shared_domains = sorted(
        [(i, c) for i, c in shared if i.startswith("domain:")], key=lambda x: -x[1])
    shared_ips = sorted(
        [(i, c) for i, c in shared if i.startswith("ip:")], key=lambda x: -x[1])
    shared_atts = sorted(
        [(i, c) for i, c in shared if i.startswith("attachment:")], key=lambda x: -x[1])

    if shared_domains:
        return "domains", "high", [i.replace("domain:", "") for i, _ in shared_domains[:3]]
    if shared_ips:
        return "ips", "high", [i.replace("ip:", "") for i, _ in shared_ips[:3]]
    if shared_atts:
        return "attachment_names", "high", [i.replace("attachment:", "") for i, _ in shared_atts[:3]]

    senders = set()
    for m in group_mails:
        meta = m.get("meta", {})
        s = (meta.get("envelope_from") or meta.get("mail_from") or "").lower().strip()
        if s:
            senders.add(s)
    if len(senders) == 1:
        return "mailFrom", "high", list(senders)

    from_names = set()
    for m in group_mails:
        meta = m.get("meta", {})
        fn = (meta.get("sender_name") or "").strip()
        if fn:
            from_names.add(fn)
    if len(from_names) == 1:
        return "from", "medium", list(from_names)

    return "none", "low", []