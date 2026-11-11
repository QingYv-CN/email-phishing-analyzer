"""规则化判定：与 LLM 结果交叉验证。"""

import email.utils
import urllib.parse
from datetime import datetime, timezone

from config import MAX_MAIL_AGE_HOURS, TRUSTED_DOMAINS
from tools.safe_domain_whitelist import is_whitelisted


def is_mail_too_old(date_str: str, max_hours: int = MAX_MAIL_AGE_HOURS) -> bool:
    if not date_str:
        return False
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (now - dt).total_seconds() / 3600 > max_hours
    except Exception:
        return False


def parse_email_date(date_str: str) -> int | None:
    if not date_str:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return None


def is_trusted_whitelisted(data: dict) -> bool:
    sender = data.get("sender", "").lower()
    if "@" not in sender:
        return False
    domain = sender.split("@")[-1].strip("<>")
    if not any(domain == wd or domain.endswith("." + wd) for wd in TRUSTED_DOMAINS):
        return False
    auth = ((data.get("headers") or {}).get("authentication_results") or "").lower()
    if "fail" in auth or "softfail" in auth:
        return False
    return True


def attachment_force_verdict(att_result: dict) -> dict:
    if not att_result:
        return {"force_high": False, "force_suspicious": False, "reasons": []}
    high_count = att_result.get("mismatch_high_count", 0)
    medium_count = att_result.get("mismatch_medium_count", 0)
    reasons = []
    for r in att_result.get("results", []):
        ftc = r.get("file_type_check") or {}
        if ftc.get("mismatch") and ftc.get("severity") in ("high", "medium"):
            fname = r.get("filename") or "-"
            detail = ftc.get("detail") or "文件类型不一致"
            reasons.append(f"{fname} → {detail}")
    return {
        "force_high": high_count > 0,
        "force_suspicious": (high_count > 0) or (medium_count > 0),
        "reasons": reasons,
    }


def rule_based_check(data: dict, image_result: dict | None, attachment_result: dict | None) -> dict:
    score = 0
    reasons = []
    sender = (data.get("sender") or "").lower()
    sender_domain = sender.split("@")[-1] if "@" in sender else ""
    sender_name = data.get("sender_name") or ""

    if sender_domain in {"qq.com", "163.com", "126.com", "gmail.com", "outlook.com"} and any(
        kw in sender_name for kw in ["银行", "财务", "HR", "IT", "客服", "安全", "官方"]
    ):
        score += 3
        reasons.append(f"免费邮箱冒充企业: {sender}")

    auth = ((data.get("headers") or {}).get("authentication_results") or "").lower()
    if "spf=fail" in auth or "dmarc=fail" in auth:
        score += 2
        reasons.append("SPF/DMARC 认证失败")

    for att in data.get("attachments") or []:
        if (att.get("filename") or "").lower().endswith((".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".hta")):
            score += 3
            reasons.append(f"高危附件: {att.get('filename')}")

    ip_intel = data.get("ip_intel", {})
    for ip in data.get("ips", []):
        intel = ip_intel.get(ip, {})
        if not intel.get("is_safe", False):
            score += 3
            reasons.append(f"恶意/可疑 IP: {ip} (VT: {intel.get('worst_category')})")

    domain_intel = data.get("domain_intel", {})
    for url in data.get("urls") or []:
        try:
            d = urllib.parse.urlparse(url).netloc.lower()
            if d.startswith("www."):
                d = d[4:]
            if is_whitelisted(d):
                continue
            intel = domain_intel.get(d, {})
            if intel.get("is_safe", False):
                continue
            if intel.get("worst_category") in ("undetected", "unknown") and any(
                tld in url.lower() for tld in [".ru", ".tk", ".xyz", ".top", ".club", ".click"]
            ):
                score += 2
                reasons.append(f"未收录+可疑 TLD: {url}")
                continue
        except Exception:
            pass
        if any(tld in url.lower() for tld in [".ru", ".tk", ".xyz", ".top", ".club", ".click"]):
            score += 1
            reasons.append(f"可疑 TLD: {url}")

    if attachment_result:
        for item in attachment_result.get("results", []):
            if item.get("risk_level") == "high":
                score += 3
                reasons.append(f"压缩包含高危文件: {item.get('filename')}")

        att_check = attachment_force_verdict(attachment_result)
        if att_check["force_high"]:
            score += 5
            reasons.append("附件文件类型欺骗(声称无害实际高危): " + "；".join(att_check["reasons"]))
        elif att_check["force_suspicious"]:
            score += 3
            reasons.append("附件文件类型不一致: " + "；".join(att_check["reasons"]))

    if score >= 5:
        verdict = "高危"
    elif score >= 3:
        verdict = "可疑"
    elif score >= 1:
        verdict = "低危"
    else:
        verdict = "正常"
    return {"rule_score": score, "rule_verdict": verdict, "rule_reasons": reasons}