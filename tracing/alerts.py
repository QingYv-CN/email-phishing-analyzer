"""从 tool_results 拼受害者名单、聚合高风险用户。纯函数。"""

import json

from tools.mail_log_searcher import _is_whitelist_mailfrom
from tracing.ioc import _ioc_get
from recipient_blacklist import is_blacklisted_email


def _format_time(utc_time_str):
    from datetime import datetime, timezone, timedelta
    if not utc_time_str:
        return "-"
    try:
        if utc_time_str.endswith("Z"):
            dt_utc = datetime.strptime(utc_time_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        else:
            dt_utc = datetime.fromisoformat(utc_time_str.replace("Z", "+00:00"))
        return dt_utc.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return utc_time_str


def build_alerts_from_tool_results(tool_results: list[str]) -> list[dict]:
    all_logs = []
    for result_str in tool_results:
        try:
            data = json.loads(result_str)
        except Exception:
            continue
        logs = data.get("all_users")
        if not logs:
            logs = data.get("sample_logs") or []
        if logs:
            all_logs.extend(logs)

    filtered_logs = []
    for log in all_logs:
        mail_from = log.get("mailFrom", "")
        if _is_whitelist_mailfrom(mail_from):
            continue
        if log.get("is_dirty", False):
            continue
        filtered_logs.append(log)

    seen = set()
    dedup_logs = []
    for log in filtered_logs:
        key = (log.get("user"), log.get("subject"))
        if key not in seen:
            seen.add(key)
            dedup_logs.append(log)

    alerts = []
    if dedup_logs:
        affected_users = [{
            "user": log.get("user"),
            "sender": log.get("mailFrom"),
            "from_display": log.get("from"),
            "is_spoofed_internal": log.get("is_spoofed_internal", False),
            "time": _format_time(log.get("time")),
            "subject": log.get("subject"),
        } for log in dedup_logs]
        alerts.append({
            "campaign": "溯源命中名单",
            "affected_users": affected_users,
            "total_logs": len(dedup_logs),
            "status": "success",
        })
    else:
        alerts.append({
            "campaign": "特征随机无法定位",
            "affected_users": [],
            "total_logs": 0,
            "status": "failed_to_locate",
        })
    return alerts


def _aggregate_risk_users(all_attachment_downloads: list[dict],
                          all_url_visits: list[dict]) -> list[dict]:
    risk_users: dict[str, dict] = {}

    def _ensure(display: str) -> dict:
        k = display.lower()
        if k not in risk_users:
            risk_users[k] = {
                "user": display,
                "reasons": [],
                "attachment_downloads": [],
                "url_visits": [],
            }
        return risk_users[k]

    for item in all_attachment_downloads:
        u = _ensure(item["user"])
        risk = item.get("risk", "")
        tag = "🔴" if risk == "high" else "🟠"
        if item.get("fallback"):
            src = "[保守兜底,需人工复核]"
        elif item.get("llm_approved"):
            src = "[LLM确认]"
        else:
            src = ""
        u["reasons"].append(
            f"{tag} 下载可疑附件 {item.get('attachment_name', '')} "
            f"[{item.get('activity')}] ({item.get('reason', '')}) {src}"
        )
        u["attachment_downloads"].append(item)

    for item in all_url_visits:
        u = _ensure(item["user"])
        if item.get("fallback"):
            src = "[保守兜底,需人工复核]"
        elif item.get("llm_approved"):
            src = "[LLM确认]"
        else:
            src = ""
        u["reasons"].append(
            f"🔴 访问风险URL {item.get('url', '')} ({item.get('reason', '')}) {src}"
        )
        u["url_visits"].append(item)

    return [
        r for r in risk_users.values()
        if not is_blacklisted_email(r["user"])
    ]