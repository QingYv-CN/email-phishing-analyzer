"""行为审计日志查询（附件下载 / URL 访问）。"""

import json
import logging
import re
import urllib.parse
from datetime import datetime, timedelta, timezone

import httpx
from langchain_core.tools import tool

from config import (
    BEHAVIOR_LOOKBACK_HOURS, BEHAVIOR_QUERY_LENGTH,
    BEHAVIOR_MAX_ATTACHMENT_PATTERNS, BEHAVIOR_MAX_URL_PATTERNS,
)
from log_query.common import (
    LOG_BASE_URL,
    _MAX_TOTAL_RECORDS, _MAX_PAGES, _MAX_USER_PER_BATCH,
    _SAMPLE_SIZE,
    _random_sample, _get_log_token,
)

logger = logging.getLogger("log_query.behavior_logs")


ATTACHMENT_HIGH_RISK_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".jar", ".msi",
    ".dll", ".lnk", ".hta", ".cpl", ".iso", ".img", ".vhd", ".vhdx",
}
ATTACHMENT_MEDIUM_RISK_EXT = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".cab",
    ".docm", ".xlsm", ".pptm", ".rtf", ".doc", ".xls", ".ppt",
}
DISGUISE_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar", ".7z",
}


def _classify_attachment_risk(filename: str) -> tuple[str, str]:
    fn = (filename or "").lower().strip()
    if not fn:
        return "low", ""
    parts = fn.split(".")
    if len(parts) >= 3:
        second_last = "." + parts[-2].lower()
        last = "." + parts[-1].lower()
        if second_last in DISGUISE_EXTS and last in ATTACHMENT_HIGH_RISK_EXT:
            return "high", f"双扩展名伪装 {parts[-2]}.{parts[-1]}"
    ext = "." + parts[-1] if parts else ""
    if ext in ATTACHMENT_HIGH_RISK_EXT:
        return "high", f"高危后缀 {ext}"
    if ext in ATTACHMENT_MEDIUM_RISK_EXT:
        return "medium", f"压缩包/宏文档/老Office {ext}"
    return "low", ""


def _match_attack_attachment(filename: str, attack_names: list[str]) -> tuple[bool, str]:
    if not filename or not attack_names:
        return False, ""

    fn_lower = filename.lower()
    fn_base = fn_lower.rsplit(".", 1)[0] if "." in fn_lower else fn_lower

    for raw in attack_names:
        name = (raw or "").strip()
        if not name:
            continue
        name_lower = name.lower()
        name_base = name_lower.rsplit(".", 1)[0] if "." in name_lower else name_lower

        if name_lower in fn_lower or fn_lower in name_lower:
            return True, f"附件名匹配攻击附件 {name}"

        if len(name_base) >= 4 and name_base in fn_base:
            return True, f"附件主干匹配攻击附件 {name}"

        tokens = [t for t in re.split(r"[_\-\s\.]+", name_base) if len(t) >= 4 and not t.isdigit()]
        if tokens:
            core = max(tokens, key=len)
            if core in fn_base:
                return True, f"附件关键词匹配 {core}（源自 {name}）"

    return False, ""


def _classify_url_risk(url: str, suspicious_domains: set) -> tuple[str, str]:
    if not url:
        return "low", ""
    try:
        d = urllib.parse.urlparse(url).netloc.lower()
        if "@" in d:
            d = d.split("@")[-1]
        if ":" in d:
            d = d.split(":")[0]
        if d.startswith("www."):
            d = d[4:]
        if d in suspicious_domains:
            return "high", f"命中恶意域名 {d}"
        for sd in suspicious_domains:
            if d.endswith("." + sd):
                return "high", f"子域命中恶意域名 {sd}"
    except Exception:
        pass
    return "low", ""


def _infer_filter_scope(filters: dict) -> str:
    if not filters:
        return "broad"
    if any(k in filters for k in ("user", "email", "resourceOwner", "ip")):
        return "narrow"
    return "broad"


def _normalize_filter_value(value):
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=False)
    return value


def _clean_behavior_filters(activities: list[str], filters: dict) -> tuple[dict, list[str]]:
    unsupported: set[str] = set()
    for a in activities or []:
        if a in ("ATTACHMENT_DOWNLOAD", "BIG_ATTACHMENT_DOWNLOAD"):
            unsupported.add("attachmentName")
        elif a == "THREATPOLICY_URL_ACCESS":
            unsupported.add("url")

    cleaned = {}
    removed = []
    for k, v in (filters or {}).items():
        if k in unsupported:
            removed.append(k)
            continue
        cleaned[k] = _normalize_filter_value(v)
    return cleaned, removed


async def _query_activity_logs(activities: list[str], filters: dict, offset: int = 0) -> dict:
    now = datetime.now(timezone.utc)
    begin_time = (now - timedelta(hours=BEHAVIOR_LOOKBACK_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "activities": activities,
        "beginTimestamp": begin_time,
        "endTimestamp": end_time,
        "offset": offset,
        "length": BEHAVIOR_QUERY_LENGTH,
        "filters": filters,
    }
    logger.info(f"[_query_activity_logs] 实际请求 payload: {json.dumps(payload, ensure_ascii=False)}")
    print(f"=== [_query_activity_logs] 实际请求 payload: {json.dumps(payload, ensure_ascii=False)} ===", flush=True)

    token = await _get_log_token()
    url = f"{LOG_BASE_URL}/rpc/v2/report/records/"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
        resp.raise_for_status()
        return resp.json()


async def _query_activity_logs_with_pagination(
    activities: list[str],
    filters: dict,
    max_total_records: int = _MAX_TOTAL_RECORDS,
    max_pages: int = _MAX_PAGES,
) -> tuple[list[dict], bool]:
    all_records: list[dict] = []
    offset = 0
    for page_idx in range(max_pages):
        try:
            data = await _query_activity_logs(activities, filters, offset)
        except Exception as e:
            logger.error(f"[_query_activity_logs_with_pagination] 第 {page_idx + 1} 页查询失败: {e}")
            print(f"=== [_query_activity_logs_with_pagination] 第 {page_idx + 1} 页查询失败: {e} ===", flush=True)
            return all_records, False
        records = data.get("records", []) or []
        all_records.extend(records)
        has_more = data.get("hasMore", False)
        if not has_more or not records:
            logger.info(
                f"[_query_activity_logs_with_pagination] 翻页完成：共 {page_idx + 1} 页，{len(all_records)} 条"
            )
            return all_records, True
        if len(all_records) >= max_total_records:
            logger.warning(
                f"[_query_activity_logs_with_pagination] 达到全量上限 {max_total_records}，停止翻页"
            )
            return all_records[:max_total_records], True
        offset += len(records)
    logger.warning(
        f"[_query_activity_logs_with_pagination] 达到翻页上限 {max_pages} 页，已查 {len(all_records)} 条"
    )
    return all_records, False


def _extract_user_from_record(record: dict) -> str:
    email = (record.get("email") or "").strip()
    if email and "@" in email:
        return email
    ro = (record.get("resourceOwner") or "").strip()
    if ro and "@" in ro:
        return ro
    return ""


def _infer_record_activity(record: dict, props: dict, fallback: list[str]) -> str:
    for k in ("activity", "action", "actionType", "eventType", "type", "category"):
        v = record.get(k)
        if v:
            return str(v)
    if props.get("url"):
        return "THREATPOLICY_URL_ACCESS"
    if props.get("attachmentName"):
        for k in ("isBig", "bigAttachment", "isLargeAttachment"):
            if props.get(k):
                return "BIG_ATTACHMENT_DOWNLOAD"
        return "ATTACHMENT_DOWNLOAD"
    return fallback[0] if fallback else ""


def build_attachment_patterns(attachment_names: list[str]) -> list[str]:
    patterns: set[str] = set()
    for name in attachment_names or []:
        if not name:
            continue
        base = name.strip().rsplit(".", 1)[0] if "." in name else name.strip()
        if len(base) < 3:
            continue
        patterns.add(f"*{base}*")
        tokens = [t for t in re.split(r"[_\-\s\.]+", base) if len(t) >= 4 and not t.isdigit()]
        if tokens:
            core = max(tokens, key=len)
            if len(core) >= 4:
                patterns.add(f"*{core}*")
    return list(patterns)[:BEHAVIOR_MAX_ATTACHMENT_PATTERNS]


def build_url_patterns(domains: list[str]) -> list[str]:
    patterns: list[str] = []
    for d in domains or []:
        d = (d or "").strip().lower()
        if not d or "." not in d:
            continue
        patterns.append(f"*://{d}/*")
        patterns.append(f"*://{d}")
        patterns.append(f"*://*.{d}/*")
    return patterns[:BEHAVIOR_MAX_URL_PATTERNS]


@tool
async def search_behavior_logs(
    filters: dict,
    activities: list[str] | None = None,
    activity: str | None = None,
    suspicious_domains: str = "[]",
    attack_attachment_names: str = "[]",
) -> str:
    """
    查询用户行为日志（附件下载 / 大附件下载 / URL 访问），返回带风险标签的样本供你判断。

    ★ 系统行为：
    - 自动翻页：has_more 时自动用 offset 翻页，查完全部记录（上限 1w 条）。
    - user 列表分批：user 过滤超过 500 个时自动分批查询。
    - 附件名匹配：传入 attack_attachment_names 后，程序侧会自动把"名字命中攻击附件"的记录升级为 high。
    - 返回 sample_logs 为随机采样的 30 条（真实分布）；同时返回全量统计字段供判断宽泛度。
    """
    if not activities and activity:
        activities = [activity]
    if isinstance(activities, str):
        activities = [activities]
    if not activities:
        return json.dumps({"error": "activities 不能为空"}, ensure_ascii=False)

    _VALID = {"ATTACHMENT_DOWNLOAD", "BIG_ATTACHMENT_DOWNLOAD", "THREATPOLICY_URL_ACCESS"}
    activities = [a for a in activities if a in _VALID]
    if not activities:
        return json.dumps({"error": "activities 无有效值"}, ensure_ascii=False)

    logger.info(f"[search_behavior_logs] 收到调用: activities={activities}, filters={filters}, "
                f"suspicious_domains={suspicious_domains}, attack_attachment_names={attack_attachment_names}")
    print(f"=== [search_behavior_logs] 收到调用: activities={activities}, filters={filters}, "
          f"suspicious_domains={suspicious_domains}, attack_attachment_names={attack_attachment_names} ===", flush=True)

    cleaned_filters, removed_fields = _clean_behavior_filters(activities, filters)
    if removed_fields:
        msg = f"已自动移除 {activities} 不支持的过滤字段: {removed_fields}。"
        logger.warning(f"[search_behavior_logs] {msg}")
        print(f"=== [search_behavior_logs] {msg} ===", flush=True)

    try:
        susp_list = json.loads(suspicious_domains) if isinstance(suspicious_domains, str) else suspicious_domains
        if not isinstance(susp_list, list):
            susp_list = []
        susp_set = {str(s).strip().lower() for s in susp_list if s}
    except Exception:
        susp_set = set()

    try:
        att_list = json.loads(attack_attachment_names) if isinstance(attack_attachment_names, str) else attack_attachment_names
        if not isinstance(att_list, list):
            att_list = []
        att_names = [str(a).strip() for a in att_list if a and str(a).strip()]
    except Exception:
        att_names = []

    try:
        user_filter = cleaned_filters.get("user")
        user_list = None
        if user_filter:
            try:
                user_list = json.loads(user_filter) if isinstance(user_filter, str) else user_filter
                if not isinstance(user_list, list):
                    user_list = None
            except Exception:
                user_list = None

        all_records: list[dict] = []
        fully_fetched = True

        if user_list and len(user_list) > _MAX_USER_PER_BATCH:
            total_batches = (len(user_list) + _MAX_USER_PER_BATCH - 1) // _MAX_USER_PER_BATCH
            logger.info(f"[search_behavior_logs] user 列表 {len(user_list)} 个，分 {total_batches} 批查询")
            for i in range(0, len(user_list), _MAX_USER_PER_BATCH):
                batch = user_list[i:i + _MAX_USER_PER_BATCH]
                batch_filters = {**cleaned_filters, "user": json.dumps(batch, ensure_ascii=False)}
                batch_records, batch_ok = await _query_activity_logs_with_pagination(activities, batch_filters)
                all_records.extend(batch_records)
                if not batch_ok:
                    fully_fetched = False
        else:
            all_records, fully_fetched = await _query_activity_logs_with_pagination(activities, cleaned_filters)

        all_items: list[dict] = []
        high_risk_users: list[dict] = []
        seen_high: set[str] = set()
        risk_hit_count = 0
        low_risk_count = 0
        per_activity_count: dict[str, int] = {}

        for r in all_records:
            user = _extract_user_from_record(r)
            if not user:
                continue
            props = r.get("properties", {}) or {}
            rec_activity = _infer_record_activity(r, props, activities)
            per_activity_count[rec_activity] = per_activity_count.get(rec_activity, 0) + 1

            if props.get("url"):
                url = props.get("url", "") or ""
                risk, reason = _classify_url_risk(url, susp_set)
                item = {
                    "activity": rec_activity,
                    "user": user,
                    "url": url[:200],
                    "subject": (props.get("subject") or "")[:80],
                    "ip": r.get("ip", ""),
                    "time": r.get("timestamp", ""),
                    "risk": risk,
                    "reason": reason,
                }
            elif props.get("attachmentName"):
                an = props.get("attachmentName", "") or ""
                risk, reason = _classify_attachment_risk(an)

                matched, match_reason = _match_attack_attachment(an, att_names)
                if matched:
                    if risk == "low":
                        risk, reason = "high", match_reason
                    elif risk == "medium":
                        risk = "high"
                        reason = f"{reason}；{match_reason}"
                    else:
                        reason = f"{reason}；{match_reason}"

                item = {
                    "activity": rec_activity,
                    "user": user,
                    "attachment_name": an[:200],
                    "size": props.get("attachmentSize", ""),
                    "ip": r.get("ip", ""),
                    "time": r.get("timestamp", ""),
                    "risk": risk,
                    "reason": reason,
                }
            else:
                item = {
                    "activity": rec_activity,
                    "user": user,
                    "ip": r.get("ip", ""),
                    "time": r.get("timestamp", ""),
                    "risk": "low",
                    "reason": "",
                }

            all_items.append(item)

            if item["risk"] == "low":
                low_risk_count += 1
            else:
                risk_hit_count += 1
                k = user.lower()
                if k not in seen_high:
                    seen_high.add(k)
                    high_risk_users.append({
                        "user": user,
                        "risk": item["risk"],
                        "reason": item.get("reason", ""),
                        "activity": rec_activity,
                        "url": item.get("url"),
                        "attachment_name": item.get("attachment_name"),
                        "ip": item.get("ip", ""),
                        "time": item.get("time", ""),
                    })

        sample_logs = _random_sample(all_items, _SAMPLE_SIZE)
        sample_high_count = sum(1 for s in sample_logs if s.get("risk") in ("high", "medium"))

        valid_total = len(all_items)
        high_risk_rate = round(risk_hit_count / valid_total, 4) if valid_total else 0.0
        filter_scope = _infer_filter_scope(cleaned_filters)

        print(
            f"=== [search_behavior_logs] activities={activities} | 全量 {len(all_records)} | "
            f"valid={valid_total} | high={risk_hit_count} (rate={high_risk_rate}) | low={low_risk_count} | "
            f"sample_total={len(sample_logs)} | sample_high={sample_high_count} | "
            f"filter_scope={filter_scope} | fully_fetched={fully_fetched} ===",
            flush=True,
        )
        logger.info(
            f"[search_behavior_logs] activities={activities} | 全量 {len(all_records)} | "
            f"valid={valid_total} | high={risk_hit_count} (rate={high_risk_rate}) | low={low_risk_count} | "
            f"sample_total={len(sample_logs)} | sample_high={sample_high_count} | "
            f"filter_scope={filter_scope} | fully_fetched={fully_fetched}"
        )

        return json.dumps({
            "activities": activities,
            "raw_returned": len(all_records),
            "valid_returned": valid_total,
            "risk_hit_count": risk_hit_count,
            "low_risk_count": low_risk_count,
            "high_risk_count": risk_hit_count,
            "high_risk_rate": high_risk_rate,
            "high_risk_users": high_risk_users,
            "per_activity_count": per_activity_count,
            "hasMore": not fully_fetched,
            "fully_fetched": fully_fetched,
            "applied_filters": cleaned_filters,
            "removed_unsupported_fields": removed_fields,
            "filter_scope": filter_scope,
            "sample_logs": sample_logs,
            "sample_total": len(sample_logs),
            "sample_high_count": sample_high_count,
            "note": (
                "sample_logs 为随机采样，sample_high_count 是采样中命中数；"
                "high_risk_count 是全量命中数；high_risk_rate = high / valid；"
                "filter_scope 标识 filter 是宽泛型(broad)还是精确型(narrow)。"
            ),
        }, ensure_ascii=False)

    except Exception as e:
        logger.error(f"[search_behavior_logs] 行为日志查询失败: {e}")
        return json.dumps({"error": str(e), "sample_logs": []}, ensure_ascii=False)