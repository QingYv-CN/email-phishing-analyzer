"""邮件投递日志查询（MAIL_RECEIVED）。"""

import json
import logging
import re
from datetime import datetime, timedelta, timezone

import httpx
from langchain_core.tools import tool

from log_query.common import (
    LOG_BASE_URL, BANNED_EXTENSIONS,
    _MAX_TOTAL_RECORDS, _MAX_PAGES, _SAMPLE_SIZE,
    _random_sample, _get_log_token, _get_domain,
    _is_whitelist_mailfrom, _contains_internal_domain,
)

logger = logging.getLogger("log_query.mail_logs")


@tool
@tool
async def search_mail_logs(filters: dict, offset: int = 0) -> str:
    _ = offset

    # ★ 硬性要求：MAIL_RECEIVED 只看外部邮件，内部域噪音不占 _MAX_TOTAL_RECORDS 配额
    # 不依赖 LLM 传，不管 LLM 传什么，都强制覆盖
    filters = dict(filters or {})
    _FORCED_DIRECTIONS = "from-outside"
    if filters.get("directions") != _FORCED_DIRECTIONS:
        if filters.get("directions"):
            logger.warning(
                f"[search_mail_logs] LLM 传入 directions={filters.get('directions')!r}，"
                f"强制改为 {_FORCED_DIRECTIONS!r}"
            )
        filters["directions"] = _FORCED_DIRECTIONS

    print(f"=== [search_mail_logs] LLM 调用日志查询 | Filters={filters} ===", flush=True)
    logger.info(f"[search_mail_logs] 收到调用: filters={filters}")

    if "attachmentName" in filters:
        att_val = filters["attachmentName"]
        try:
            att_list = json.loads(att_val) if isinstance(att_val, str) else att_val
            if isinstance(att_list, list) and all(ext in BANNED_EXTENSIONS for ext in att_list):
                err_msg = f"拦截：不允许仅用纯后缀 {att_list} 查询附件！"
                print(f"=== [search_mail_logs] {err_msg} ===", flush=True)
                logger.warning(f"[search_mail_logs] {err_msg}")
                return json.dumps({
                    "error": err_msg, "hasMore": False, "raw_returned": 0,
                    "filtered_out_internal": 0, "spoofed_internal_count": 0,
                    "dirty_count": 0, "valid_returned": 0,
                    "sample_logs": [], "all_users": [],
                }, ensure_ascii=False)
        except Exception:
            pass

    now = datetime.now(timezone.utc)
    begin_time = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    all_simplified: list[dict] = []
    total_raw = 0
    total_filtered_out = 0
    total_spoofed = 0
    total_dirty = 0
    api_offset = 0

    try:
        token = await _get_log_token()
    except Exception as e:
        logger.error(f"[search_mail_logs] 获取 token 失败: {e}")
        return json.dumps({
            "error": str(e), "hasMore": False, "raw_returned": 0,
            "filtered_out_internal": 0, "spoofed_internal_count": 0,
            "dirty_count": 0, "valid_returned": 0,
            "sample_logs": [], "all_users": [],
        })

    url = f"{LOG_BASE_URL}/rpc/v2/report/records/"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    for page_idx in range(_MAX_PAGES):
        if total_raw >= _MAX_TOTAL_RECORDS:
            logger.warning(f"[search_mail_logs] 达到全量上限 {_MAX_TOTAL_RECORDS}，停止翻页")
            break

        payload = {
            "activities": ["MAIL_RECEIVED"],
            "beginTimestamp": begin_time,
            "endTimestamp": end_time,
            "offset": api_offset,
            "length": 500,
            "filters": filters,
        }
        logger.info(f"[search_mail_logs] 第 {page_idx + 1} 页 payload: {json.dumps(payload, ensure_ascii=False)}")
        print(f"=== [search_mail_logs] 第 {page_idx + 1} 页 payload: {json.dumps(payload, ensure_ascii=False)} ===", flush=True)

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.error(f"[search_mail_logs] 第 {page_idx + 1} 页查询失败: {e}")
            break

        records = data.get("records", []) or []
        has_more = data.get("hasMore", False)
        total_raw += len(records)

        for r in records:
            props = r.get("properties", {})
            mail_from = props.get("mailFrom", "")
            from_display = props.get("from", "")
            subject = props.get("subject", "")

            if _is_whitelist_mailfrom(mail_from):
                total_filtered_out += 1
                continue

            is_spoofed = False
            if _contains_internal_domain(from_display) or _contains_internal_domain(props.get("replyTo", "")):
                is_spoofed = True
                total_spoofed += 1

            is_dirty = False
            if _get_domain(mail_from) in {"163.com", "qq.com"} and not is_spoofed:
                if len(re.findall(r'[\u4e00-\u9fa5]', subject)) > 5:
                    is_dirty = True
                    total_dirty += 1

            to_field = props.get("to", "")
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', to_field)
            user = emails[0] if emails else (r.get("resourceOwner", "") or "未知收件人")

            all_simplified.append({
                "user": user,
                "mailFrom": mail_from,
                "from": from_display,
                "subject": subject[:50],
                "time": r.get("timestamp"),
                "is_spoofed_internal": is_spoofed,
                "is_dirty": is_dirty,
            })

        if not has_more or not records:
            logger.info(f"[search_mail_logs] 翻页完成：{page_idx + 1} 页，原始 {total_raw} 条")
            break
        api_offset += len(records)

    sample_logs = _random_sample(all_simplified, _SAMPLE_SIZE)

    print(
        f"=== [search_mail_logs] 全量原始 {total_raw} 条 | 排除内部白名单 {total_filtered_out} 条 | "
        f"伪装内部 {total_spoofed} 条 | 疑似脏数据 {total_dirty} 条 | "
        f"有效 {len(all_simplified)} 条 | 采样 {len(sample_logs)} 条 ===",
        flush=True,
    )
    logger.info(
        f"[search_mail_logs] 全量原始 {total_raw} 条 | 排除内部白名单 {total_filtered_out} 条 | "
        f"伪装内部 {total_spoofed} 条 | 疑似脏数据 {total_dirty} 条 | "
        f"有效 {len(all_simplified)} 条 | 采样 {len(sample_logs)} 条"
    )

    return json.dumps({
        "hasMore": False,
        "raw_returned": total_raw,
        "filtered_out_internal": total_filtered_out,
        "spoofed_internal_count": total_spoofed,
        "dirty_count": total_dirty,
        "valid_returned": len(all_simplified),
        "sample_logs": sample_logs,
        "all_users": all_simplified,
        "note": (
            "sample_logs 为随机采样，用于 LLM 判断查询宽泛度；"
            "all_users 是全量有效记录，供程序构建受害者名单，LLM 无需读取。"
        ),
    }, ensure_ascii=False)