"""analyzer 的固定流水线：解析 → 情报 → 图片 / 附件 → LLM → 交叉验证 → 落库。"""

import asyncio
import json
import logging
import time
import urllib.parse

import db_manager
from config import (
    LLM_MODEL, LLM_TIMEOUT,
    EMAIL_PARSE_TIMEOUT, IMAGE_STEP_TIMEOUT, ATTACHMENT_TIMEOUT,
    MAX_IMAGES, MAX_OCR_CHARS, MAX_URLS,
)
from tools.email_parser import parse_email
from tools.image_analyzer import extract_images_content
from tools.sandbox import analyze_attachment
from tools.vt_intel import get_batch_domain_intel, get_batch_ip_intel
from tools.safe_domain_whitelist import is_whitelisted

from analysis.runtime import runtime, _run_blocking
from analysis.prompts import SYSTEM_PROMPT
from analysis.url_utils import extract_urls_from_href
from analysis.normalizer import (
    parse_json, normalize_success, normalize_error,
)
from analysis.rules import (
    is_mail_too_old, parse_email_date, is_trusted_whitelisted,
    rule_based_check, attachment_force_verdict,
)

logger = logging.getLogger("analysis.pipeline")


async def _step_parse_email(email_content: str, req_id: str) -> dict:
    logger.info(f"[{req_id}] → parse_email | 输入长度={len(email_content)}")
    try:
        result = await asyncio.wait_for(
            _run_blocking(parse_email, email_content), timeout=EMAIL_PARSE_TIMEOUT
        )
        if result.get("status") == "success" and result.get("data"):
            logger.info(f"[{req_id}] ← parse_email | 发件人={result['data'].get('sender', '')}")
        return result
    except Exception as e:
        logger.error(f"[{req_id}] ← parse_email | 异常: {e}")
        raise


async def _step_images(images: list[dict], req_id: str) -> dict | None:
    if not images:
        return None
    paths = [img["path"] for img in images[:MAX_IMAGES]]
    try:
        async with runtime.ocr_sem:
            return await asyncio.wait_for(
                _run_blocking(extract_images_content, paths), timeout=IMAGE_STEP_TIMEOUT
            )
    except Exception as e:
        logger.error(f"[{req_id}] ← extract_images | 异常: {e}")
        raise


async def _step_attachments(attachments: list[dict], req_id: str) -> dict | None:
    if not attachments:
        return None
    try:
        return await asyncio.wait_for(
            _run_blocking(analyze_attachment, attachments), timeout=ATTACHMENT_TIMEOUT
        )
    except Exception as e:
        logger.error(f"[{req_id}] ← analyze_attachment | 异常: {e}")
        raise


def _sanitize_for_prompt(text: str) -> str:
    return text[:2000] if text else ""


def _build_user_prompt(data: dict, image_result: dict | None, attachment_result: dict | None) -> str:
    headers = data.get("headers") or {}
    lines = [
        "# 邮件基本信息",
        f"发件人地址（From 头）：{data.get('sender', '')}",
        f"发件人显示名：{data.get('sender_name', '')}",
        f"真实发件人（envelope from）：{data.get('envelope_from', '') or '（无法提取）'}",
        f"主题：{data.get('subject', '')}",
        f"发送时间：{data.get('date', '')}",
        "",
        "# 邮件头与认证",
        f"authentication_results：{headers.get('authentication_results', '未提供')}",
    ]
    lines += ["received 链路："] + [f"  - {r}" for r in headers.get("received", [])[:5]]

    raw_text = data.get("body_text") or ""
    raw_html = data.get("body_html") or ""

    lines += [
        "# 正文（纯文本，仅前 2000 字符）",
        "<<<EMAIL_DATA_START>>>",
        _sanitize_for_prompt(raw_text) or "（无）",
        "<<<EMAIL_DATA_END>>>",
        "# 正文（HTML，仅前 2000 字符）",
        "<<<EMAIL_DATA_START>>>",
        _sanitize_for_prompt(raw_html) or "（无）",
        "<<<EMAIL_DATA_END>>>",
    ]

    domain_intel = data.get("domain_intel", {})
    ip_intel = data.get("ip_intel", {})

    lines += ["", "# 提取到的 URL 及 VirusTotal 情报"]
    urls = data.get("urls", [])[:MAX_URLS]
    if urls:
        for u in urls:
            try:
                d = urllib.parse.urlparse(u).netloc.lower()
                if d.startswith("www."):
                    d = d[4:]
                if is_whitelisted(d):
                    lines.append(f"  - {u} [已加入安全白名单，不可作为恶意依据]")
                    continue
                intel = domain_intel.get(d, {})
                lines.append(f"  - {u} [VT情报: {json.dumps(intel, ensure_ascii=False)}]")
            except Exception:
                lines.append(f"  - {u}")
    else:
        lines.append("  （无）")

    lines += ["", "# 提取到的 IP 及 VirusTotal 情报"]
    ips = data.get("ips", [])[:20]
    if ips:
        for ip in ips:
            intel = ip_intel.get(ip, {})
            lines.append(f"  - {ip} [VT情报: {json.dumps(intel, ensure_ascii=False)}]")
    else:
        lines.append("  （无）")

    if image_result:
        lines += ["", f"# 图片分析（共 {image_result.get('total_images', 0)} 张）"]
        for item in image_result.get("results", []):
            ocr = (item.get("ocr_text") or "")[:MAX_OCR_CHARS]
            if ocr:
                lines.append(f"图片 {item.get('image')} OCR: {ocr}")
            for qr in item.get("qr_codes", []):
                lines.append(f"  二维码: {qr.get('text', '')}")
    else:
        lines += ["", "# 图片分析", "（无图片）"]

    if attachment_result:
        lines += ["", f"# 附件结构（共 {attachment_result.get('total', 0)} 个）"]
        lines.append(json.dumps(attachment_result, ensure_ascii=False, indent=2))
    else:
        lines += ["", "# 附件结构", "（无附件）"]

    lines += ["", "请基于以上信息，按系统提示中的分析框架输出最终 JSON 结论。"]
    return "\n".join(lines)


async def _call_llm(user_prompt: str, req_id: str) -> tuple[str, dict]:
    resp = await asyncio.wait_for(
        runtime.llm_client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            timeout=LLM_TIMEOUT,
        ),
        timeout=LLM_TIMEOUT + 5,
    )
    usage_obj = getattr(resp, "usage", None)
    usage = {"total": getattr(usage_obj, "total_tokens", 0) if usage_obj else 0}
    return resp.choices[0].message.content or "", usage


async def pipeline(email_content: str, req_id: str, meta: dict, t0: float) -> dict:
    parsed = await _step_parse_email(email_content, req_id)
    if parsed.get("status") != "success" or not parsed.get("data"):
        meta["elapsed_ms"] = int((time.time() - t0) * 1000)
        return normalize_error("PARSE_FAILED", parsed.get("message", "解析失败"), meta)

    data = parsed["data"]

    html_urls = extract_urls_from_href(data.get("body_html", ""))
    if html_urls:
        existing = {u.strip().lower() for u in data.get("urls", [])}
        added = 0
        for u in html_urls:
            key = u.strip().lower()
            if key not in existing:
                data["urls"].append(u)
                existing.add(key)
                added += 1
        if added:
            logger.info(f"[{req_id}] 从 HTML href 补充 {added} 条 URL，当前共 {len(data['urls'])} 条")

    if is_trusted_whitelisted(data):
        meta["elapsed_ms"] = int((time.time() - t0) * 1000)
        return {
            "success": True,
            "request_id": req_id,
            "timestamp": meta["timestamp"],
            "elapsed_ms": meta["elapsed_ms"],
            "result": {
                "verdict": "正常",
                "verdict_code": "clean",
                "confidence": "高",
                "confidence_code": "high",
                "confidence_basis": "基于白名单",
                "summary": f"发件人白名单通过：{data.get('sender')}",
                "evidence": [],
                "ioc_details": {"urls": [], "attachments": [], "qr_codes": [], "image_texts": []},
                "advice": {"immediate": "无", "followup": "无", "manual_confirm": "无"},
            },
            "meta": {
                "model": "whitelist_skip",
                "email_length": meta["email_length"],
                "image_count": 0,
                "attachment_count": 0,
                "url_count": 0,
                "llm_tokens": {"prompt": 0, "completion": 0, "total": 0},
                "mail_from": data.get("sender", ""),
                "envelope_from": data.get("envelope_from", ""),
                "sender_name": data.get("sender_name", ""),
                "subject": data.get("subject", ""),
                "raw_urls": data.get("urls", []),
            },
        }

    domains_to_check = set()
    for u in data.get("urls", []):
        try:
            d = urllib.parse.urlparse(u).netloc.lower()
            if d.startswith("www."):
                d = d[4:]
            if d:
                domains_to_check.add(d)
        except Exception:
            pass
    ips_to_check = set(data.get("ips", []))

    real_domains = {d for d in domains_to_check if not is_whitelisted(d)}
    domain_intel = await get_batch_domain_intel(real_domains)
    for d in (domains_to_check - real_domains):
        domain_intel[d] = {
            "is_safe": True,
            "worst_category": "whitelisted",
            "categories": ["whitelisted"],
            "source": "safe_domain_whitelist",
        }
    ip_intel = await get_batch_ip_intel(ips_to_check)

    data["domain_intel"] = domain_intel
    data["ip_intel"] = ip_intel

    meta["image_count"] = len(data.get("images", []))
    meta["attachment_count"] = len(data.get("attachments", []))
    meta["url_count"] = len(data.get("urls", []))
    meta["mail_from"] = data.get("sender", "")
    meta["envelope_from"] = data.get("envelope_from", "") or ""
    meta["sender_name"] = data.get("sender_name", "") or ""
    meta["subject"] = data.get("subject", "") or ""
    meta["email_timestamp"] = parse_email_date(data.get("date", "")) or 0
    meta["email_date"] = data.get("date", "") or ""

    image_task = asyncio.create_task(_step_images(data.get("images", []), req_id))
    attachment_task = asyncio.create_task(_step_attachments(data.get("attachments", []), req_id))
    image_result, attachment_result = await asyncio.gather(image_task, attachment_task)

    user_prompt = _build_user_prompt(data, image_result, attachment_result)
    async with runtime.llm_sem:
        raw, usage = await _call_llm(user_prompt, req_id)

    meta["llm_tokens"] = usage
    raw_result = parse_json(raw)
    meta["elapsed_ms"] = int((time.time() - t0) * 1000)

    if raw_result.get("parse_error"):
        rule = rule_based_check(data, image_result, attachment_result)
        if rule["rule_verdict"] in ("可疑", "高危"):
            return normalize_error("LLM_OUTPUT_INVALID_BUT_RISKY", f"LLM输出异常，规则判为{rule['rule_verdict']}", meta)
        return normalize_error("LLM_OUTPUT_INVALID", "模型返回无法解析为 JSON", meta)

    normalized = normalize_success(raw_result, meta, data)
    r = normalized["result"]

    if attachment_result:
        sandbox_map = {}
        for sr in attachment_result.get("results", []):
            fn = sr.get("filename")
            if fn:
                sandbox_map[fn.lower()] = sr
        att_list = r["ioc_details"]["attachments"]
        seen_fns = set()
        for att in att_list:
            if not isinstance(att, dict):
                continue
            fn = (att.get("filename") or "").lower()
            seen_fns.add(fn)
            sr = sandbox_map.get(fn)
            if sr:
                att["file_type_check"] = sr.get("file_type_check")
                att["risk_level"] = sr.get("risk_level")
        for fn_lower, sr in sandbox_map.items():
            if fn_lower in seen_fns:
                continue
            att_list.append({
                "filename": sr.get("filename"),
                "type": sr.get("ext") or "",
                "file_type_check": sr.get("file_type_check"),
                "risk_level": sr.get("risk_level"),
            })

    rule = rule_based_check(data, image_result, attachment_result)
    if r["verdict"] in ("正常", "低危") and rule["rule_verdict"] in ("可疑", "高危"):
        r["verdict"] = "可疑"
        r["verdict_code"] = "suspicious"
        r["confidence"] = "中"
        r["confidence_code"] = "medium"
        r["evidence"].append({
            "dimension": "规则交叉验证",
            "finding": f"规则判为{rule['rule_verdict']}",
            "risk": "中",
            "risk_code": "medium",
        })

    att_check = attachment_force_verdict(attachment_result)
    if att_check["force_high"] and r["verdict_code"] != "high":
        r["verdict"] = "高危"
        r["verdict_code"] = "high"
        r["confidence"] = "高"
        r["confidence_code"] = "high"
        r["evidence"].append({
            "dimension": "附件文件类型欺骗",
            "finding": "；".join(att_check["reasons"]),
            "risk": "高",
            "risk_code": "high",
        })
    elif att_check["force_suspicious"] and r["verdict_code"] in ("clean", "low"):
        r["verdict"] = "可疑"
        r["verdict_code"] = "suspicious"
        r["confidence"] = "中"
        r["confidence_code"] = "medium"
        r["evidence"].append({
            "dimension": "附件文件类型不一致",
            "finding": "；".join(att_check["reasons"]),
            "risk": "中",
            "risk_code": "medium",
        })

    if normalized.get("success"):
        mail_date = data.get("date", "")
        if not is_mail_too_old(mail_date):
            try:
                db_manager.save_analysis_result(req_id, normalized, meta.get("mail_from", ""))
            except Exception as e:
                logger.error(f"[{req_id}] 写入数据池失败: {e}")

    logger.info(f"[{req_id}] 完成 | 结论={r['verdict']}")
    return normalized