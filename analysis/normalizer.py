"""LLM 结果归一化 + 程序 IOC 补充。"""

import json
import logging

from analysis.ioc import supplement_ioc_urls

logger = logging.getLogger("analysis.normalizer")


VERDICT_MAP = {"高危": "high", "可疑": "suspicious", "低危": "low", "正常": "clean", "未知": "unknown"}
CONFIDENCE_MAP = {"高": "high", "中": "medium", "低": "low"}
RISK_MAP = {"高": "high", "中": "medium", "低": "low"}


def parse_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw_output": text, "parse_error": True}


def norm_verdict(v) -> tuple[str, str]:
    if not v:
        return "未知", "unknown"
    for cn, en in VERDICT_MAP.items():
        if v.strip() == cn or v.strip().lower() == en:
            return cn, en
    return "未知", "unknown"


def norm_confidence(v) -> tuple[str, str]:
    if not v:
        return "低", "low"
    for cn, en in CONFIDENCE_MAP.items():
        if v.strip() == cn or v.strip().lower() == en:
            return cn, en
    return "低", "low"


def norm_risk(v) -> tuple[str, str]:
    if not v:
        return "中", "medium"
    for cn, en in RISK_MAP.items():
        if v.strip() == cn or v.strip().lower() == en:
            return cn, en
    return "中", "medium"


def normalize_success(raw_result: dict, meta: dict, data: dict | None = None) -> dict:
    verdict_cn, verdict_code = norm_verdict(raw_result.get("verdict"))
    confidence_cn, confidence_code = norm_confidence(raw_result.get("confidence"))
    evidence = []
    for ev in raw_result.get("evidence") or []:
        if isinstance(ev, dict):
            risk_cn, risk_code = norm_risk(ev.get("risk"))
            evidence.append({
                "dimension": str(ev.get("dimension", "")).strip(),
                "finding": str(ev.get("finding", "")).strip(),
                "risk": risk_cn,
                "risk_code": risk_code,
            })
    ioc = raw_result.get("ioc_details") or {}
    advice = raw_result.get("advice") or {}

    llm_urls = ioc.get("urls") or []
    if not isinstance(llm_urls, list):
        llm_urls = []

    supplemented_urls: list[dict] = []
    if data:
        supplemented_urls = supplement_ioc_urls(data, llm_urls)
        if supplemented_urls:
            logger.info(
                f"[{meta.get('request_id', '')}] 程序补充 IOC URL {len(supplemented_urls)} 条: "
                f"{[s['real'] for s in supplemented_urls[:5]]}"
            )

    all_urls = llm_urls + supplemented_urls

    return {
        "success": True,
        "request_id": meta["request_id"],
        "timestamp": meta["timestamp"],
        "elapsed_ms": meta["elapsed_ms"],
        "result": {
            "verdict": verdict_cn,
            "verdict_code": verdict_code,
            "confidence": confidence_cn,
            "confidence_code": confidence_code,
            "confidence_basis": str(raw_result.get("confidence_basis", "")).strip(),
            "summary": str(raw_result.get("summary", "")).strip(),
            "evidence": evidence,
            "ioc_details": {
                "urls": all_urls,
                "attachments": ioc.get("attachments") or [],
                "qr_codes": ioc.get("qr_codes") or [],
                "image_texts": ioc.get("image_texts") or [],
            },
            "advice": {
                "immediate": str(advice.get("immediate", "")).strip(),
                "followup": str(advice.get("followup", "")).strip(),
                "manual_confirm": str(advice.get("manual_confirm", "")).strip(),
            },
        },
        "meta": {
            "model": meta["model"],
            "email_length": meta["email_length"],
            "image_count": meta["image_count"],
            "attachment_count": meta["attachment_count"],
            "url_count": meta["url_count"],
            "llm_tokens": meta["llm_tokens"],
            "mail_from": meta.get("mail_from", ""),
            "envelope_from": meta.get("envelope_from", ""),
            "sender_name": meta.get("sender_name", ""),
            "subject": meta.get("subject", ""),
            "email_timestamp": meta.get("email_timestamp", 0),
            "email_date": meta.get("email_date", ""),
            "raw_urls": data.get("urls", []) if data else [],
        },
    }


def normalize_error(code: str, message: str, meta: dict) -> dict:
    return {
        "success": False,
        "request_id": meta.get("request_id", ""),
        "timestamp": meta.get("timestamp", ""),
        "elapsed_ms": meta.get("elapsed_ms", 0),
        "error": {"code": code, "message": message},
    }