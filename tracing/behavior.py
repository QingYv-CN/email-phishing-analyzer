import asyncio
import json
import logging
import re
import time

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI

from config import (
    LLM_API_BASE, LLM_API_KEY, LLM_MODEL,
    MAX_TOOL_CALLS_PER_CAMPAIGN, BEHAVIOR_CONCURRENCY,
    LLM_MAX_RETRIES, LLM_RETRY_BASE_DELAY,
)
from tools.mail_log_searcher import search_behavior_logs
from tools.safe_domain_whitelist import is_whitelisted
from trace_stats import run_stats
import tracing.progress as P
from tracing.prompts import BEHAVIOR_SYSTEM_PROMPT
from tracing.alerts import _aggregate_risk_users

logger = logging.getLogger("tracing.behavior")


_behavior_llm_instance = None
_behavior_llm_lock = asyncio.Lock()


async def _get_behavior_llm():
    global _behavior_llm_instance
    async with _behavior_llm_lock:
        if _behavior_llm_instance is None:
            _behavior_llm_instance = ChatOpenAI(
                api_key=LLM_API_KEY,
                base_url=LLM_API_BASE,
                model=LLM_MODEL,
                temperature=0.1,
                timeout=90,
            ).bind_tools([search_behavior_logs])
    return _behavior_llm_instance


async def _invoke_behavior_llm(llm_behavior, messages, camp_name: str):
    for attempt in range(LLM_MAX_RETRIES):
        prompt_len = sum(len(str(getattr(m, "content", "") or "")) for m in messages)
        run_stats.add("prompt_total", prompt_len)
        run_stats.max("prompt_max", prompt_len)
        run_stats.inc("llm_calls")
        try:
            return await llm_behavior.ainvoke(messages)
        except Exception as e:
            run_stats.inc("llm_fails")
            if isinstance(e, asyncio.TimeoutError) or "timeout" in str(e).lower():
                run_stats.inc("llm_timeouts")
            if attempt < LLM_MAX_RETRIES - 1:
                run_stats.inc("llm_retries")
                delay = LLM_RETRY_BASE_DELAY * (2 ** attempt)
                print(
                    f"=== [Behavior] LLM 失败，{delay}s 后重试 "
                    f"({attempt + 1}/{LLM_MAX_RETRIES}) campaign={camp_name}: {e} ===",
                    flush=True,
                )
                await asyncio.sleep(delay)
            else:
                print(
                    f"=== [Behavior] LLM 失败（放弃），campaign={camp_name}: {e} ===",
                    flush=True,
                )
                return None
    return None


def _parse_final_decision(text: str) -> tuple[list[str], str, bool]:
    if not text:
        return [], "empty_response", False

    text_clean = text.strip()
    if text_clean.startswith("```"):
        text_clean = text_clean.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

    try:
        start = text_clean.index("{")
        end = text_clean.rindex("}") + 1
        obj = json.loads(text_clean[start:end])
        decision = str(obj.get("final_decision", "")).lower().strip()
        confirmed = obj.get("confirmed_users", [])
        reason = str(obj.get("reason", ""))

        if not isinstance(confirmed, list):
            confirmed = []
        confirmed = [str(u).strip() for u in confirmed if u]

        if decision == "reject":
            return [], reason or "llm_reject", True

        return confirmed, reason, False
    except Exception:
        pass

    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text_clean)
    if emails:
        return emails, "fallback_regex", False

    return [], "parse_failed", False


async def _run_behavior_agent(
    camp: dict,
    activities: list[str],
    kind: str,
    victim_users: list[str],
) -> list[dict]:
    features = camp.get("features", {}) or {}
    att_names = features.get("attachment_names", []) or []
    domains = [d for d in (features.get("domains", []) or []) if not is_whitelisted(d)]
    subjects = features.get("subjects", []) or []

    if kind == "attachment" and not att_names:
        return []
    if kind == "url" and not domains:
        return []
    if not activities:
        return []

    hint = {
        "campaign": camp.get("name"),
        "activities": activities,
        "attack_attachment_names": att_names,
        "attack_domains": domains,
        "attack_subjects": subjects[:5],
        "victim_users_preview": victim_users[:30],
        "victim_users_total": len(victim_users),
        "supported_filters": ["user", "email", "resourceOwner", "subject", "ip"],
        "note": (
            f"当前 activities={activities}。日志接口不支持 attachmentName 或 url 过滤。"
            "**优先用 subject 过滤**；subject 查不到时系统会自动用完整 victim_users 补 user 过滤。"
            "返回结果请重点看：filter_scope / valid_returned / high_risk_count / high_risk_rate / sample_high_count。"
            "综合判断是否宽泛：narrow 有命中 → accept；broad 且 total>100 且 rate<5% → reject。"
            "不要从采样里找被漏掉的 high。"
        ),
    }

    messages = [
        SystemMessage(content=BEHAVIOR_SYSTEM_PROMPT),
        HumanMessage(content=json.dumps(hint, ensure_ascii=False)),
    ]
    llm_behavior = await _get_behavior_llm()

    all_confirmed_by_rule: dict[str, dict] = {}
    tool_call_count = 0
    final_response = None
    susp_domains_json = json.dumps(domains, ensure_ascii=False)
    att_names_json = json.dumps(att_names, ensure_ascii=False)
    camp_name = camp.get("name", "")

    def _build_confirm_entry(
        u: dict,
        llm_approved: bool,
        llm_reason: str = "",
        fallback: bool = False,
    ) -> dict:
        entry = {
            "user": u.get("user", ""),
            "risk": u.get("risk", "medium"),
            "reason": u.get("reason", ""),
            "activity": u.get("activity") or (activities[0] if activities else ""),
            "campaign": camp_name,
            "llm_approved": llm_approved,
            "ip": u.get("ip", ""),
            "time": u.get("time", ""),
        }
        if u.get("url"):
            entry["url"] = u["url"]
        if u.get("attachment_name"):
            entry["attachment_name"] = u["attachment_name"]
        if fallback:
            entry["fallback"] = True
        if llm_reason:
            entry["llm_reason"] = llm_reason
        return entry

    while tool_call_count < MAX_TOOL_CALLS_PER_CAMPAIGN:
        response = await _invoke_behavior_llm(llm_behavior, messages, camp_name)
        if response is None:
            # ★ 不再直接丢弃已收集结果；标记为 LLM 不可用，
            # 跳出循环，走后续"保守兜底（只纳入 risk=high）"分支
            print(
                f"=== [Behavior] LLM 不可用，使用已收集结果兜底 | campaign={camp_name} "
                f"activities={activities} 已收集 {len(all_confirmed_by_rule)} 个用户 ===",
                flush=True,
            )
            logger.warning(
                f"[Behavior] LLM 不可用，使用已收集结果兜底 | campaign={camp_name} "
                f"activities={activities} 已收集 {len(all_confirmed_by_rule)} 个用户"
            )
            break

        messages.append(response)
        tool_calls = getattr(response, "tool_calls", None) or []

        if not tool_calls:
            final_response = response
            break

        for tc in tool_calls:
            if tool_call_count >= MAX_TOOL_CALLS_PER_CAMPAIGN:
                break
            if tc.get("name") != "search_behavior_logs":
                continue

            args = dict(tc.get("args") or {})
            args["activities"] = activities
            args.pop("activity", None)

            if not args.get("suspicious_domains"):
                args["suspicious_domains"] = susp_domains_json
            args["attack_attachment_names"] = att_names_json

            filters = args.get("filters") or {}
            has_specific_filter = any(
                k in filters for k in ("subject", "email", "resourceOwner", "ip")
            )
            if not has_specific_filter and victim_users:
                filters["user"] = json.dumps(victim_users, ensure_ascii=False)
                logger.info(
                    f"[Behavior] 程序覆盖 user 过滤为完整 victim_users | campaign={camp_name} "
                    f"activities={activities} user_count={len(victim_users)}"
                )
            args["filters"] = filters

            logger.info(
                f"[Behavior] 准备调用 search_behavior_logs | campaign={camp_name} "
                f"activities={activities} args={json.dumps(args, ensure_ascii=False)}"
            )
            print(
                f"=== [Behavior] 准备调用 search_behavior_logs | campaign={camp_name} "
                f"activities={activities} args={json.dumps(args, ensure_ascii=False)} ===",
                flush=True,
            )

            try:
                result_str = await search_behavior_logs.ainvoke(args)
            except Exception as e:
                result_str = json.dumps({"error": str(e), "sample_logs": []}, ensure_ascii=False)
            messages.append(ToolMessage(content=result_str, tool_call_id=tc.get("id", "")))
            tool_call_count += 1

            try:
                parsed = json.loads(result_str)
                for u in parsed.get("high_risk_users", []) or []:
                    user = (u.get("user") or "").strip()
                    if user:
                        k = user.lower()
                        if k not in all_confirmed_by_rule:
                            all_confirmed_by_rule[k] = u
            except Exception:
                pass
    else:
        print(
            f"=== [Behavior] tool 次数用完，强制追加最终判定 | campaign={camp_name} "
            f"activities={activities} ===",
            flush=True,
        )
        logger.info(
            f"[Behavior] tool 次数用完，强制追加最终判定 | campaign={camp_name} activities={activities}"
        )
        messages.append(HumanMessage(content=(
            "工具调用次数已用完。请基于以上所有查询结果，输出最终 JSON 判定（不再调用任何工具）。"
            "格式：{\"final_decision\": \"accept\"|\"reject\", \"confirmed_users\": [...], \"reason\": \"...\"}"
        )))
        final_response = await _invoke_behavior_llm(llm_behavior, messages, camp_name)

    llm_users: list[str] = []
    reason = ""
    is_explicit_reject = False

    if final_response is not None:
        content = getattr(final_response, "content", "") or ""
        llm_users, reason, is_explicit_reject = _parse_final_decision(content)
    else:
        # ★ LLM 未给出最终判定（调用失败 / 重试耗尽），触发保守兜底分支
        reason = "no_final_response"

    if is_explicit_reject:
        print(
            f"=== [Behavior] LLM 明确拒绝（判为宽泛 / 无命中）| campaign={camp_name} "
            f"activities={activities} | reason={reason} ===",
            flush=True,
        )
        logger.info(
            f"[Behavior] LLM 明确拒绝 | campaign={camp_name} activities={activities} | reason={reason}"
        )
        return []

    if reason in ("parse_failed", "empty_response", "no_final_response") and not llm_users:
        print(
            f"=== [Behavior] LLM 输出无效（{reason}），保守兜底：只纳入 risk=high | campaign={camp_name} ===",
            flush=True,
        )
        logger.warning(
            f"[Behavior] LLM 输出无效（{reason}），保守兜底：只纳入 risk=high | campaign={camp_name}"
        )
        confirmed = []
        for _k, u in all_confirmed_by_rule.items():
            if u.get("risk") == "high":
                confirmed.append(
                    _build_confirm_entry(u, llm_approved=False, fallback=True, llm_reason=reason)
                )
        return confirmed

    confirmed: list[dict] = []
    llm_confirmed_keys: set[str] = set()
    fabricated: list[str] = []
    for u in llm_users:
        k = u.lower()
        if k in all_confirmed_by_rule:
            llm_confirmed_keys.add(k)
        else:
            fabricated.append(u)
    if fabricated:
        print(
            f"=== [Behavior] LLM 编造/无法校验的用户 {len(fabricated)} 个，已忽略 | campaign={camp_name} ===",
            flush=True,
        )
        logger.warning(
            f"[Behavior] LLM 编造/无法校验的用户 {len(fabricated)} 个，已忽略 | campaign={camp_name}"
        )

    for k, u in all_confirmed_by_rule.items():
        approved = k in llm_confirmed_keys
        confirmed.append(_build_confirm_entry(
            u, llm_approved=approved, llm_reason=reason if approved else ""
        ))

    print(
        f"=== [Behavior] LLM accept → 全量纳入 {len(confirmed)} 个 high/medium 用户"
        f"（其中 LLM 认可 {len(llm_confirmed_keys)} 个）| campaign={camp_name} activities={activities} ===",
        flush=True,
    )
    logger.info(
        f"[Behavior] LLM accept → 全量纳入 {len(confirmed)} 个 high/medium 用户"
        f"（LLM 认可 {len(llm_confirmed_keys)} 个）| campaign={camp_name} activities={activities}"
    )
    return confirmed


async def behavior_check(state: dict) -> dict:
    t0 = time.time()
    print("\n=== [Tracer] 4. 行为审计（LLM 反思 + 最终判定版）===", flush=True)
    campaigns = state.get("campaigns", [])

    if not campaigns:
        logger.info("[Tracer] behavior_check | 无 campaign，跳过")
        P.update(stage="done")
        run_stats.set("victim_users", 0)
        run_stats.set("high_risk_users", 0)
        run_stats.phase("behavior", time.time() - t0)
        return {"high_risk_users": [], "all_attachment_downloads": [], "all_url_visits": []}

    victim_users: list[str] = []
    for alert in state.get("all_alerts", []) or []:
        if alert.get("status") != "success":
            continue
        for u in alert.get("affected_users", []) or []:
            user = (u.get("user") or "").strip()
            if user and "@" in user and user not in victim_users:
                victim_users.append(user)

    logger.info(f"[Tracer] behavior_check 收到受害者用户 {len(victim_users)} 个")
    print(f"=== [Tracer] behavior_check 收到受害者用户 {len(victim_users)} 个 ===", flush=True)

    if not victim_users:
        logger.warning("[Tracer] 无受害者用户（all_alerts 未定位到收件人），跳过行为审计")
        print("=== [Tracer] 无受害者用户，跳过行为审计 ===", flush=True)
        P.update(stage="done")
        run_stats.set("victim_users", 0)
        run_stats.set("high_risk_users", 0)
        run_stats.phase("behavior", time.time() - t0)
        return {"high_risk_users": [], "all_attachment_downloads": [], "all_url_visits": []}

    _behavior_total = 0
    for c in campaigns:
        f = c.get("features", {}) or {}
        if f.get("attachment_names"):
            _behavior_total += 1
        if any(not is_whitelisted(d) for d in (f.get("domains") or [])):
            _behavior_total += 1
    P.update(behavior_total=_behavior_total, stage="behavior")

    sem = asyncio.Semaphore(BEHAVIOR_CONCURRENCY)
    logger.info(f"[Tracer] behavior_check 并发上限 = {BEHAVIOR_CONCURRENCY}")

    async def process_campaign(camp: dict) -> list[dict]:
        async with sem:
            features = camp.get("features", {}) or {}
            has_att = bool(features.get("attachment_names"))
            has_url = any(not is_whitelisted(d) for d in (features.get("domains") or []))

            tasks: list[tuple[dict, list[str], str]] = []
            if has_att:
                tasks.append((camp, ["ATTACHMENT_DOWNLOAD", "BIG_ATTACHMENT_DOWNLOAD"], "attachment"))
            if has_url:
                tasks.append((camp, ["THREATPOLICY_URL_ACCESS"], "url"))

            if not tasks:
                return []

            confirmed: list[dict] = []
            for c, acts, k in tasks:
                try:
                    r = await _run_behavior_agent(c, acts, k, victim_users)
                    if isinstance(r, list):
                        confirmed.extend(r)
                        P.inc("behavior_done")
                        for item in r:
                            if "url" in item:
                                P.append_item("all_url_visits", item)
                            else:
                                P.append_item("all_attachment_downloads", item)
                    else:
                        P.inc("behavior_done")
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    print(f"=== [Tracer] behavior 子任务异常: {e} ===", flush=True)
                    logger.error(f"[Tracer] behavior 子任务异常: {e}")
                    P.inc("behavior_done")
            return confirmed

    all_results = await asyncio.gather(
        *(process_campaign(c) for c in campaigns), return_exceptions=True
    )

    all_attachment_downloads: list[dict] = []
    all_url_visits: list[dict] = []
    for r in all_results:
        if isinstance(r, Exception):
            print(f"=== [Tracer] behavior campaign 异常: {r} ===", flush=True)
            logger.error(f"[Tracer] behavior campaign 异常: {r}")
            continue
        for item in r:
            if "url" in item:
                all_url_visits.append(item)
            else:
                all_attachment_downloads.append(item)

    high_risk_users = _aggregate_risk_users(all_attachment_downloads, all_url_visits)

    fallback_count = sum(
        1 for u in high_risk_users
        for item in (u.get("attachment_downloads", []) + u.get("url_visits", []))
        if item.get("fallback")
    )
    elapsed = time.time() - t0
    print(
        f"=== [Tracer] 行为审计完成: 高风险用户 {len(high_risk_users)} 人 "
        f"(附件下载 {len(all_attachment_downloads)} 条, URL访问 {len(all_url_visits)} 条, "
        f"兜底 {fallback_count} 条) 耗时 {elapsed:.1f}s ===",
        flush=True,
    )
    logger.info(
        f"[Tracer] behavior_check 耗时 {elapsed:.1f}s | 高风险用户 {len(high_risk_users)} 人 | "
        f"附件下载 {len(all_attachment_downloads)} 条 | URL访问 {len(all_url_visits)} 条 | 兜底 {fallback_count} 条"
    )
    run_stats.set("victim_users", len(victim_users))
    run_stats.set("high_risk_users", len(high_risk_users))
    run_stats.phase("behavior", elapsed)

    P.update(stage="done")

    return {
        "high_risk_users": high_risk_users,
        "all_attachment_downloads": all_attachment_downloads,
        "all_url_visits": all_url_visits,
    }