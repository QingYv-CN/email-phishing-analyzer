import asyncio
import json
import logging
import time

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI

from config import (
    LLM_API_BASE, LLM_API_KEY, LLM_MODEL,
    MAX_TOOL_CALLS_PER_CAMPAIGN, CAMPAIGN_CONCURRENCY,
    LLM_MAX_RETRIES, LLM_RETRY_BASE_DELAY,
)
from tools.mail_log_searcher import search_mail_logs
from black_filter_store import get_black_store, score_badness
from trace_stats import run_stats
import tracing.progress as P
from tracing.prompts import SYSTEM_PROMPT

logger = logging.getLogger("tracing.agent")


llm = ChatOpenAI(
    api_key=LLM_API_KEY,
    base_url=LLM_API_BASE,
    model=LLM_MODEL,
    temperature=0.1,
    timeout=60,
).bind_tools([search_mail_logs])


def _format_campaign_for_llm(camp: dict) -> str:
    anchor_field = camp.get("anchor_field", "none")
    anchor_values = camp.get("anchor_values", []) or []
    confidence = camp.get("cluster_confidence", "low")
    features = camp.get("features", {})

    parts = ["【本组聚类锚点（必须优先尝试）】"]
    if anchor_field == "none":
        parts.append("无锚点 —— 本组邮件共同特征不明确，按原优先级策略试探。")
    else:
        parts.append(f"anchor_field   : {anchor_field}")
        parts.append(f"anchor_values  : {json.dumps(anchor_values, ensure_ascii=False)}")
        parts.append(f"cluster_confidence : {confidence}")
        if anchor_field == "subjects":
            parts.append("⚠️ 注意：subjects 是**弱锚点**，不能单独使用，必须和 from 或 mailFrom 组合！")
        elif anchor_field == "domains":
            parts.append("⚠️ 注意：邮件日志无 domain 字段，请用 mailFrom（同域名发件人）实现。")
        elif anchor_field == "ips":
            parts.append("⚠️ 注意：邮件日志无 ip 字段，请用 mailFrom 实现。")
        else:
            parts.append("→ 第一轮请**直接使用锚点字段**查询，不要从 subject 起步。")

    parts.append("")
    parts.append("【完整攻击特征】")
    slim = {
        "name": camp.get("name"),
        "features": features,
        "sample_count": camp.get("sample_count"),
        "summary_reason": camp.get("summary_reason"),
    }
    parts.append(json.dumps(slim, ensure_ascii=False, indent=2))
    return "\n".join(parts)


async def run_agents(state: dict) -> dict:
    t0 = time.time()
    campaigns = state.get("campaigns", [])
    if not campaigns:
        run_stats.phase("agents", time.time() - t0)
        return {"all_tool_results": []}

    sem = asyncio.Semaphore(CAMPAIGN_CONCURRENCY)

    async def process_one(camp: dict) -> list[str]:
        async with sem:
            messages = [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=_format_campaign_for_llm(camp)),
            ]

            store = get_black_store()
            bw_prompt = store.build_prompt()
            if bw_prompt:
                messages.append(SystemMessage(content=bw_prompt))

            tool_results: list[str] = []
            trials: list[dict] = []
            tool_call_count = 0

            try:
                while tool_call_count < MAX_TOOL_CALLS_PER_CAMPAIGN:
                    response = None
                    for attempt in range(LLM_MAX_RETRIES):
                        prompt_len = sum(len(str(getattr(m, "content", "") or "")) for m in messages)
                        run_stats.add("prompt_total", prompt_len)
                        run_stats.max("prompt_max", prompt_len)
                        run_stats.inc("llm_calls")
                        try:
                            response = await llm.ainvoke(messages)
                            break
                        except Exception as e:
                            run_stats.inc("llm_fails")
                            if isinstance(e, asyncio.TimeoutError) or "timeout" in str(e).lower():
                                run_stats.inc("llm_timeouts")
                            if attempt < LLM_MAX_RETRIES - 1:
                                run_stats.inc("llm_retries")
                                delay = LLM_RETRY_BASE_DELAY * (2 ** attempt)
                                print(
                                    f"=== [Tracer] LLM 调用失败，{delay}s 后重试"
                                    f"（{attempt + 1}/{LLM_MAX_RETRIES}）"
                                    f"（campaign={camp.get('name')}）: {e} ===",
                                    flush=True,
                                )
                                await asyncio.sleep(delay)
                            else:
                                print(
                                    f"=== [Tracer] LLM 调用失败（campaign={camp.get('name')}）: {e} ===",
                                    flush=True,
                                )
                                return tool_results
                    if response is None:
                        return tool_results

                    messages.append(response)
                    tool_calls = getattr(response, "tool_calls", None) or []
                    if not tool_calls:
                        break

                    for tc in tool_calls:
                        if tool_call_count >= MAX_TOOL_CALLS_PER_CAMPAIGN:
                            break
                        if tc.get("name") != "search_mail_logs":
                            continue

                        args = tc.get("args") or {}
                        filters = args.get("filters") or {}
                        try:
                            result_str = await search_mail_logs.ainvoke(args)
                        except Exception as e:
                            result_str = json.dumps(
                                {"error": str(e), "sample_logs": []},
                                ensure_ascii=False,
                            )

                        trials.append({
                            "filters": filters,
                            "badness": score_badness(result_str),
                        })
                        messages.append(ToolMessage(
                            content=result_str,
                            tool_call_id=tc.get("id", ""),
                        ))
                        tool_results.append(result_str)
                        tool_call_count += 1

                if trials:
                    worst = max(trials, key=lambda t: t["badness"])
                    if worst["badness"] >= 100 and worst["filters"]:
                        await store.record(worst["filters"], worst["badness"])
                        print(
                            f"=== [Tracer] campaign={camp.get('name')} 黑词落库 | "
                            f"badness={worst['badness']} | filters={worst['filters']} ===",
                            flush=True,
                        )
            finally:
                P.inc("agents_done")
                P.append_list("all_tool_results", tool_results)

            return tool_results

    tasks = [process_one(c) for c in campaigns]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_results: list[str] = []
    for r in results:
        if isinstance(r, Exception):
            print(f"=== [Tracer] 某组处理异常: {r} ===", flush=True)
            continue
        all_results.extend(r)

    print(
        f"=== [Tracer] 2. Agent 循环完成：{len(campaigns)} 组，"
        f"累积 {len(all_results)} 条工具结果 ===",
        flush=True,
    )
    logger.info(
        f"[Tracer] run_agents 耗时 {time.time() - t0:.1f}s | "
        f"campaigns={len(campaigns)} | tool_results={len(all_results)}"
    )
    run_stats.phase("agents", time.time() - t0)
    return {"all_tool_results": all_results}