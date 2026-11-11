"""LangGraph 装配。含 cluster / extract 两个轻节点。"""

import asyncio
import logging
import time
import urllib.parse
from typing import TypedDict

from langgraph.graph import StateGraph, START, END

from tools.vt_intel import get_batch_domain_intel, get_batch_ip_intel
from tools.safe_domain_whitelist import is_whitelisted
from trace_stats import run_stats
from black_filter_store import get_black_store
import tracing.progress as P
from tracing.clustering import group_mails_by_ioc
from tracing.alerts import build_alerts_from_tool_results
from tracing.agent import run_agents
from tracing.behavior import behavior_check
from tracing.ioc import _ioc_get

logger = logging.getLogger("tracing.graph")


# ★ 用 TypedDict 而不是 dict 作为 langgraph schema。
#   动态 dict schema 在部分 langgraph 版本下会丢字段（campaigns 被重置为初始 []），
#   TypedDict 会让 langgraph 正确追踪每个字段的 reducer。
class TraceState(TypedDict, total=False):
    mails_24h: list
    campaigns: list
    all_tool_results: list
    all_alerts: list
    final_alerts: list
    high_risk_users: list
    all_attachment_downloads: list
    all_url_visits: list


async def cluster_campaigns(state: dict) -> dict:
    t0 = time.time()
    print("\n=== [Tracer] 1. 开始基于 IOC 强制合并 ===", flush=True)

    try:
        await get_black_store().cleanup()
    except Exception as e:
        logger.error(f"[Tracer] 黑词库清理失败: {e}")

    mails = state["mails_24h"]
    if not mails:
        logger.info("[Tracer] cluster_campaigns | 无邮件，直接返回")
        P.update(cluster_done=True, campaigns=[], stage="agents", agents_total=0)
        run_stats.set("campaigns", 0)
        run_stats.phase("cluster", time.time() - t0)
        return {"campaigns": []}

    all_domains = set()
    all_ips = set()
    for m in mails:
        res = m.get("result", {})
        ioc_details = res.get("ioc_details", {})
        for u in ioc_details.get("urls", []) or []:
            real = _ioc_get(u, "real") or _ioc_get(u, "url") or _ioc_get(u, "text")
            if real:
                try:
                    target = real if "://" in real else "http://" + real
                    d = urllib.parse.urlparse(target).netloc.lower()
                    if "@" in d:
                        d = d.split("@")[-1]
                    if ":" in d:
                        d = d.split(":")[0]
                    if d.startswith("www."):
                        d = d[4:]
                    if d and "." in d and not is_whitelisted(d):
                        all_domains.add(d)
                except Exception:
                    pass
        for ip in res.get("ips", []) or []:
            all_ips.add(ip)

    domain_intel = await get_batch_domain_intel(all_domains)
    ip_intel = await get_batch_ip_intel(all_ips)

    campaigns = group_mails_by_ioc(mails, domain_intel, ip_intel)

    for camp in campaigns:
        camp["domain_intel"] = {d: domain_intel.get(d, {}) for d in camp["features"].get("domains", [])}
        camp["ip_intel"] = {i: ip_intel.get(i, {}) for i in camp["features"].get("ips", [])}

    anchor_stats = {}
    for c in campaigns:
        k = c.get("anchor_field", "none")
        anchor_stats[k] = anchor_stats.get(k, 0) + 1

    print(f"=== [Tracer] IOC 合并完成：产生 {len(campaigns)} 个待查组 ===", flush=True)
    print(f"=== [Tracer] 锚点分布: {anchor_stats} ===", flush=True)

    logger.info(
        f"[Tracer] cluster_campaigns 耗时 {time.time() - t0:.1f}s | "
        f"campaigns={len(campaigns)} | anchors={anchor_stats}"
    )
    run_stats.set("campaigns", len(campaigns))
    run_stats.phase("cluster", time.time() - t0)

    P.update(
        cluster_done=True,
        campaigns=campaigns,
        stage="agents",
        agents_total=len(campaigns),
    )

    return {"campaigns": campaigns}


def extract_alerts(state: dict) -> dict:
    t0 = time.time()
    print("\n=== [Tracer] 3. 提取最终受影响名单 ===", flush=True)

    alerts = build_alerts_from_tool_results(state.get("all_tool_results", []))

    P.update(extract_done=True, all_alerts=alerts, stage="behavior")

    run_stats.phase("extract", time.time() - t0)
    return {"all_alerts": alerts}


builder = StateGraph(TraceState)   # ★ 关键：用 TypedDict
builder.add_node("cluster", cluster_campaigns)
builder.add_node("run_agents", run_agents)
builder.add_node("extract", extract_alerts)
builder.add_node("behavior", behavior_check)

builder.add_edge(START, "cluster")
builder.add_edge("cluster", "run_agents")
builder.add_edge("run_agents", "extract")
builder.add_edge("extract", "behavior")
builder.add_edge("behavior", END)

trace_graph = builder.compile()