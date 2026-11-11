import os
import time
import logging
import asyncio
import ipaddress
from typing import Optional, Set, Dict
import requests
from langchain_core.tools import tool

logger = logging.getLogger("vt_intel")

VTAI_AGENT_TOKEN = os.getenv("VTAI_TOKEN", "")


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False


class VTAIClient:
    def __init__(self, token: Optional[str] = None, timeout: int = 20, max_retries: int = 1):
        self.token = token or os.environ.get("VTAI_TOKEN")
        if not self.token:
            raise ValueError("VTAI token 未配置。")
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff = 2
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        })
        self.cache = {}

    def _get(self, path: str) -> dict:
        url = f"https://ai.virustotal.com{path}"
        last_exc = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 404:
                    return {"__http_404__": (resp.text or "")[:500]}
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "60"))
                    logger.warning(f"VTAI 触发限流，休眠 {retry_after}s 后重试")
                    time.sleep(retry_after)
                    continue
                if resp.status_code >= 400:
                    logger.error(f"VTAI HTTP {resp.status_code} | url={url} | body={(resp.text or '')[:500]}")
                resp.raise_for_status()
                return resp.json()
            except (requests.Timeout, requests.ConnectionError) as e:
                last_exc = e
                if attempt < self.max_retries:
                    logger.warning(
                        f"VTAI 网络异常 ({type(e).__name__})，{self.retry_backoff}s 后重试 "
                        f"({attempt + 1}/{self.max_retries}): {e}"
                    )
                    time.sleep(self.retry_backoff)
                    continue
                raise
        raise last_exc or RuntimeError("VTAI request failed")

    def _parse_categories(self, categories: list) -> dict:
        if not categories:
            return {"is_safe": False, "worst_category": "unknown"}

        PRIORITY = ["malicious", "suspicious", "phishing", "malware", "adware", "spam", "undetected", "unknown"]

        # ★ 改动：allowed_safe 里移除 undetected
        # 只有"纯 harmless"（或 harmless + error 引擎失败）才判 safe。
        # harmless + undetected 混合 → 视为 undetected（部分引擎不认识，可能是老域名被回收利用）。
        # 理由：undetected 意味着有引擎"没扫过 / 不认识"，这是风险信号，不应因为另一个引擎说 harmless 就抹平。
        if "harmless" in categories:
            allowed_safe = {"harmless", "error"}
            non_safe = set(categories) - allowed_safe
            if not non_safe:
                return {"is_safe": True, "worst_category": "harmless"}

        for p in PRIORITY:
            if p in categories:
                return {"is_safe": False, "worst_category": p}

        return {"is_safe": False, "worst_category": categories[0]}

    def _is_placeholder_report(self, data: dict) -> bool:
        """识别 VT AI 对无记录域名的占位报告（analysis_date 是今天 + 全 0 统计）"""
        try:
            d = data.get("data", {})
            stats = d.get("last_analysis_stats", {})
            analysis_date = d.get("analysis_date", "")
            today = time.strftime("%Y-%m-%d", time.gmtime())
            return (
                analysis_date.startswith(today)
                and stats.get("malicious", 0) == 0
                and stats.get("suspicious", 0) == 0
                and stats.get("harmless", 0) == 0
            )
        except Exception:
            return False

    def _build_from_404(self, indicator: str, ioc_type: str, body_snippet: str) -> dict:
        is_not_found = (
            "No existing VirusTotal report found" in body_snippet
            or '"code":"not_found"' in body_snippet
            or '"code": "not_found"' in body_snippet
        )
        if is_not_found:
            return {
                "indicator": indicator,
                "type": ioc_type,
                "categories": ["undetected"],
                "is_safe": False,
                "worst_category": "undetected",
                "note": "not_found_in_vt",
                "raw_body": body_snippet[:200],
            }
        return {
            "indicator": indicator,
            "type": ioc_type,
            "error": f"HTTP 404 (unexpected): {body_snippet}",
            "is_safe": False,
            "worst_category": "unknown",
            "note": "http_404_unexpected",
        }

    def _build_unavailable(self, indicator: str, ioc_type: str, exc: Exception) -> dict:
        return {
            "indicator": indicator,
            "type": ioc_type,
            "error": str(exc),
            "is_safe": False,
            "worst_category": "unknown",
            "note": "intel_unavailable",
        }

    def get_domain_verdict(self, domain: str) -> dict:
        if domain in self.cache: return self.cache[domain]
        domain = domain.lower().strip()
        if domain.startswith("www."): domain = domain[4:]

        try:
            data = self._get(f"/api/v3/domains/{domain}")
            if "__http_404__" in data:
                res = self._build_from_404(domain, "domain", data["__http_404__"])
            else:
                coverage = data.get("data", {}).get("coverage", {})
                categories = coverage.get("categories", [])
                parsed = self._parse_categories(categories)
                res = {
                    "indicator": domain,
                    "type": "domain",
                    "categories": categories,
                    **parsed,
                }
                if self._is_placeholder_report(data) and res.get("worst_category") == "undetected":
                    res["note"] = "placeholder_undetected"
        except Exception as e:
            logger.error(f"查域名 {domain} 情报失败: {e}")
            res = self._build_unavailable(domain, "domain", e)
        self.cache[domain] = res
        return res

    def get_ip_verdict(self, ip: str) -> dict:
        if ip in self.cache: return self.cache[ip]
        ip = ip.strip()
        if not _is_public_ip(ip):
            res = {"indicator": ip, "type": "ip", "note": "internal_ip", "is_safe": True, "worst_category": "internal"}
            self.cache[ip] = res
            return res

        try:
            data = self._get(f"/api/v3/ip_addresses/{ip}")
            if "__http_404__" in data:
                res = self._build_from_404(ip, "ip", data["__http_404__"])
            else:
                coverage = data.get("data", {}).get("coverage", {})
                categories = coverage.get("categories", [])
                parsed = self._parse_categories(categories)
                res = {
                    "indicator": ip,
                    "type": "ip",
                    "categories": categories,
                    **parsed,
                }
                if self._is_placeholder_report(data) and res.get("worst_category") == "undetected":
                    res["note"] = "placeholder_undetected"
        except Exception as e:
            logger.error(f"查 IP {ip} 情报失败: {e}")
            res = self._build_unavailable(ip, "ip", e)
        self.cache[ip] = res
        return res


vt_client = VTAIClient(token=VTAI_AGENT_TOKEN)


async def get_batch_domain_intel(domains: Set[str]) -> Dict[str, dict]:
    if not domains: return {}
    sem = asyncio.Semaphore(5)

    async def fetch(d):
        async with sem:
            return await asyncio.to_thread(vt_client.get_domain_verdict, d)

    results = await asyncio.gather(*(fetch(d) for d in domains))
    return {r["indicator"]: r for r in results}


async def get_batch_ip_intel(ips: Set[str]) -> Dict[str, dict]:
    if not ips: return {}
    sem = asyncio.Semaphore(5)

    async def fetch(i):
        async with sem:
            return await asyncio.to_thread(vt_client.get_ip_verdict, i)

    results = await asyncio.gather(*(fetch(i) for i in ips))
    return {r["indicator"]: r for r in results}