"""URL 归一化 + HTML href 提取（支持协议相对路径）。"""

import re


def normalize_url(raw_url: str, default_scheme: str = "http") -> str:
    if not raw_url:
        return ""
    s = raw_url.strip().strip('"').strip("'")
    if not s:
        return ""
    if s.startswith("//"):
        return f"{default_scheme}:{s}"
    if "://" in s:
        return s
    if s.startswith("/"):
        return ""
    if "." in s.split("/")[0]:
        return f"{default_scheme}://{s}"
    return ""


def extract_urls_from_href(html: str) -> list[str]:
    if not html:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
        raw = m.group(1).strip()
        normalized = normalize_url(raw)
        if normalized:
            key = normalized.lower()
            if key not in seen:
                seen.add(key)
                out.append(normalized)
    return out