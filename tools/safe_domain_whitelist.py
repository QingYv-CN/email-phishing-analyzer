"""安全域名白名单（URL 维度，与发件人白名单相互独立）。

- 单封邮件分析阶段：命中白名单的 URL 不允许作为恶意依据
- 溯源聚类阶段：命中白名单的域名不参与 IOC 聚类
- 行为审计阶段：命中白名单的 URL 访问不判定为高风险

文件格式：每行一个域名；支持 # 注释；支持完整 URL / 带端口 / 带 www. 自动归一化。
"""

import os
import time
import threading
from urllib.parse import urlparse

try:
    from config import SAFE_DOMAIN_WHITELIST_FILE
except Exception:                       # config 缺失时降级为空
    SAFE_DOMAIN_WHITELIST_FILE = ""

_LOCK = threading.Lock()
_WHITELIST: set[str] = set()
_LAST_MTIME: float = 0.0
_LAST_CHECK_TS: float = 0.0
_FILE_PATH: str = ""
_CHECK_INTERVAL = 5.0                   # 5 秒内不重复 stat


def _normalize(raw: str) -> str:
    """把一行文本归一化成裸域名（不带协议/端口/www.）"""
    if not raw:
        return ""
    s = raw.strip().lower()
    if not s or s.startswith("#"):
        return ""
    # 去掉协议
    if "://" in s:
        try:
            s = urlparse(s).netloc or ""
        except Exception:
            return ""
    # 去掉路径/参数（如果用户误写成 URL）
    if "/" in s:
        s = s.split("/", 1)[0]
    # 去掉端口
    if ":" in s:
        s = s.split(":", 1)[0]
    # 去掉 user:pass@host
    if "@" in s:
        s = s.split("@", 1)[-1]
    # 去掉 www.
    if s.startswith("www."):
        s = s[4:]
    # 基本合法性
    if not s or "." not in s:
        return ""
    return s


def _reload(force: bool = False) -> None:
    global _WHITELIST, _LAST_MTIME, _LAST_CHECK_TS

    now = time.time()
    if not force and now - _LAST_CHECK_TS < _CHECK_INTERVAL:
        return
    _LAST_CHECK_TS = now

    path = _FILE_PATH
    if not path or not os.path.exists(path):
        return
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return
    if not force and mtime <= _LAST_MTIME:
        return

    with _LOCK:
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return
        if not force and mtime <= _LAST_MTIME:
            return
        entries: set[str] = set()
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    d = _normalize(line)
                    if d:
                        entries.add(d)
        except OSError:
            return
        _WHITELIST = entries
        _LAST_MTIME = mtime


def configure(path: str) -> None:
    """在 main.lifespan 里可主动调用，未调用则使用 config 默认路径。"""
    global _FILE_PATH
    _FILE_PATH = path or ""
    _reload(force=True)


def is_whitelisted(domain_or_url: str) -> bool:
    """判断给定域名或 URL 是否在白名单内（精确 + 子域匹配）。"""
    _reload()
    if not domain_or_url:
        return False
    d = _normalize(domain_or_url)
    if not d:
        return False
    if d in _WHITELIST:
        return True
    for w in _WHITELIST:
        if d.endswith("." + w):
            return True
    return False


def get_whitelist() -> set[str]:
    _reload()
    return set(_WHITELIST)


# 模块加载时自动初始化
if SAFE_DOMAIN_WHITELIST_FILE:
    configure(SAFE_DOMAIN_WHITELIST_FILE)