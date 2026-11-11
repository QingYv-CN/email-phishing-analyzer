"""不展示的收件人域名后缀黑名单。

- 只影响最终展示（收件人名单、高风险用户），不影响日志查询语句
- 从 recipient_blacklist.txt 热加载，改文件保存后 5 秒内生效
"""

import os
import threading
import time
from urllib.parse import urlparse

from config import BASE_DIR

BLACKLIST_FILE = os.path.join(BASE_DIR, "recipient_blacklist.txt")

_LOCK = threading.Lock()
_BLACKLIST: set[str] = set()
_LAST_MTIME: float = 0.0
_LAST_CHECK: float = 0.0
_CHECK_INTERVAL = 5.0


def _normalize(raw: str) -> str:
    if not raw:
        return ""
    s = raw.strip().lower()
    if not s or s.startswith("#"):
        return ""
    if s.startswith("@"):
        s = s[1:]
    if "://" in s:
        try:
            s = urlparse(s).netloc or ""
        except Exception:
            return ""
    if "/" in s:
        s = s.split("/", 1)[0]
    if ":" in s:
        s = s.split(":", 1)[0]
    if "@" in s:
        s = s.split("@", 1)[-1]
    if s.startswith("www."):
        s = s[4:]
    return s


def _reload(force: bool = False) -> None:
    global _BLACKLIST, _LAST_MTIME, _LAST_CHECK

    now = time.time()
    if not force and now - _LAST_CHECK < _CHECK_INTERVAL:
        return
    _LAST_CHECK = now

    if not os.path.exists(BLACKLIST_FILE):
        return
    try:
        mtime = os.path.getmtime(BLACKLIST_FILE)
    except OSError:
        return
    if not force and mtime <= _LAST_MTIME:
        return

    with _LOCK:
        try:
            mtime = os.path.getmtime(BLACKLIST_FILE)
        except OSError:
            return
        if not force and mtime <= _LAST_MTIME:
            return
        entries: set[str] = set()
        try:
            with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    d = _normalize(line)
                    if d:
                        entries.add(d)
        except OSError:
            return
        _BLACKLIST = entries
        _LAST_MTIME = mtime


def _email_domain(email: str) -> str:
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[-1].strip().lower().strip("<> ").strip()


def is_blacklisted_email(email: str) -> bool:
    """判断收件人邮箱的域名是否在黑名单里（精确 + 子域匹配）。"""
    _reload()
    if not email:
        return False
    d = _email_domain(email)
    if not d:
        return False
    if d in _BLACKLIST:
        return True
    for w in _BLACKLIST:
        if d.endswith("." + w):
            return True
    return False


def filter_emails(emails: list[str]) -> list[str]:
    return [e for e in (emails or []) if not is_blacklisted_email(e)]


def filter_alerts(all_alerts: list[dict]) -> list[dict]:
    """过滤 affected_users 中命中黑名单的收件人，同时更新 total_logs。"""
    out: list[dict] = []
    for alert in all_alerts or []:
        users = alert.get("affected_users") or []
        filtered = [
            u for u in users
            if not is_blacklisted_email(u.get("user", ""))
        ]
        if len(filtered) != len(users):
            new_alert = dict(alert)
            new_alert["affected_users"] = filtered
            new_alert["total_logs"] = len(filtered)
            out.append(new_alert)
        else:
            out.append(alert)
    return out


_reload(force=True)