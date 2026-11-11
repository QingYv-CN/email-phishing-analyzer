"""薄壳入口 —— 兼容旧 import 路径。"""

from log_query.mail_logs import search_mail_logs
from log_query.behavior_logs import (
    search_behavior_logs,
    build_attachment_patterns,
    build_url_patterns,
)
from log_query.common import _is_whitelist_mailfrom

__all__ = [
    "search_mail_logs",
    "search_behavior_logs",
    "build_attachment_patterns",
    "build_url_patterns",
    "_is_whitelist_mailfrom",
]