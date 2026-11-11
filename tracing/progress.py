"""溯源进度快照。所有节点读写都走这里，避免各模块自己判断 None。"""

_progress: dict | None = None


def init() -> dict:
    global _progress
    _progress = {
        "interrupted": False,
        "stage": "init",
        "cluster_done": False,
        "campaigns": [],
        "agents_done": 0,
        "agents_total": 0,
        "all_tool_results": [],
        "extract_done": False,
        "all_alerts": [],
        "behavior_done": 0,
        "behavior_total": 0,
        "all_attachment_downloads": [],
        "all_url_visits": [],
    }
    return _progress


def get() -> dict | None:
    return _progress


def update(**kw):
    if _progress is not None:
        _progress.update(kw)


def inc(key: str, n: int = 1):
    if _progress is not None:
        _progress[key] = _progress.get(key, 0) + n


def append_list(key: str, items: list):
    if _progress is not None:
        _progress.setdefault(key, []).extend(items)


def append_item(key: str, item):
    if _progress is not None:
        _progress.setdefault(key, []).append(item)