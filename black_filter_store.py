"""黑词库：严格匹配的完整 filter 组合，跨组共享，持久化。

判定方向：新查询 ⊆ 黑词（子串/更泛化）→ 命中。
生命周期：created_at 超 7 天 → 清；上限 200 条，超了删最老。
包含压缩：单字段 A ⊂ B（A 是 B 的子串，即更泛化）→ 删 A，留更精确的 B。
"""

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("black_filter_store")

BLACK_FILTER_TTL_DAYS = 7
BLACK_FILTER_MAX_SIZE = 200
BLACK_FILTER_PROMPT_LIMIT = 50
BADNESS_RECORD_THRESHOLD = 100


def score_badness(result_str: str) -> int:
    try:
        data = json.loads(result_str)
    except Exception:
        return 500
    if data.get("error"):
        return 500
    raw = data.get("raw_returned", 0) or 0
    has_more = 1 if data.get("hasMore") else 0
    dirty = data.get("dirty_count", 0) or 0
    # ★ filtered_out_internal 不计入 badness：白名单过滤是正确行为，不是炸锅
    valid = data.get("valid_returned", 0) or 0
    return int(raw + has_more * 150 + dirty * 3 + max(0, raw - valid) * 2)


def _resolve_path() -> str:
    try:
        from config import REPORT_DIR
        return os.path.join(REPORT_DIR, "blackfilters.json")
    except (ImportError, AttributeError):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "blackfilters.json")


class BlackFilterStore:
    def __init__(self, path: str, ttl_days: int, max_size: int):
        self.path = path
        self.ttl_days = ttl_days
        self.max_size = max_size
        self._records: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._records = data.get("records", {}) or {}
            logger.info(f"[BlackFilter] 加载 {len(self._records)} 条黑词 | path={self.path}")
        except Exception as e:
            logger.error(f"[BlackFilter] 加载失败: {e}，使用空库")
            self._records = {}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"records": self._records}, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except Exception as e:
            logger.error(f"[BlackFilter] 保存失败: {e}")

    @staticmethod
    def _key(filter_dict: dict) -> str:
        return hashlib.md5(
            json.dumps(filter_dict, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    async def record(self, filter_dict: dict, badness: int):
        """记录一次炸锅。相同 filter 累加 count 和 total_badness。"""
        if not filter_dict:
            return
        key = self._key(filter_dict)
        async with self._lock:
            now = self._now()
            if key in self._records:
                rec = self._records[key]
                rec["count"] += 1
                rec["total_badness"] += badness
                rec["last_hit_at"] = now
            else:
                self._records[key] = {
                    "filter": filter_dict,
                    "count": 1,
                    "total_badness": badness,
                    "created_at": now,
                    "last_hit_at": now,
                }
            self._save()
        logger.info(f"[BlackFilter] 记录黑词 | badness={badness} | filter={json.dumps(filter_dict, ensure_ascii=False)}")

    async def cleanup(self):
        """三段清理：TTL → 包含压缩 → 上限截断。"""
        async with self._lock:
            before = len(self._records)
            now = datetime.now(timezone.utc)

            # 1. 绝对 TTL
            ttl = timedelta(days=self.ttl_days)
            expired = []
            for k, r in list(self._records.items()):
                try:
                    created = datetime.fromisoformat(r["created_at"])
                    if now - created > ttl:
                        expired.append(k)
                except Exception:
                    expired.append(k)
            for k in expired:
                del self._records[k]

            # 2. 包含压缩：单字段，A ⊂ B（A 是 B 的子串，即更泛化）→ 删 A，留更精确的 B
            to_delete = set()
            keys = list(self._records.keys())
            for ka in keys:
                if ka in to_delete:
                    continue
                ra = self._records.get(ka)
                if not ra:
                    continue
                fa = ra["filter"]
                if len(fa) != 1:
                    continue
                fka = next(iter(fa))
                va = str(fa[fka])
                for kb in keys:
                    if ka == kb or kb in to_delete:
                        continue
                    rb = self._records.get(kb)
                    if not rb:
                        continue
                    fb = rb["filter"]
                    if len(fb) != 1:
                        continue
                    fkb = next(iter(fb))
                    if fka != fkb:
                        continue
                    vb = str(fb[fkb])
                    if va != vb and va in vb:
                        # A 是 B 的子串（更泛化）→ 删 A，保留更精确的 B
                        # 这样 B 被完全匹配拦住，A 作为 B 的子串也被拦住，教训不丢
                        to_delete.add(ka)
                        break
            for k in to_delete:
                del self._records[k]

            # 3. 上限截断：超 200 按 created_at 删最老
            capped = 0
            if len(self._records) > self.max_size:
                sorted_by_age = sorted(
                    self._records.items(),
                    key=lambda kv: kv[1].get("created_at", "")
                )
                excess = len(self._records) - self.max_size
                for k, _ in sorted_by_age[:excess]:
                    del self._records[k]
                    capped += 1

            after = len(self._records)
            if before != after:
                self._save()
                msg = (
                    f"[BlackFilter] 清理: {before} → {after} "
                    f"| ttl_expired={len(expired)} | contained={len(to_delete)} | capped={capped}"
                )
                logger.info(msg)
                print(f"=== {msg} ===", flush=True)

    def build_prompt(self, limit: int = BLACK_FILTER_PROMPT_LIMIT) -> Optional[str]:
        """把黑词库快照做成给 LLM 看的 SystemMessage。空库返回 None。"""
        if not self._records:
            return None
        recs = sorted(self._records.values(), key=lambda r: -r.get("total_badness", 0))[:limit]
        lines = [
            "【⚠️ 历史黑词清单：以下 filter 组合在过去造成过严重炸锅】",
            "",
            "【判定规则（必读）】",
            "- ❌ 完全一样的 filter → 必炸，禁止使用",
            "- ❌ 更泛化的 filter（你的字段值是黑词同字段值的子串，或字段是其子集）→ 必炸，禁止使用",
            "     例：黑词 {\"subject\": \"OA：请假流程更新\"} 时，{\"subject\": \"OA\"} 和 {\"subject\": \"请假\"} 都算命中",
            "- ✅ 平行组合（如 {\"subject\": \"OA：报销单模板\"}）→ 可正常使用",
            "- ✅ 更精确的组合（如 {\"subject\": \"OA：请假流程更新 第2批\"}）→ 可正常使用",
            "",
            "【清单（按累计炸锅程度降序）】",
        ]
        for i, r in enumerate(recs, 1):
            lines.append(
                f"  {i}. {json.dumps(r['filter'], ensure_ascii=False)}    "
                f"(触发 {r.get('count', 0)} 次，累计离谱度 {r.get('total_badness', 0)})"
            )
        if len(self._records) > len(recs):
            lines.append(f"  （另有 {len(self._records) - len(recs)} 条未展示）")
        return "\n".join(lines)


_black_filter_store: Optional[BlackFilterStore] = None


def get_black_store() -> BlackFilterStore:
    global _black_filter_store
    if _black_filter_store is None:
        _black_filter_store = BlackFilterStore(
            path=_resolve_path(),
            ttl_days=BLACK_FILTER_TTL_DAYS,
            max_size=BLACK_FILTER_MAX_SIZE,
        )
    return _black_filter_store