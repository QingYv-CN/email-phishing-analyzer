"""溯源运行统计：每次 /trace/trigger 结束后写一行 JSONL 到 log_query/trace_stats.jsonl。"""
import json
import logging
import os
import threading
import time
from datetime import datetime

from config import TRACE_STATS_LOG_PATH

logger = logging.getLogger("trace_stats")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    os.makedirs(os.path.dirname(TRACE_STATS_LOG_PATH), exist_ok=True)
    handler = logging.FileHandler(TRACE_STATS_LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


FINAL_REPORT_MAX_CHARS = 8000  # final_response.report 超长截断，避免单行过大


class TraceStats:
    def __init__(self):
        self._lock = threading.Lock()
        self._data = {}
        self._begin_ts = 0.0

    def begin(self, mails_count: int):
        with self._lock:
            self._begin_ts = time.time()
            self._data = {
                "run_id": f"trace-{int(self._begin_ts)}",
                "start_ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "mails": int(mails_count),
                "campaigns": 0,
                "victim_users": 0,
                "high_risk_users": 0,
                "prompt_total": 0,
                "prompt_max": 0,
                "llm_calls": 0,
                "llm_retries": 0,
                "llm_timeouts": 0,
                "llm_fails": 0,
                "cluster_s": 0.0,
                "agents_s": 0.0,
                "extract_s": 0.0,
                "behavior_s": 0.0,
                "html_report_s": 0.0,
                "llm_report_s": 0.0,
                "total_s": 0.0,
                "final_response": {},
            }

    def set(self, key, value):
        with self._lock:
            if key in self._data:
                self._data[key] = value

    def inc(self, key, n=1):
        with self._lock:
            if key in self._data:
                self._data[key] += n

    def add(self, key, n):
        with self._lock:
            if key in self._data:
                self._data[key] += n

    def max(self, key, n):
        with self._lock:
            if key in self._data and n > self._data[key]:
                self._data[key] = n

    def phase(self, key, seconds: float):
        with self._lock:
            k = key if key in self._data else f"{key}_s"
            if k in self._data:
                self._data[k] = round(float(seconds), 2)

    @staticmethod
    def _trim_final(resp: dict | None, max_report_chars: int = FINAL_REPORT_MAX_CHARS) -> dict:
        if not isinstance(resp, dict):
            return {}
        out = {}
        for k, v in resp.items():
            if k == "report" and isinstance(v, str) and len(v) > max_report_chars:
                out[k] = v[:max_report_chars] + f"\n...[truncated {len(v) - max_report_chars} chars]"
            else:
                out[k] = v
        return out

    def _write(self, data: dict):
        logger.info(json.dumps(data, ensure_ascii=False))
        final = data.get("final_response") or {}
        final_status = str(final.get("status", ""))
        final_hr = final.get("high_risk_users_count", "")
        final_msg = str(final.get("message", ""))[:80]
        final_url = str(final.get("detail_url", ""))[:200]
        final_report_len = len(str(final.get("report", "")))
        print(
            f"[TraceStats] status={data['status']} mails={data['mails']} "
            f"campaigns={data['campaigns']} victims={data['victim_users']} "
            f"high_risk={data['high_risk_users']} prompt_total={data['prompt_total']} "
            f"prompt_max={data['prompt_max']} llm_calls={data['llm_calls']} "
            f"retries={data['llm_retries']} timeouts={data['llm_timeouts']} "
            f"fails={data['llm_fails']} cluster={data['cluster_s']}s "
            f"agents={data['agents_s']}s extract={data['extract_s']}s "
            f"behavior={data['behavior_s']}s html={data['html_report_s']}s "
            f"llm_report={data['llm_report_s']}s total={data['total_s']}s "
            f"error={data['error'][:80]} | final_status={final_status} "
            f"final_hr={final_hr} final_report_len={final_report_len} "
            f"final_msg={final_msg} final_url={final_url}",
            flush=True,
        )

    def emit(self, status: str, error: str = "", final_response: dict | None = None):
        with self._lock:
            data = dict(self._data)
            if self._begin_ts:
                data["total_s"] = round(time.time() - self._begin_ts, 2)
            data["status"] = status
            data["error"] = (error or "")[:500]
            data["final_response"] = self._trim_final(final_response)
            for k in ("mails", "campaigns", "victim_users", "high_risk_users",
                      "prompt_total", "prompt_max", "llm_calls", "llm_retries",
                      "llm_timeouts", "llm_fails"):
                data.setdefault(k, 0)
            for k in ("cluster_s", "agents_s", "extract_s", "behavior_s",
                      "html_report_s", "llm_report_s", "total_s"):
                data.setdefault(k, 0.0)
        self._write(data)

    def record_skipped(self, response: dict):
        """上一次还没跑完，本次直接 skipped 也要留痕。"""
        data = {
            "run_id": f"trace-skipped-{int(time.time())}",
            "start_ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mails": 0, "campaigns": 0, "victim_users": 0, "high_risk_users": 0,
            "prompt_total": 0, "prompt_max": 0,
            "llm_calls": 0, "llm_retries": 0, "llm_timeouts": 0, "llm_fails": 0,
            "cluster_s": 0.0, "agents_s": 0.0, "extract_s": 0.0, "behavior_s": 0.0,
            "html_report_s": 0.0, "llm_report_s": 0.0, "total_s": 0.0,
            "status": "skipped", "error": "",
            "final_response": self._trim_final(response),
        }
        self._write(data)


run_stats = TraceStats()