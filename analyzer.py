"""邮件钓鱼分析 pipeline —— 固定流程，一次 LLM 调用出结果。

本文件只保留进程入口 `analyze_email` 和对外 re-export。
具体流水线在 `analysis/` 包内。
"""

import asyncio
import logging
import time

from config import LLM_MODEL, TOTAL_TIMEOUT

from analysis.runtime import (
    Runtime, runtime, _inflight_lock, _run_blocking, _cleanup_loop,
)
from analysis.pipeline import pipeline
from analysis.normalizer import normalize_error, normalize_success

logger = logging.getLogger("analyzer")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)


# 兼容别名（旧代码里的下划线名字）
_pipeline = pipeline
_normalize_error = normalize_error
_normalize_success = normalize_success


__all__ = [
    "Runtime", "runtime", "_run_blocking", "_cleanup_loop",
    "analyze_email",
    "_pipeline", "_normalize_error", "_normalize_success",
]


async def analyze_email(email_content: str) -> dict:
    req_id = f"req-{int(time.time() * 1000) % 1000000:06d}"
    t0 = time.time()
    async with _inflight_lock:
        runtime.inflight += 1
    meta = {
        "request_id": req_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "elapsed_ms": 0,
        "model": LLM_MODEL,
        "email_length": len(email_content),
        "image_count": 0,
        "attachment_count": 0,
        "url_count": 0,
        "llm_tokens": {"prompt": 0, "completion": 0, "total": 0},
    }
    try:
        result = await asyncio.wait_for(
            pipeline(email_content, req_id, meta, t0), timeout=TOTAL_TIMEOUT
        )
        if isinstance(result, dict) and result.get("success"):
            runtime.total_ok += 1
        else:
            runtime.total_err += 1
        return result
    except asyncio.TimeoutError:
        runtime.total_err += 1
        return normalize_error("TOTAL_TIMEOUT", "分析超时", meta)
    except Exception as e:
        runtime.total_err += 1
        return normalize_error("INTERNAL_ERROR", str(e), meta)
    finally:
        async with _inflight_lock:
            runtime.inflight -= 1