import asyncio
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from openai import AsyncOpenAI
from pydantic import BaseModel

from config import (
    LLM_API_BASE, LLM_API_KEY, LLM_TIMEOUT,
    REQUEST_TIMEOUT,
    MAX_CONCURRENT_REQUESTS, MAX_LLM_CONCURRENT,
    MAX_OCR_CONCURRENT, BLOCKING_WORKERS, QUEUE_WAIT_SECONDS,
    REPORT_DIR,
    TRACE_HARD_TIMEOUT_SECONDS,
    TRACE_LOCK_EXPIRE_SECONDS,
)
from analyzer import (
    runtime, analyze_email, _cleanup_loop,
)
from reports.task_manager import trigger_trace, trace_status

logger = logging.getLogger("main")

# ★ 报告文件名白名单：只允许字母/数字/下划线/点/短横线
_SAFE_REPORT_FILENAME = re.compile(r'^[A-Za-z0-9_.-]+$')


@asynccontextmanager
async def lifespan(app: FastAPI):
    runtime.request_sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    runtime.llm_sem = asyncio.Semaphore(MAX_LLM_CONCURRENT)
    runtime.ocr_sem = asyncio.Semaphore(MAX_OCR_CONCURRENT)
    runtime.pool = ThreadPoolExecutor(max_workers=BLOCKING_WORKERS)
    runtime.llm_client = AsyncOpenAI(
        api_key=LLM_API_KEY, base_url=LLM_API_BASE, timeout=LLM_TIMEOUT
    )
    cleanup_task = asyncio.create_task(_cleanup_loop())
    logger.info(
        f"[startup] 并发上限: 请求={MAX_CONCURRENT_REQUESTS}, LLM={MAX_LLM_CONCURRENT}, "
        f"OCR={MAX_OCR_CONCURRENT}, 线程={BLOCKING_WORKERS} | "
        f"溯源硬上限={TRACE_HARD_TIMEOUT_SECONDS}s | 溯源锁过期={TRACE_LOCK_EXPIRE_SECONDS}s"
    )
    yield
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    runtime.pool.shutdown(wait=True)
    await runtime.llm_client.close()


app = FastAPI(title="邮件钓鱼检测API", lifespan=lifespan)


class EmailRequest(BaseModel):
    email_content: str


@app.post("/analyze")
async def analyze(req: EmailRequest):
    try:
        await asyncio.wait_for(runtime.request_sem.acquire(), timeout=QUEUE_WAIT_SECONDS)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=503, detail="服务繁忙", headers={"Retry-After": "5"})
    try:
        return await asyncio.wait_for(analyze_email(req.email_content), timeout=REQUEST_TIMEOUT)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="分析超时")
    finally:
        runtime.request_sem.release()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/report/{filename}")
async def get_report(filename: str):
    # ★ 防路径穿越：只允许字母/数字/下划线/点/短横线，且排除 "." 和 ".."
    if (not filename or filename in (".", "..")
            or not _SAFE_REPORT_FILENAME.match(filename)):
        raise HTTPException(status_code=400, detail="非法文件名")

    filepath = os.path.join(REPORT_DIR, filename)

    # ★ 双保险：确保解析后仍在 REPORT_DIR 内
    real_path = os.path.realpath(filepath)
    real_root = os.path.realpath(REPORT_DIR)
    if not real_path.startswith(real_root + os.sep):
        raise HTTPException(status_code=400, detail="非法文件名")

    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail="报告不存在")

    if time.time() - os.path.getmtime(filepath) > 3 * 86400:
        try:
            os.remove(filepath)
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="报告已过期（有效期 3 天）")

    return FileResponse(filepath)


@app.post("/trace/trigger")
async def _trace_trigger():
    return await trigger_trace()


@app.get("/trace/status/{task_id}")
async def _trace_status(task_id: str):
    return await trace_status(task_id)