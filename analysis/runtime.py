"""进程级 runtime：并发闸、线程池、LLM 客户端、临时文件清理。"""

import asyncio
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor

from config import ATTACHMENT_DIR


class Runtime:
    request_sem: asyncio.Semaphore = None
    llm_sem: asyncio.Semaphore = None
    ocr_sem: asyncio.Semaphore = None
    pool: ThreadPoolExecutor = None
    llm_client = None
    inflight: int = 0
    total_ok: int = 0
    total_err: int = 0


runtime = Runtime()
_inflight_lock = asyncio.Lock()


async def _run_blocking(fn, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(runtime.pool, fn, *args)


async def _cleanup_loop():
    while True:
        try:
            await asyncio.sleep(300)
            now = time.time()
            if not os.path.isdir(ATTACHMENT_DIR):
                continue
            for name in os.listdir(ATTACHMENT_DIR):
                full = os.path.join(ATTACHMENT_DIR, name)
                if now - os.path.getmtime(full) > 600:
                    if os.path.isfile(full):
                        os.remove(full)
                    elif os.path.isdir(full):
                        shutil.rmtree(full, ignore_errors=True)
        except asyncio.CancelledError:
            break
        except Exception:
            pass