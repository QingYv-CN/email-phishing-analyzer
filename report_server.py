import os
import time
import logging
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from config import REPORT_SERVER_PORT

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("report_server")

app = FastAPI()

REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


@app.get("/report/{filename}")
async def get_report(filename: str):
    # 防止路径穿越
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="非法文件名")

    filepath = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="报告不存在")

    # 3 天有效期
    if time.time() - os.path.getmtime(filepath) > 3 * 86400:
        try:
            os.remove(filepath)
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="报告已过期（有效期 3 天）")

    return FileResponse(filepath)


if __name__ == "__main__":
    logger.info(f"报告服务启动在 http://0.0.0.0:{REPORT_SERVER_PORT}")
    uvicorn.run(app, host="0.0.0.0", port=REPORT_SERVER_PORT)