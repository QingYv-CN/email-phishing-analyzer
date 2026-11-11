"""
统一配置中心 —— 所有模块从此处读取配置。
保持向后兼容：其他模块仍可 from config import XXX 直接使用。
"""

import os
import tempfile

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── LLM ──
LLM_API_BASE = os.getenv("LLM_API_BASE", "https://api.example.com/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "example-model")
LLM_TIMEOUT = 60.0
LLM_MAX_RETRIES = 2
LLM_RETRY_BASE_DELAY = 2.0
# ── 溯源 (tracer) ──
MAX_TOOL_CALLS_PER_CAMPAIGN = 3
CAMPAIGN_CONCURRENCY = 2
BEHAVIOR_CONCURRENCY = 1              # ★ 新增：behavior_check 专用，先给 2，不行再降 1

# ★ 溯源执行时限
# ── 溯源 (tracer) ──
TRACE_HARD_TIMEOUT_SECONDS = 1700.0   # 溯源图执行硬上限，超时即强制结束，用已完成数据出报告
TRACE_LOCK_EXPIRE_SECONDS = 1800.0    # 溯源锁过期兜底，建议 >= HARD + 100

# ── 行为审计（附件下载 / URL 访问） ──
BEHAVIOR_LOOKBACK_HOURS = 24          # 行为查询回溯窗口
BEHAVIOR_QUERY_LENGTH = 500           # 单次查询返回上限
BEHAVIOR_MAX_ATTACHMENT_PATTERNS = 10 # 每个 campaign 最多使用的附件名 pattern 数
BEHAVIOR_MAX_URL_PATTERNS = 20        # 每个 campaign 最多使用的 URL pattern 数

# ── 并发参数 ──
MAX_CONCURRENT_REQUESTS = 50       # 请求级总闸
MAX_LLM_CONCURRENT = 10            # LLM 并发
MAX_OCR_CONCURRENT = 3             # OCR 并发
BLOCKING_WORKERS = 30              # 阻塞线程池
QUEUE_WAIT_SECONDS = 30.0          # 请求排队等待

TOTAL_TIMEOUT = 180.0
REQUEST_TIMEOUT = TOTAL_TIMEOUT + 60.0  # 单请求超时

# ── 分析阶段超时 ──
EMAIL_PARSE_TIMEOUT = 30.0
IMAGE_STEP_TIMEOUT = 90.0
ATTACHMENT_TIMEOUT = 45.0

# ── 截断上限 ──
MAX_BODY_CHARS = 2500
MAX_HTML_CHARS = 2500
MAX_IMAGES = 3
MAX_OCR_CHARS = 1200
MAX_URLS = 30

# ── 数据保留 ──
HISTORY_RETENTION_HOURS = 24
FINGERPRINT_RETENTION_DAYS = 7
MAX_MAIL_AGE_HOURS = 24

# ── 路径 ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "analyzer.db")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
ATTACHMENT_DIR = os.path.join(tempfile.gettempdir(), "email_attachments")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(ATTACHMENT_DIR, exist_ok=True)

# ── API ──
BASE_API_URL = os.getenv("BASE_API_URL", "http://127.0.0.1:8000")

# ── 白名单 ──
TRUSTED_DOMAINS = {
    d.strip().lower()
    for d in os.getenv("TRUSTED_DOMAINS", "example.com,example.org").split(",")
    if d.strip()
}
import os

# 项目根目录（config.py 所在目录），无论从哪个 cwd 启动都能定位
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# 白名单文件：项目根目录下的 whitelist.txt
SAFE_DOMAIN_WHITELIST_FILE = os.path.join(_PROJECT_ROOT, "whitelist.txt")

# ── 反注入 ──
INJECTION_PATTERNS = ["忽略", "忘掉", "系统提示", "ignore previous", "you are now"]

# ── 邮件附件大小上限 ──
MAX_ATTACHMENT_SIZE = 20 * 1024 * 1024  # 20 MB

# ── 日志 / 统计 ──
LOG_DIR = os.path.join(BASE_DIR, "log_query")
TRACE_STATS_LOG_PATH = os.path.join(LOG_DIR, "trace_stats.jsonl")
os.makedirs(LOG_DIR, exist_ok=True)


# ★ 程序化补充 IOC 时，是否补充 VT 判定为 undetected 的 URL
# True（推荐）: 攻击者常用新注册短链域名，VT 未收录，必须补
# False: 只补 malicious/suspicious/phishing，漏掉所有新域名钓鱼
SUPPLEMENT_UNDETECTED_URLS = True