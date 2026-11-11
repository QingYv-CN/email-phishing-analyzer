markdown
# Email Phishing Analyzer

一个用于邮件钓鱼检测、IOC 提取、日志溯源与行为审计的示例项目。

项目包含两条主要流程：

1. **单封邮件分析**：解析邮件头、正文、URL、IP、图片 OCR、二维码、附件结构，结合 VirusTotal 情报与 LLM 输出风险结论。
2. **日志溯源与行为审计**：对已判定为可疑/高危的邮件做 IOC 聚类，查询邮件日志定位受影响用户，并审计附件下载 / URL 访问行为。

> 本项目仅用于授权的安全分析与研究。请勿用于未授权监控、邮件内容采集或侵犯隐私的用途。

---

## Features

- 邮件解析：From / Return-Path / Received / Authentication-Results / 正文 / HTML / 附件 / 图片
- URL 与 IP 提取，支持可配置的安全域名白名单
- VirusTotal / VTAI 情报查询接口封装
- 图片 OCR 与二维码识别接口封装（可选）
- 附件魔数检测：识别双扩展名、伪装可执行文件、压缩包结构
- LLM 输出 JSON 归一化与规则交叉验证
- 可疑邮件落库、24 小时数据池、指纹去重
- 日志查询工具：邮件接收日志、附件下载、URL 访问
- 基于 LangGraph 的溯源流水线：聚类 → Agent 查询 → 受害者提取 → 行为审计
- FastAPI HTTP 接口与报告文件下载
- 黑词库：记录导致查询过宽的 filter，降低后续误查

---

## Project Structure

```text
.
├── main.py                     # FastAPI 入口
├── analyzer.py                 # 单封邮件分析入口
├── config.py                   # 配置中心，从环境变量读取
├── db_manager.py               # SQLite 数据池
├── report_server.py            # 独立报告服务示例
├── black_filter_store.py       # 黑词库
├── recipient_blacklist.py      # 收件人展示黑名单
├── trace_stats.py              # 溯源统计 JSONL
├── analysis/                   # 单封邮件分析流水线
├── tracing/                    # 溯源图、Agent、行为审计
├── log_query/                  # 日志查询工具
├── tools/                      # 邮件解析、附件沙箱、OCR、VTAI
├── templates/                  # 报告模板
├── whitelist.example.txt
├── recipient_blacklist.example.txt
└── .env.example
Requirements
Python 3.10+

可选：Umi-OCR 本地服务

可选：7z / unrar 用于部分压缩包解析

可选：VirusTotal / VTAI token

一个 OpenAI 兼容的 LLM API

建议依赖：

bash
pip install fastapi uvicorn openai httpx pydantic requests \
  langchain-core langchain-openai langgraph python-dotenv

# 可选
pip install py7zr rarfile
Quick Start
1. 克隆与安装
bash
git clone https://github.com/your-name/email-phishing-analyzer.git
cd email-phishing-analyzer

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -r requirements.txt
2. 配置环境变量
bash
cp .env.example .env
编辑 .env，填入你自己的：

LLM API 地址、Key、模型名

日志平台地址与 OAuth client 凭证（如使用溯源功能）

VTAI token（如使用情报查询）

安全域名白名单

OCR 服务地址（如使用图片分析）

不要提交 .env。公开仓库只提交 .env.example。

3. 准备白名单文件
bash
cp whitelist.example.txt whitelist.txt
cp recipient_blacklist.example.txt recipient_blacklist.txt
按需编辑：

whitelist.txt：安全域名，不参与恶意 IOC 聚类

recipient_blacklist.txt：不在报告中展示的收件人域名后缀

4. 启动服务
bash
uvicorn main:app --host 0.0.0.0 --port 8000
健康检查：

bash
curl http://127.0.0.1:8000/health
API Usage
分析单封邮件
bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "email_content": "From: Alice <alice@example.com>\nTo: bob@example.com\nSubject: Test\n\nHello"
  }'
返回示例：

json
{
  "success": true,
  "request_id": "req-000001",
  "result": {
    "verdict": "可疑",
    "verdict_code": "suspicious",
    "confidence": "中",
    "confidence_code": "medium",
    "summary": "示例结论",
    "evidence": [],
    "ioc_details": {
      "urls": [],
      "attachments": [],
      "qr_codes": [],
      "image_texts": []
    },
    "advice": {
      "immediate": "示例建议",
      "followup": "示例建议",
      "manual_confirm": "示例动作"
    }
  }
}
触发溯源
bash
curl -X POST http://127.0.0.1:8000/trace/trigger
查询溯源状态
bash
curl http://127.0.0.1:8000/trace/status/<task_id>
下载报告
bash
curl -O http://127.0.0.1:8000/report/<filename>
报告文件默认 3 天过期。

Configuration
主要环境变量：

变量	说明	示例
LLM_API_BASE	OpenAI 兼容 API 地址	https://api.example.com/v1
LLM_API_KEY	LLM API Key	replace-me
LLM_MODEL	模型名	example-model
LOG_BASE_URL	日志平台地址	https://mail.example.com
LOG_CLIENT_ID	日志平台 OAuth client id	replace-me
LOG_CLIENT_SECRET	日志平台 OAuth client secret	replace-me
VTAI_TOKEN	VirusTotal / VTAI token	replace-me
OCR_BASE_URL	Umi-OCR 地址	http://127.0.0.1:1224
TRUSTED_DOMAINS	安全域名，逗号分隔	example.com,example.org
WHITELIST_SENDER_EMAILS	安全发件人邮箱，逗号分隔	security@example.com
SAFE_DOMAIN_WHITELIST_FILE	安全域名文件路径	./whitelist.txt
DB_PATH	SQLite 路径	./analyzer.db
REPORT_DIR	报告目录	./reports
