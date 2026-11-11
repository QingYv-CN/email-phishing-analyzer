"""
邮件解析工具 —— 供 Agent 使用。
仅依赖 Python 标准库，无需额外安装。
"""

import os
import re
import tempfile
from email import message_from_bytes
from email.header import decode_header
from email.utils import getaddresses, parsedate_to_datetime

MAX_ATTACHMENT_SIZE = 20 * 1024 * 1024   # 单个附件 20 MB


def _save_attachment(part, filename):
    """把附件/图片保存到临时目录，返回绝对路径"""
    try:
        payload = part.get_payload(decode=True)
        if not payload:
            return None
        if len(payload) > MAX_ATTACHMENT_SIZE:
            print(f"[email_parser] 附件超过 20MB，跳过: {filename}")
            return None
        safe_name = os.path.basename(filename) or "unnamed"
        save_path = os.path.join(ATTACHMENT_DIR, safe_name)
        if os.path.exists(save_path):
            base, ext = os.path.splitext(safe_name)
            save_path = os.path.join(ATTACHMENT_DIR, f"{base}_{os.getpid()}{ext}")
        with open(save_path, "wb") as f:
            f.write(payload)
        return save_path
    except Exception:
        return None


# ---------- 正则 ----------
URL_PATTERN = re.compile(
    r'(?:https?|ftp)://[^\s<>"\'\)\]]+'
    r'|www\.[^\s<>"\'\)\]]+',
    re.IGNORECASE,
)
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
)

ATTACHMENT_DIR = os.path.join(tempfile.gettempdir(), "email_attachments")
os.makedirs(ATTACHMENT_DIR, exist_ok=True)


# ---------- 内部辅助函数 ----------
def _decode_header_value(raw):
    """解码 =?utf-8?B?...?= 这类编码的邮件头"""
    if not raw:
        return ""
    parts = decode_header(raw)
    decoded = []
    for content, charset in parts:
        if isinstance(content, bytes):
            try:
                decoded.append(content.decode(charset or "utf-8", errors="replace"))
            except (LookupError, TypeError):
                decoded.append(content.decode("utf-8", errors="replace"))
        else:
            decoded.append(content)
    return "".join(decoded).strip()


def _get_payload_text(part):
    """安全解码邮件某一部分的文本内容"""
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        try:
            return str(part.get_payload())
        except Exception:
            return ""


def _extract_urls(text):
    """从文本中提取 URL，去掉结尾的标点"""
    if not text:
        return []
    urls = []
    for match in URL_PATTERN.findall(text):
        cleaned = match.rstrip('.,;:!?')
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls


def _extract_ips(text):
    """从文本中提取 IP 地址"""
    if not text:
        return []
    ips = []
    for ip in IP_PATTERN.findall(text):
        if ip not in ips:
            ips.append(ip)
    return ips


# ★ 新增：提取真实发件人（envelope from）
def _extract_envelope_from(received_list: list[str], return_path: str, auth_results: str) -> str:
    """
    提取邮件真实 envelope from（日志系统 mailFrom 字段存的就是它）。
    优先级：Return-Path > Received 里的 mailfrom:xxx > Authentication-Results 里的 smtp.mailfrom=xxx
    注意：From 头（用户看到的发件人）经常是伪造的，不能用于日志查询。
    """
    # 1. Return-Path（最权威）
    rp = (return_path or "").strip().strip("<>").strip()
    if rp and "@" in rp:
        return rp.lower()

    # 2. Received 里的 mailfrom:xxx / mailfrom=xxx
    for r in received_list or []:
        m = re.search(r'mailfrom[=:]\s*<?([\w\.\-+]+@[\w\.\-]+)>?', r, re.IGNORECASE)
        if m:
            return m.group(1).lower()

    # 3. Authentication-Results 里的 smtp.mailfrom=xxx
    m = re.search(r'smtp\.mailfrom\s*=\s*<?([\w\.\-+]+@[\w\.\-]+)>?', auth_results or "", re.IGNORECASE)
    if m:
        return m.group(1).lower()

    return ""


# ---------- 主工具函数 ----------
def parse_email(email_content: str) -> dict:
    """
    解析邮件内容，提取发件人、主题、正文、邮件头、URL、IP、附件和图片列表。
    """
    try:
        if isinstance(email_content, str):
            raw_bytes = email_content.encode("utf-8", errors="replace")
        else:
            raw_bytes = email_content
        msg = message_from_bytes(raw_bytes)
    except Exception as e:
        return {"status": "error", "message": f"邮件解析失败: {e}"}

    # ---- 头部字段 ----
    sender_name_raw, sender_addr = "", ""
    from_header = msg.get("From", "")
    if from_header:
        parsed = getaddresses([_decode_header_value(from_header)])
        if parsed:
            sender_name_raw, sender_addr = parsed[0]

    reply_to = ""
    if msg.get("Reply-To"):
        parsed = getaddresses([_decode_header_value(msg.get("Reply-To"))])
        if parsed:
            reply_to = parsed[0][1]

    return_path = _decode_header_value(msg.get("Return-Path", ""))
    subject = _decode_header_value(msg.get("Subject", ""))
    message_id = _decode_header_value(msg.get("Message-ID", ""))

    date_str = ""
    if msg.get("Date"):
        try:
            date_str = parsedate_to_datetime(msg.get("Date")).isoformat()
        except Exception:
            date_str = msg.get("Date", "")

    received_list = [_decode_header_value(r) for r in msg.get_all("Received", [])]
    auth_results = _decode_header_value(msg.get("Authentication-Results", ""))

    # ★ 新增：提取真实 envelope from
    envelope_from = _extract_envelope_from(received_list, return_path, auth_results)

    # ---- 正文、附件、图片 ----
    text_parts, html_parts = [], []
    attachments, images = [], []

    for part in msg.walk():
        if part.is_multipart():
            continue

        ctype = part.get_content_type()
        disposition = str(part.get("Content-Disposition") or "").lower()
        filename_raw = part.get_filename()
        filename = _decode_header_value(filename_raw) if filename_raw else ""
        content_id = (part.get("Content-ID") or "").strip()

        if ctype == "text/plain" and "attachment" not in disposition:
            text_parts.append(_get_payload_text(part))
            continue
        if ctype == "text/html" and "attachment" not in disposition:
            html_parts.append(_get_payload_text(part))
            continue

        if ctype.startswith("image/") or content_id:
            save_path = _save_attachment(part, filename or f"image_{len(images)}")
            if save_path:
                images.append({
                    "filename": filename or os.path.basename(save_path),
                    "type": ctype,
                    "path": save_path,
                    "content_id": content_id,
                })
            continue

        if "attachment" in disposition or filename:
            save_path = _save_attachment(part, filename or f"attachment_{len(attachments)}")
            if save_path:
                attachments.append({
                    "filename": filename or os.path.basename(save_path),
                    "type": ctype,
                    "path": save_path,
                })
            continue

    body_text = "\n".join(p for p in text_parts if p)
    body_html = "\n".join(p for p in html_parts if p)

    combined_text = "\n".join([body_text, body_html, subject])
    urls = _extract_urls(combined_text)
    ips = _extract_ips(combined_text)

    return {
        "status": "success",
        "data": {
            "sender": sender_addr,
            "sender_name": sender_name_raw,
            "reply_to": reply_to,
            "return_path": return_path,
            "envelope_from": envelope_from,   # ★ 新增
            "subject": subject,
            "date": date_str,
            "headers": {
                "received": received_list,
                "authentication_results": auth_results,
                "message_id": message_id,
            },
            "body_text": body_text,
            "body_html": body_html,
            "urls": urls,
            "ips": ips,
            "attachments": attachments,
            "images": images,
        },
    }


# ---------- 本地测试 ----------
if __name__ == "__main__":
    import json

    sample = """From: Alice <alice@example.com>
To: bob@example.com
Subject: =?UTF-8?B?5rWL6K+V6YKu5Lu2?=
Date: 21 Oct 2026 08:54:59 -0700
Return-Path: <sender@example.net>
Received: from mail.example.net(mailfrom:sender@example.net ip:203.0.113.10)
          by mx.example.com;
          Thu, 22 Oct 2026 01:02:44 +0800
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

test body
"""
    r = parse_email(sample)
    print(json.dumps(r, ensure_ascii=False, indent=2))