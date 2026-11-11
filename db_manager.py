import sqlite3
import json
import time
import hashlib
import os
import logging
import threading

from config import DB_PATH, HISTORY_RETENTION_HOURS, FINGERPRINT_RETENTION_DAYS

logger = logging.getLogger("db_manager")

# 线程局部连接缓存 —— 每个线程复用同一连接
_local = threading.local()


def _get_conn():
    """获取当前线程的 SQLite 连接（缓存复用 + 健康检查）"""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
            return conn
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            pass
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    _local.conn = conn
    return conn


def init_db():
    conn = _get_conn()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_history (
                id TEXT PRIMARY KEY,
                timestamp INTEGER,
                email_ts INTEGER,
                verdict_code TEXT,
                mail_from TEXT,
                subject TEXT,
                raw_json TEXT
            )
        ''')
        # ★ migration：老库没有 email_ts 列，加上（SQLite ADD COLUMN 幂等性靠 catch）
        try:
            cursor.execute("ALTER TABLE analysis_history ADD COLUMN email_ts INTEGER")
            logger.info("[migration] analysis_history 新增 email_ts 列")
        except sqlite3.OperationalError:
            pass

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alert_fingerprints (
                fingerprint TEXT PRIMARY KEY,
                campaign_name TEXT,
                first_seen INTEGER,
                last_seen INTEGER,
                alert_sent INTEGER DEFAULT 0
            )
        ''')
        conn.commit()
        logger.info(f"数据库初始化完成: {DB_PATH}")
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
    finally:
        pass


def save_analysis_result(req_id: str, normalized: dict, mail_from: str):
    if not normalized.get("success"):
        return

    result = normalized.get("result", {})
    verdict_code = result.get("verdict_code")

    if verdict_code not in ("high", "suspicious"):
        return

    now = int(time.time())

    # ★ 新增：优先用邮件 Date 头 epoch（email_timestamp），缺失则 fallback 分析时刻
    meta = normalized.get("meta", {}) or {}
    email_ts = meta.get("email_timestamp")
    if not isinstance(email_ts, int) or email_ts <= 0:
        email_ts = now

    subject = result.get("summary", "")[:100]

    conn = _get_conn()
    cursor = conn.cursor()
    try:
        # 去重窗口：仍按分析时刻（now - 2h）判断，保持原有"2小时内同发件人+主题合并"语义
        cursor.execute('''
            SELECT id FROM analysis_history
            WHERE mail_from = ? AND subject = ? AND timestamp > ?
        ''', (mail_from, subject, now - 7200))

        existing = cursor.fetchone()

        if existing:
            cursor.execute('''
                UPDATE analysis_history
                SET timestamp = ?, email_ts = ?, raw_json = ?, id = ?
                WHERE id = ?
            ''', (now, email_ts, json.dumps(normalized, ensure_ascii=False), req_id, existing[0]))
        else:
            cursor.execute('''
                INSERT OR REPLACE INTO analysis_history
                (id, timestamp, email_ts, verdict_code, mail_from, subject, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                req_id, now, email_ts, verdict_code, mail_from, subject,
                json.dumps(normalized, ensure_ascii=False)
            ))

        conn.commit()
    except Exception as e:
        logger.error(f"[{req_id}] 写入数据池失败: {e}")
    finally:
        pass


def get_24h_suspicious_mails() -> list[dict]:
    """获取过去 24 小时内发送的高危/可疑邮件分析结果（按邮件 Date 头算，缺失则 fallback 分析时刻）"""
    conn = _get_conn()
    cursor = conn.cursor()
    threshold = int(time.time()) - (HISTORY_RETENTION_HOURS * 3600)

    try:
        cursor.execute('''
            SELECT raw_json FROM analysis_history
            WHERE COALESCE(email_ts, timestamp) > ? AND verdict_code IN ('high', 'suspicious')
            ORDER BY COALESCE(email_ts, timestamp) DESC LIMIT 200
        ''', (threshold,))

        rows = cursor.fetchall()
        results = []
        for row in rows:
            try:
                results.append(json.loads(row[0]))
            except json.JSONDecodeError:
                continue
        return results
    except Exception as e:
        logger.error(f"查询 24h 数据池失败: {e}")
        return []
    finally:
        pass


def check_and_set_fingerprint(campaign_features: dict, campaign_name: str = "") -> bool:
    mail_from = sorted(campaign_features.get("mailFrom", []))
    domains = sorted(campaign_features.get("domains", []))

    fp_str = f"{','.join(mail_from)}|{','.join(domains)}"
    if not fp_str.strip() or fp_str == "|":
        fp_str = campaign_name

    fingerprint = hashlib.md5(fp_str.encode('utf-8')).hexdigest()

    conn = _get_conn()
    cursor = conn.cursor()
    now = int(time.time())

    try:
        cursor.execute("SELECT last_seen FROM alert_fingerprints WHERE fingerprint = ?", (fingerprint,))
        row = cursor.fetchone()

        if row:
            last_seen = row[0]
            if now - last_seen < 86400:
                cursor.execute("UPDATE alert_fingerprints SET last_seen = ? WHERE fingerprint = ?", (now, fingerprint))
                conn.commit()
                return False

        cursor.execute('''
            INSERT INTO alert_fingerprints (fingerprint, campaign_name, first_seen, last_seen, alert_sent)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(fingerprint) DO UPDATE SET
                last_seen = ?,
                campaign_name = ?,
                alert_sent = 1
        ''', (fingerprint, campaign_name, now, now, now, campaign_name))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"指纹去重操作失败: {e}")
        return True
    finally:
        pass


def cleanup_old_records():
    """
    清理过期数据（按邮件 Date 头算，缺失则 fallback 分析时刻）
    - analysis_history 清理超过 24 小时发送的邮件
    - alert_fingerprints 清理超过 7 天未更新的指纹
    """
    now = int(time.time())
    history_threshold = now - HISTORY_RETENTION_HOURS * 3600
    fingerprint_threshold = now - FINGERPRINT_RETENTION_DAYS * 86400

    conn = _get_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM analysis_history WHERE COALESCE(email_ts, timestamp) < ?",
            (history_threshold,)
        )
        deleted_history = cursor.rowcount

        cursor.execute("DELETE FROM alert_fingerprints WHERE last_seen < ?", (fingerprint_threshold,))
        deleted_fingerprints = cursor.rowcount

        conn.commit()

        if deleted_history or deleted_fingerprints:
            logger.info(f"[cleanup] 清理了 {deleted_history} 条历史记录、{deleted_fingerprints} 条过期指纹")
    except Exception as e:
        logger.error(f"[cleanup] 数据库清理失败: {e}")
    finally:
        pass


init_db()