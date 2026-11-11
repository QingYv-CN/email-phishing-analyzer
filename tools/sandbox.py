"""
附件分析工具 —— 兼容 Windows / Linux。
- .zip / .tar / .gz / .tgz / .bz2 / .xz：Python 标准库，无需外部工具
- .7z：py7zr（可选）
- .rar：优先 rarfile + unrar/unar，否则回退到 7z 命令行
- 其它 7z 命令支持的格式：统一走 7z 命令行

★ 新增：文件头魔数检测
- 读取附件前 512 字节（ISO 额外读 offset 0x8001），判断真实文件类型
- 与声称的扩展名比对，输出 mismatch + severity（high / medium / low / none / unknown）
- 检测经典双扩展名伪装（invoice.pdf.exe）
- 风险等级综合升级：声称低危但实际是高危可执行文件，一律升 high

依赖（可选）：
    pip install py7zr rarfile
系统工具（Linux）：
    sudo apt install p7zip-full
系统工具（Windows）：
    安装 7-Zip 或 WinRAR，或在 PATH 里放 unrar.exe
"""

import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

# ---------- 可选依赖 ----------
try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False

try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False


# ---------- 自动探测外部解压工具 ----------
def _find_tool(*names: str) -> str | None:
    """在 PATH 里依次查找，返回找到的第一个可执行文件路径"""
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


SEVEN_ZIP = _find_tool("7z", "7za", "7zz")
UNRAR = _find_tool("unrar", "unar")

if HAS_RARFILE and UNRAR:
    try:
        rarfile.UNRAR_TOOL = UNRAR
    except Exception:
        pass


# ---------- 扩展名与风险分类 ----------
ARCHIVE_EXTS = {
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".7z", ".rar", ".cab", ".iso",
}

HIGH_RISK_EXTS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".jar", ".msi",
    ".dll", ".lnk", ".hta", ".cpl", ".iso", ".img", ".vhd", ".vhdx", ".udf",
}

MEDIUM_RISK_EXTS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".rtf",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".cab",
    ".doc", ".xls", ".ppt",
}

# Office OOXML 内部就是 ZIP 容器；这类扩展在压缩包判定时排除，避免展开成 XML 噪音
OFFICE_OOXML_EXTS = {
    ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
    ".dotm", ".xltm", ".potm", ".ppsx",
}

# 纯文本类扩展：无魔数可比对（.js/.vbs/.bat 等已在 HIGH_RISK_EXTS 单独按扩展名判高危）
TEXTUAL_EXTS = {
    ".txt", ".csv", ".html", ".htm", ".xml", ".json", ".md",
    ".js", ".vbs", ".bat", ".cmd", ".ps1", ".py", ".sh", ".bash",
    ".log", ".ini", ".cfg", ".conf", ".yaml", ".yml",
}


# ---------- 魔数表 ----------
# (offset, signature, magic_type)
MAGIC_SIGNATURES = [
    (0, b"MZ", "pe"),
    (0, b"%PDF", "pdf"),
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip_empty"),
    (0, b"PK\x07\x08", "zip_span"),
    (0, b"Rar!\x1a\x07\x00", "rar4"),
    (0, b"Rar!\x1a\x07\x01\x00", "rar5"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"GIF87a", "gif"),
    (0, b"GIF89a", "gif"),
    (0, b"BM", "bmp"),
    (0, b"II*\x00", "tiff"),
    (0, b"MM\x00*", "tiff"),
    (0, b"\x00\x00\x01\x00", "ico"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (0, b"{\\rtf", "rtf"),
    (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (0, b"OggS", "ogg"),
    (0, b"ID3", "mp3"),
    (0, b"fLaC", "flac"),
    (0, b"FLV", "flv"),
    (257, b"ustar", "tar"),
]

# 声称扩展名 → 可接受的 magic 类型集合
EXT_TO_EXPECTED_MAGIC = {
    # 可执行
    ".exe": {"pe"}, ".dll": {"pe"}, ".scr": {"pe"},
    ".com": {"pe"}, ".pif": {"pe"}, ".cpl": {"pe"}, ".msi": {"ole"},
    # 文档
    ".pdf": {"pdf"},
    ".zip": {"zip", "zip_empty", "zip_span"},
    ".rar": {"rar4", "rar5"},
    ".7z": {"7z"},
    ".tar": {"tar"},
    ".gz": {"gzip"}, ".tgz": {"gzip"},
    ".bz2": {"bzip2"}, ".xz": {"xz"},
    ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"},
    ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"},
    ".docm": {"zip"}, ".xlsm": {"zip"}, ".pptm": {"zip"},
    ".dotm": {"zip"}, ".xltm": {"zip"}, ".potm": {"zip"}, ".ppsx": {"zip"},
    ".rtf": {"rtf"},
    ".lnk": {"lnk"},
    ".iso": {"iso"},
    # 图片/音频/视频
    ".jpg": {"jpeg"}, ".jpeg": {"jpeg"},
    ".png": {"png"}, ".gif": {"gif"}, ".bmp": {"bmp"},
    ".tif": {"tiff"}, ".tiff": {"tiff"},
    ".svg": {"svg", "xml", "text"},
    ".ico": {"ico"},
    ".mp3": {"mp3"}, ".flac": {"flac"}, ".ogg": {"ogg"},
    ".wav": {"wav"}, ".avi": {"avi"}, ".webp": {"webp"},
}

# 可作为压缩包展开的 magic 类型
ARCHIVE_MAGIC_TYPES = frozenset({
    "zip", "zip_empty", "zip_span",
    "rar4", "rar5", "7z", "tar",
    "gzip", "bzip2", "xz",
})

# 双扩展名伪装涉及的"伪装层"扩展（.pdf.exe 里的 .pdf）
DISGUISE_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".zip", ".rar", ".7z",
}


# ---------- 内部工具 ----------
def _get_ext(name: str) -> str:
    base = os.path.basename(name).rstrip("/")
    if "." not in base:
        return ""
    return "." + base.rsplit(".", 1)[-1].lower()


def _is_archive(name: str) -> bool:
    return _get_ext(name) in ARCHIVE_EXTS


def _classify_file(name: str) -> str:
    ext = _get_ext(name)
    if ext in HIGH_RISK_EXTS:
        return "high"
    if ext in MEDIUM_RISK_EXTS:
        return "medium"
    return "low"


def _combine_risk(by_ext: str, by_magic: str) -> str:
    """按扩展名判定的风险等级 与 按魔数判定的等级 取较高者"""
    rank = {"high": 3, "medium": 2, "low": 1, "unknown": 0, "none": 0, "empty": 0}
    return by_ext if rank.get(by_ext, 0) >= rank.get(by_magic, 0) else by_magic


# ---------- 魔数检测 ----------
def _detect_magic(file_path: str) -> str:
    """读取文件头，返回真实类型名；读取失败返回 'unknown'"""
    try:
        with open(file_path, "rb") as f:
            head = f.read(512)
    except Exception:
        return "unknown"

    if not head:
        return "empty"

    # RIFF 细分（webp / avi / wav）
    if head.startswith(b"RIFF") and len(head) >= 12:
        sub = head[8:12]
        if sub == b"WEBP":
            return "webp"
        if sub == b"AVI ":
            return "avi"
        if sub == b"WAVE":
            return "wav"
        return "riff"

    for offset, sig, mtype in MAGIC_SIGNATURES:
        if offset == 0:
            if head.startswith(sig):
                return mtype
        else:
            if len(head) >= offset + len(sig) and head[offset:offset + len(sig)] == sig:
                return mtype

    # ISO9660 在 offset 0x8001
    try:
        if os.path.getsize(file_path) > 0x8006:
            with open(file_path, "rb") as f:
                f.seek(0x8001)
                if f.read(5) == b"CD001":
                    return "iso"
    except Exception:
        pass

    # 纯文本判定：前 100 字节全部可打印（含 \r\n\t）
    try:
        text = head.decode("utf-8", errors="strict")[:100]
        if text and all((c.isprintable() or c in "\r\n\t") for c in text):
            return "text"
    except (UnicodeDecodeError, ValueError):
        pass

    return "unknown"


def _check_double_extension(filename: str):
    """检测 'invoice.pdf.exe' 这类伪装；返回 (is_double, detail)"""
    if not filename:
        return False, ""
    base = os.path.basename(filename).strip()
    parts = base.split(".")
    if len(parts) < 3:
        return False, ""
    second_last = "." + parts[-2].lower()
    last = "." + parts[-1].lower()
    if second_last in DISGUISE_EXTS and last in HIGH_RISK_EXTS:
        return True, f"双扩展名伪装：{parts[-2]}{parts[-1]}"
    return False, ""


def _check_mismatch(claimed_ext: str, magic_type: str):
    """
    比对声称扩展名与真实魔数类型。
    返回 (mismatch: bool, severity: str, detail: str)
    severity ∈ {high, medium, low, none, unknown}
    """
    claimed_ext = (claimed_ext or "").lower()

    # 无扩展名：只在真实类型是危险文件时告警
    if not claimed_ext:
        if magic_type in {"pe", "lnk", "iso", "ole"}:
            return True, "high", f"⚠️ 无扩展名，实际是 {magic_type.upper()}（可执行/快捷方式）"
        if magic_type in ARCHIVE_MAGIC_TYPES:
            return True, "medium", f"无扩展名，实际是压缩包（{magic_type}）"
        if magic_type in {"png", "jpeg", "gif", "bmp", "tiff", "webp", "ico"}:
            return False, "none", f"无扩展名，实际是图片（{magic_type}）"
        if magic_type == "text":
            return False, "none", "无扩展名，纯文本文件"
        return False, "unknown", f"无扩展名，真实类型 {magic_type} 无法判定"

    # 文本类扩展：无魔数概念，不判
    if claimed_ext in TEXTUAL_EXTS:
        return False, "none", "文本类文件，无魔数可比对"

    expected = EXT_TO_EXPECTED_MAGIC.get(claimed_ext)
    if expected is None:
        return False, "unknown", f"未知扩展 {claimed_ext}，跳过魔数比对"

    if magic_type == "unknown":
        return False, "unknown", "无法识别文件真实类型"

    if magic_type == "empty":
        return True, "low", "空文件，无法读取文件头"

    if magic_type == "text":
        return True, "low", f"声称 {claimed_ext}，实际是纯文本"

    if magic_type in expected:
        return False, "none", f"文件头与声称的 {claimed_ext} 一致"

    # 不匹配 —— 按危险度分级
    if magic_type in {"pe", "lnk", "iso"}:
        return True, "high", f"⚠️ 声称 {claimed_ext}，实际是 {magic_type.upper()}（可执行/快捷方式/镜像）"
    if magic_type == "ole":
        return True, "medium", f"声称 {claimed_ext}，实际是 OLE 复合文档（老 Office / MSI）"
    if magic_type in ARCHIVE_MAGIC_TYPES:
        return True, "medium", f"声称 {claimed_ext}，实际是压缩包（{magic_type}）"
    return True, "low", f"声称 {claimed_ext}，实际是 {magic_type}"


# ---------- 目录树构建 ----------
def _build_tree(names: list[str]) -> dict:
    tree = {}
    for name in names:
        clean = name.replace("\\", "/")
        parts = [p for p in clean.split("/") if p]
        if not parts:
            continue
        current = tree
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                if clean.endswith("/"):
                    current.setdefault(part + "/", {})
                else:
                    if part + "/" not in current:
                        current[part] = None
            else:
                current = current.setdefault(part + "/", {})
    return tree


def _convert_tree(tree: dict) -> list[dict]:
    result = []
    for key, value in tree.items():
        if value is None:
            result.append({
                "name": key,
                "type": "file",
                "ext": _get_ext(key),
                "risk": _classify_file(key),
            })
        else:
            result.append({
                "name": key.rstrip("/"),
                "type": "dir",
                "children": _convert_tree(value),
            })
    return result


def _has_high_risk(nodes: list[dict]) -> bool:
    for item in nodes:
        if item["type"] == "file" and item.get("risk") == "high":
            return True
        if item["type"] in ("dir", "nested_archive") and _has_high_risk(item.get("children", [])):
            return True
    return False


def _count_files(nodes: list[dict]) -> int:
    count = 0
    for item in nodes:
        if item["type"] == "file":
            count += 1
        elif item["type"] in ("dir", "nested_archive"):
            count += _count_files(item.get("children", []))
    return count


# ---------- 压缩包成员列举 ----------
def _list_via_7z(path: str) -> list[str]:
    if not SEVEN_ZIP:
        return []
    try:
        result = subprocess.run(
            [SEVEN_ZIP, "l", "-ba", "-slt", "--", path],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
        if result.returncode != 0:
            return []
        names = []
        for line in result.stdout.splitlines():
            if line.startswith("Path = "):
                name = line[7:].strip()
                if name:
                    names.append(name)
        if names and os.path.basename(path) in names[0]:
            names = names[1:]
        return names
    except Exception:
        return []


def _list_zip(path: str) -> list[str]:
    try:
        with zipfile.ZipFile(path) as zf:
            return zf.namelist()
    except Exception:
        return []


def _list_tar(path: str) -> list[str]:
    try:
        with tarfile.open(path) as tf:
            return tf.getnames()
    except Exception:
        return []


def _list_7z(path: str) -> list[str]:
    if HAS_PY7ZR:
        try:
            with py7zr.SevenZipFile(path) as zf:
                return zf.getnames()
        except Exception:
            pass
    return _list_via_7z(path)


def _list_rar(path: str) -> list[str]:
    if HAS_RARFILE:
        try:
            with rarfile.RarFile(path) as rf:
                return rf.namelist()
        except Exception:
            pass
    return _list_via_7z(path)


def _list_members(path: str) -> list[str]:
    """按扩展名分派列举成员"""
    ext = _get_ext(path)
    if ext == ".zip":
        return _list_zip(path)
    if ext in (".tar", ".gz", ".tgz", ".bz2", ".xz"):
        return _list_tar(path)
    if ext == ".7z":
        return _list_7z(path)
    if ext == ".rar":
        return _list_rar(path)
    return _list_via_7z(path)


def _list_members_by_magic(path: str, magic_type: str) -> list[str]:
    """按魔数类型分派列举成员"""
    if magic_type in {"zip", "zip_empty", "zip_span"}:
        return _list_zip(path)
    if magic_type in {"rar4", "rar5"}:
        return _list_rar(path)
    if magic_type == "7z":
        return _list_7z(path)
    if magic_type in {"tar", "gzip", "bzip2", "xz"}:
        return _list_tar(path)
    return _list_via_7z(path)


def _list_members_smart(path: str, magic_type: str) -> list[str]:
    """优先按魔数类型列举（比扩展名可靠）；失败时回退到扩展名"""
    if magic_type in ARCHIVE_MAGIC_TYPES:
        names = _list_members_by_magic(path, magic_type)
        if names:
            return names
    return _list_members(path)


# ---------- 主工具函数 ----------
def analyze_attachment(attachments: list[dict]) -> dict:
    """
    分析邮件附件结构。对每个附件：
    1. 读取文件头，识别真实类型（PE/PDF/ZIP/OLE/... 等）
    2. 与声称扩展名比对，输出 mismatch + severity
    3. 检测双扩展名伪装（invoice.pdf.exe）
    4. 若是压缩包（按扩展名或魔数判定），递归展开其内部结构（最多 2 层）
    5. 风险等级综合升级：声称低危但实际高危，一律升 high

    Args:
        attachments: 附件列表，每项形如 {"filename": "...", "type": "...", "path": "..."}

    Returns:
        {
            "total": 附件总数,
            "archive_count": 按压缩包处理的数量,
            "high_risk_count": 风险等级为 high 的附件数,
            "mismatch_high_count": 文件类型高度不一致的数量（伪装可执行等）,
            "mismatch_medium_count": 文件类型中度不一致的数量（伪装压缩包等）,
            "results": [
                {
                    "filename": "...",
                    "type": "...",
                    "is_archive": bool,
                    "risk_level": "high" / "medium" / "low" / "unknown",
                    "summary": "...",
                    "tree": [...] (仅压缩包),
                    "file_type_check": {
                        "magic_type": "pe" / "pdf" / "zip" / ...,
                        "claimed_ext": ".pdf",
                        "mismatch": bool,
                        "severity": "high" / "medium" / "low" / "none" / "unknown",
                        "double_ext": bool,
                        "detail": "..."
                    },
                    "error": None
                }
            ]
        }
    """
    results = []

    for att in attachments:
        filename = att.get("filename", "")
        file_path = att.get("path", "")
        claimed_ext = _get_ext(filename) or _get_ext(file_path)

        # 双扩展名检测（不依赖文件存在）
        double_ext, double_ext_detail = _check_double_extension(filename)

        # ---- 文件不存在 ----
        if not file_path or not os.path.isfile(file_path):
            results.append({
                "filename": filename,
                "type": att.get("type", ""),
                "is_archive": _is_archive(filename) or _is_archive(file_path),
                "risk_level": "unknown",
                "summary": f"文件不存在或路径无效: {file_path}",
                "error": "FILE_NOT_FOUND",
                "file_type_check": {
                    "magic_type": "unknown",
                    "claimed_ext": claimed_ext,
                    "mismatch": False,
                    "severity": "unknown",
                    "double_ext": double_ext,
                    "detail": "文件不存在，无法读取文件头",
                },
            })
            continue

        # ---- 魔数检测 ----
        magic_type = _detect_magic(file_path)
        mismatch, severity, detail = _check_mismatch(claimed_ext, magic_type)
        if double_ext:
            detail = (detail + "；" + double_ext_detail) if detail else double_ext_detail

        file_type_check = {
            "magic_type": magic_type,
            "claimed_ext": claimed_ext,
            "mismatch": mismatch,
            "severity": severity,
            "double_ext": double_ext,
            "detail": detail,
        }

        # ---- 是否按压缩包处理 ----
        is_arc_by_name = _is_archive(filename) or _is_archive(file_path)
        is_arc_by_magic = (magic_type in ARCHIVE_MAGIC_TYPES) and (claimed_ext not in OFFICE_OOXML_EXTS)
        treat_as_archive = is_arc_by_name or is_arc_by_magic

        # ============ 压缩包分支 ============
        if treat_as_archive:
            try:
                names = _list_members_smart(file_path, magic_type)

                if not names:
                    ext = _get_ext(file_path)
                    if is_arc_by_name:
                        if ext == ".rar" and not HAS_RARFILE and not SEVEN_ZIP:
                            err = "RAR 需要 rarfile+unrar 或 7z；Linux: apt install p7zip-full"
                        elif ext == ".7z" and not HAS_PY7ZR and not SEVEN_ZIP:
                            err = "7z 需要 py7zr 或 7z 命令行；Linux: apt install p7zip-full"
                        else:
                            err = "无法列出压缩包内容（格式不支持、文件损坏或工具缺失）"
                    else:
                        err = f"魔数判定为 {magic_type}，但无法解析内容（可能损坏或工具缺失）"
                    results.append({
                        "filename": filename,
                        "type": att.get("type", ""),
                        "is_archive": True,
                        "risk_level": _combine_risk("medium", severity),
                        "summary": f"压缩包解析失败：{err}",
                        "tree": [],
                        "file_type_check": file_type_check,
                        "error": err,
                    })
                    continue

                tree = _build_tree(names)
                children = _convert_tree(tree)
                has_high = _has_high_risk(children)
                file_count = _count_files(children)

                base_risk = "high" if has_high else "medium"
                final_risk = _combine_risk(base_risk, severity)

                summary = f"压缩包，含 {file_count} 个文件"
                if has_high:
                    summary += "，其中发现高危可执行文件"
                if mismatch:
                    summary += f"；{detail}"

                results.append({
                    "filename": filename,
                    "type": att.get("type", ""),
                    "is_archive": True,
                    "risk_level": final_risk,
                    "summary": summary,
                    "tree": children,
                    "file_type_check": file_type_check,
                    "error": None,
                })
            except Exception as e:
                results.append({
                    "filename": filename,
                    "type": att.get("type", ""),
                    "is_archive": True,
                    "risk_level": "unknown",
                    "summary": f"解析异常: {type(e).__name__}: {e}",
                    "tree": [],
                    "file_type_check": file_type_check,
                    "error": str(e),
                })

        # ============ 非压缩包分支 ============
        else:
            ext_risk = _classify_file(filename)
            final_risk = _combine_risk(ext_risk, severity)

            summary = f"非压缩包文件，扩展名 {claimed_ext or '无'}，风险等级 {final_risk}"
            if mismatch:
                summary += f"；{detail}"

            results.append({
                "filename": filename,
                "type": att.get("type", ""),
                "ext": claimed_ext,
                "is_archive": False,
                "risk_level": final_risk,
                "summary": summary,
                "file_type_check": file_type_check,
                "error": None,
            })

    return {
        "total": len(attachments),
        "archive_count": sum(1 for r in results if r.get("is_archive")),
        "high_risk_count": sum(1 for r in results if r.get("risk_level") == "high"),
        "mismatch_high_count": sum(
            1 for r in results if (r.get("file_type_check") or {}).get("severity") == "high"
        ),
        "mismatch_medium_count": sum(
            1 for r in results if (r.get("file_type_check") or {}).get("severity") == "medium"
        ),
        "results": results,
    }


# ---------- 环境自检 ----------
def check_environment() -> dict:
    return {
        "platform": os.name,
        "seven_zip": SEVEN_ZIP,
        "unrar": UNRAR,
        "py7zr_installed": HAS_PY7ZR,
        "rarfile_installed": HAS_RARFILE,
        "supported_formats": {
            "zip": "stdlib",
            "tar/gz/tgz/bz2/xz": "stdlib",
            "7z": "py7zr" if HAS_PY7ZR else ("7z" if SEVEN_ZIP else "unsupported"),
            "rar": (
                "rarfile+unrar" if (HAS_RARFILE and UNRAR)
                else ("rarfile" if HAS_RARFILE else ("7z" if SEVEN_ZIP else "unsupported"))
            ),
        },
    }


# ---------- 本地测试 ----------
if __name__ == "__main__":
    import json

    print("=" * 70)
    print("环境自检")
    print("=" * 70)
    print(json.dumps(check_environment(), ensure_ascii=False, indent=2))

    # 构造测试文件
    tmpdir = tempfile.gettempdir()
    test_files = {}

    # 1. 正常 PDF
    fake_pdf = os.path.join(tmpdir, "normal.pdf")
    with open(fake_pdf, "wb") as f:
        f.write(b"%PDF-1.4\nfake content")
    test_files["normal.pdf"] = fake_pdf

    # 2. 伪装成 PDF 的 PE（最经典）
    fake_pe_pdf = os.path.join(tmpdir, "disguised.pdf")
    with open(fake_pe_pdf, "wb") as f:
        f.write(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 200)
    test_files["invoice.pdf"] = fake_pe_pdf

    # 3. 双扩展名伪装
    test_files["report.pdf.exe"] = fake_pe_pdf

    # 4. 伪造成图片的 PE
    test_files["photo.jpg"] = fake_pe_pdf

    # 5. 正常 zip
    test_zip = os.path.join(tmpdir, "normal.zip")
    with zipfile.ZipFile(test_zip, "w") as z:
        z.writestr("readme.txt", "hello")
        z.writestr("evil.exe", "fake exe")
    test_files["archive.zip"] = test_zip

    # 6. 伪装成 docx 实际是 zip（正常）
    test_files["report.docx"] = test_zip

    # 7. 伪装成 PDF 实际是 zip（藏匿）
    test_files["hidden.pdf"] = test_zip

    print()
    print("=" * 70)
    print("魔数检测测试")
    print("=" * 70)

    att_list = [
        {"filename": name, "type": "application/octet-stream", "path": path}
        for name, path in test_files.items()
    ]
    result = analyze_attachment(att_list)
    print(json.dumps(result, ensure_ascii=False, indent=2))

    for path in test_files.values():
        try:
            os.remove(path)
        except Exception:
            pass