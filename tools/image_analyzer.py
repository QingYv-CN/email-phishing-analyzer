import base64
import requests


UMI_OCR_BASE = "http://127.0.0.1:1224"
OCR_URL = f"{UMI_OCR_BASE}/api/ocr"
QRCODE_URL = f"{UMI_OCR_BASE}/api/qrcode"


def _image_to_base64(image_path: str) -> str:
    """把图片文件转成 Umi-OCR 需要的 Base64 字符串（无前缀）"""
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def _call_ocr(image_path: str) -> str:
    """调用 Umi-OCR 的文字识别接口，返回识别出的文本"""
    try:
        resp = requests.post(
            OCR_URL,
            json={"base64": _image_to_base64(image_path)},
            timeout=60,
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("code") == 100:
            data = result.get("data", "")
            # 部分版本返回字符串，部分返回列表，两种都兼容
            if isinstance(data, list):
                return "\n".join(
                    item.get("text", "") for item in data if isinstance(item, dict)
                ).strip()
            return str(data).strip()
        return ""
    except Exception:
        return ""


def _call_qrcode(image_path: str) -> list[dict]:
    """调用 Umi-OCR 的二维码识别接口，返回二维码信息列表"""
    try:
        resp = requests.post(
            QRCODE_URL,
            json={"base64": _image_to_base64(image_path)},
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("code") == 100:
            data = result.get("data", [])
            if isinstance(data, list):
                return [
                    {"text": item.get("text", ""), "format": item.get("format", "")}
                    for item in data if item.get("text")
                ]
            return []
        return []
    except Exception:
        return []


def extract_images_content(image_list: list[str]) -> dict:
    """
    批量分析邮件中的所有图片，同时进行 OCR 文字识别和二维码识别。
    当邮件中发现图片时调用，一次性传入所有图片，不要逐张调用。
    返回每张图片的文字内容和二维码内容。

    Args:
        image_list: 图片路径列表

    Returns:
        {
            "total_images": 图片总数,
            "text_found_count": 有文字内容的图片数,
            "qr_found_count": 有二维码的图片数,
            "results": [
                {
                    "image": "图片路径",
                    "ocr_text": "识别出的文字（无则空串）",
                    "qr_codes": [{"text": "二维码内容", "format": "QRCode"}],
                    "error": null
                }
            ]
        }
    """
    results = []
    for img in image_list:
        try:
            ocr_text = _call_ocr(img)
            qr_codes = _call_qrcode(img)
            results.append({
                "image": img,
                "ocr_text": ocr_text,
                "qr_codes": qr_codes,
                "error": None,
            })
        except Exception as e:
            results.append({
                "image": img,
                "ocr_text": "",
                "qr_codes": [],
                "error": str(e),
            })
    return {
        "total_images": len(image_list),
        "text_found_count": sum(1 for r in results if r["ocr_text"]),
        "qr_found_count": sum(1 for r in results if r["qr_codes"]),
        "results": results,
    }