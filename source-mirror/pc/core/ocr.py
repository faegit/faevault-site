"""OCR 引擎包装：优先 RapidOCR（轻量 onnxruntime 本地推理），回退 Windows WinRT OCR。

RapidOCR 基于 PP-OCR 模型转换为 onnxruntime 格式，体积小、CPU 上初始化和单张
推理均在亚秒到数秒级，远快于 PaddleOCR/EasyOCR 的深度学习管线。
"""

from __future__ import annotations

import difflib
import io
import json
import re
import time
import warnings
from collections import Counter
from functools import lru_cache
from pathlib import Path

import numpy as np
from PIL import Image, ImageOps

from .log import get

_log = get("ocr")

warnings.filterwarnings("ignore")


# 低于此置信度的识别行将被丢弃
_MIN_CONF = 0.4


def _normalize_image(image_bytes: bytes) -> bytes:
    img = Image.open(io.BytesIO(image_bytes))
    img = ImageOps.exif_transpose(img).convert("RGB")
    img = ImageOps.autocontrast(img)
    max_side = max(img.size)
    if max_side < 1200:
        scale = 1200 / max_side
        img = img.resize(
            (int(img.width * scale), int(img.height * scale)),
            Image.LANCZOS,
        )
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


@lru_cache(maxsize=1)
def _rapid_reader():
    from rapidocr_onnxruntime import RapidOCR

    return RapidOCR()


def _ocr_rapid(image_bytes: bytes) -> str:
    _log.debug("RapidOCR 开始识别")
    t0 = time.monotonic()
    image_bytes = _normalize_image(image_bytes)
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    result, _ = _rapid_reader()(np.array(img))
    lines = [text for (_box, text, conf) in result if conf >= _MIN_CONF] if result else []
    _log.debug("RapidOCR 完成，耗时 %.2fs，识别 %d 行", time.monotonic() - t0, len(lines))
    return "\n".join(lines)


# ── WinRT 回退引擎 ────────────────────────────────────────────────────────────


def _ocr_winrt(image_bytes: bytes) -> str:
    import asyncio
    import concurrent.futures

    async def _run() -> str:
        from winrt.windows.graphics.imaging import BitmapDecoder
        from winrt.windows.media.ocr import OcrEngine
        from winrt.windows.storage.streams import DataWriter, InMemoryRandomAccessStream

        stream = InMemoryRandomAccessStream()
        writer = DataWriter(stream.get_output_stream_at(0))
        writer.write_bytes(image_bytes)
        await writer.store_async()
        writer.detach_stream()
        stream.seek(0)

        decoder = await BitmapDecoder.create_async(stream)
        bitmap = await decoder.get_software_bitmap_async()
        engine = OcrEngine.try_create_from_user_profile_languages()
        if engine is None:
            raise RuntimeError("无法初始化 OCR 引擎，请确认系统已安装中文语言包。")
        result = await engine.recognize_async(bitmap)
        return result.text or ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(_run())).result(timeout=15)


# ── 公共入口 ─────────────────────────────────────────────────────────────────


def ocr_image(image_bytes: bytes) -> str:
    """识别图片文字，优先 RapidOCR，回退 WinRT。"""
    try:
        return _ocr_rapid(image_bytes)
    except ImportError:
        _log.info("RapidOCR 不可用，回退 WinRT OCR")
        return _ocr_winrt(image_bytes)
    except Exception as exc:
        _log.warning("RapidOCR 识别失败（%s），回退 WinRT OCR", exc)
        return _ocr_winrt(image_bytes)


# ── 银行卡解析 ────────────────────────────────────────────────────────────────

# 银行名称：直接从 OCR 文本中提取"...银行"整段中文名称（含具体支行/股份
# 有限公司前缀均会在到达"银行"二字时截断），无需穷举所有银行名称
_RE_BANK_CN = re.compile(r"([一-鿿]{2,12}银行)")

# 离线银行名称词典：用于对 OCR 提取结果做模糊纠错（如"建没银行"→"建设银行"）
_BANK_DB_PATH = Path(__file__).resolve().parent / "data" / "banks.json"


@lru_cache(maxsize=1)
def _bank_db() -> list[str]:
    try:
        return json.loads(_BANK_DB_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


def _correct_bank_name(name: str) -> str:
    """将 OCR 提取的银行名称与离线词典做模糊匹配纠错，无匹配则原样返回。"""
    matches = difflib.get_close_matches(name, _bank_db(), n=1, cutoff=0.6)
    return matches[0] if matches else name


# 仅印刷英文缩写的卡片（如外资卡）兜底映射到中文全称
_BANK_ABBR = {
    "ICBC": "中国工商银行",
    "CCB": "中国建设银行",
    "ABC": "中国农业银行",
    "BOCOM": "交通银行",
    "BOC": "中国银行",
    "CMB": "招商银行",
    "SPDB": "浦发银行",
    "CIB": "兴业银行",
    "CEB": "中国光大银行",
    "CGB": "广发银行",
    "PSBC": "中国邮政储蓄银行",
}

# 国际银行：匹配"...BANK"或"BANK OF ..."形式的英文机构名称（如
# STANDARD CHARTERED BANK / BANK OF AMERICA / DEUTSCHE BANK）
_RE_BANK_EN = re.compile(r"\b((?:[A-Z]{2,}\s+){0,4}BANK(?:\s+(?:OF\s+)?[A-Z]{2,}){0,3})\b")

# 不含独立"BANK"单词的知名国际银行品牌名，按更具体的名称优先匹配
_INTL_BANK_KEYWORDS = [
    "JPMORGAN CHASE",
    "BANK OF AMERICA",
    "WELLS FARGO",
    "STANDARD CHARTERED",
    "CREDIT SUISSE",
    "ROYAL BANK OF CANADA",
    "STATE BANK OF INDIA",
    "AMERICAN EXPRESS",
    "HSBC",
    "CITIBANK",
    "CITI",
    "CHASE",
    "BARCLAYS",
    "SANTANDER",
    "UBS",
    "RABOBANK",
    "SCOTIABANK",
    "NATWEST",
    "LLOYDS",
    "MAYBANK",
    "CIMB",
    "DBS",
    "OCBC",
    "UOB",
    "MIZUHO",
    "MUFG",
    "TD BANK",
    "BMO",
    "RBC",
    "ING",
]


def _find_intl_bank(text: str) -> str | None:
    """从 OCR 文本中提取国际银行英文名称，多次出现的优先，找不到返回 None。"""
    upper = text.upper()
    candidates: list[str] = [m.group(1) for m in _RE_BANK_EN.finditer(upper) if m.group(1) != "BANK"]
    for kw in _INTL_BANK_KEYWORDS:
        if re.search(rf"\b{re.escape(kw)}\b", upper):
            candidates.append(kw)
    if not candidates:
        return None
    counts = Counter(candidates)
    best_count = max(counts.values())
    candidate = next(c for c in candidates if counts[c] == best_count)
    return _correct_bank_name(candidate)


# 银行卡卡号常见位数 13-19（Amex 15、大多数 Visa/MC/银联 16、银联 17-19）
# 数字分组中允许常见 OCR 数字/字母混淆字符（O/I/L/S/B 等），随后统一纠错
_CARD_CHARS = r"[0-9OoIiLlSsBb]"
# 一段连续的卡号字符（2-19 位），后面可跟 0-4 段以空白/短横/换行分隔的同类字符
# 既覆盖 OCR 整段识别出的 15/16/19 位连续数字，也覆盖按任意位数分组、跨行的情况
_RE_CARD = re.compile(rf"\b({_CARD_CHARS}{{2,19}}(?:[\s\-]{_CARD_CHARS}{{2,19}}){{0,4}})\b")
_RE_EXPIRY = re.compile(r"\b(0?[1-9]|1[0-2])[/\-](\d{2}|\d{4})\b")
_RE_NAME_EN = re.compile(r"\b([A-Z][A-Z\s]{2,24})\b")
# 卡片背面签名栏的 7 位数字 = 卡号末4位 + 3位 CVV2
_RE_CVV_BLOCK = re.compile(rf"\b({_CARD_CHARS}{{7}})\b")
# 部分卡片背面直接标注 CVV/CVV2/安全码 + 3-4位数字（不与卡号末4位拼接）
_RE_CVV_LABEL = re.compile(rf"(?:CVV2?|安全码)\s*[:：]?\s*({_CARD_CHARS}{{3,4}})", re.IGNORECASE)
# 部分卡片背面没有任何标签，CVV 单独成行，仅3位数字
_RE_CVV_STANDALONE = re.compile(rf"^({_CARD_CHARS}{{3}})$")

# 银行/卡组织名称中常见词汇，含其中任一词的行不视为持卡人姓名
_CARD_SKIP = {
    "VISA",
    "MASTERCARD",
    "UNIONPAY",
    "AMEX",
    "DEBIT",
    "CREDIT",
    "BANK",
    "CARD",
    "CHINA",
    "CONSTRUCTION",
    "INDUSTRIAL",
    "COMMERCIAL",
    "COMMUNICATIONS",
    "AGRICULTURAL",
    "AGRICULTURE",
    "MERCHANTS",
    "MERCHANT",
    "EVERBRIGHT",
    "CITIC",
    "MINSHENG",
    "HUAXIA",
    "HUA",
    "XIA",
    "GUANGFA",
    "PUDONG",
    "DEVELOPMENT",
    "SHANGHAI",
    "POSTAL",
    "SAVINGS",
    "PING",
    "AN",
    "OF",
    "AND",
    "THE",
    "NATIONAL",
    "LIMITED",
    "LTD",
    "CO",
    "CORPORATION",
    "GROUP",
    "INTERNATIONAL",
    "ICBC",
    "CCB",
    "ABC",
    "BOC",
    "BOCOM",
    "CEB",
    "CMB",
    "CGB",
    "HSBC",
    "CITIBANK",
    "CITI",
    "CHASE",
    "JPMORGAN",
    "BARCLAYS",
    "SANTANDER",
    "UBS",
    "RABOBANK",
    "SCOTIABANK",
    "NATWEST",
    "LLOYDS",
    "MAYBANK",
    "CIMB",
    "DBS",
    "OCBC",
    "UOB",
    "MIZUHO",
    "MUFG",
    "BMO",
    "RBC",
    "ING",
    "WELLS",
    "FARGO",
    "AMERICA",
    "STANDARD",
    "CHARTERED",
    "DEUTSCHE",
    "PREMIER",
    "ELITE",
    "WORLD",
    "PLATINUM",
    "GOLD",
    "SIGNATURE",
    "INFINITE",
}

# OCR 常见数字混淆纠错（仅用于卡号区域）
_DIGIT_FIX = str.maketrans("OoIiLlSsBb", "0011115588")


def _clean_card_number(raw: str) -> str:
    digits = re.sub(r"[\s\-]", "", raw).translate(_DIGIT_FIX)
    return digits


def _looks_like_card_number(raw: str) -> bool:
    """要求长度落在常见银行卡卡号位数范围内，且至少一半字符本就是数字。"""
    digits = _clean_card_number(raw)
    if not (13 <= len(digits) <= 19):
        return False
    raw_chars = re.sub(r"[\s\-]", "", raw)
    digit_count = sum(c.isdigit() for c in raw_chars)
    return digit_count * 2 >= len(raw_chars)


def _luhn_valid(digits: str) -> bool:
    """Luhn 校验和，用于排除客服电话等被误拼接成卡号长度的数字串。"""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def parse_credit_card(text: str) -> dict:
    """从 OCR 文本中提取银行卡字段，返回非空字段字典。"""
    result: dict = {}
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    # 卡号：候选片段可能因 OCR 分行/分组被切成多段，逐一尝试相邻分段的
    # 各种连续组合。优先选择"完整覆盖整段匹配"的候选（即按 OCR 原始分组
    # 拼出的完整数字串，常见于19位银联卡的 4-4-4-4-3 分组，避免因部分
    # 子串恰好通过 Luhn 而被截断选中）；其余情况下优先选择通过 Luhn 校验
    # 的候选（客服电话等拼接数字串通常无法通过校验），同等情况下取位数最长的
    best = None
    best_luhn = False
    best_full = False
    for m in _RE_CARD.finditer(text):
        tokens = re.split(r"[\s\-]+", m.group(1))
        n = len(tokens)
        for i in range(n):
            for j in range(i + 1, n + 1):
                candidate = "".join(tokens[i:j])
                if not _looks_like_card_number(candidate):
                    continue
                full = i == 0 and j == n
                luhn = _luhn_valid(_clean_card_number(candidate))
                if best is None:
                    best, best_luhn, best_full = candidate, luhn, full
                elif full and not best_full:
                    best, best_luhn, best_full = candidate, luhn, full
                elif full == best_full:
                    if luhn and not best_luhn:
                        best, best_luhn, best_full = candidate, luhn, full
                    elif luhn == best_luhn and len(candidate) > len(best):
                        best, best_luhn, best_full = candidate, luhn, full
    if best:
        digits = _clean_card_number(best)
        result["card_number"] = digits
        result["card_number_last4"] = digits[-4:]

        # CVV：背面签名栏常打印"卡号末4位+3位CVV2"共7位数字，
        # 通过比对前4位与卡号末4位来确认并提取后3位
        for m in _RE_CVV_BLOCK.finditer(text):
            block = _clean_card_number(m.group(1))
            if block[:4] == result["card_number_last4"]:
                result["cvv"] = block[-3:]
                break

    # 部分卡片背面没有"卡号末4位+CVV"的7位拼接，而是直接标注
    # CVV/CVV2/安全码 后跟3-4位数字，独立提取（取后3位）
    if "cvv" not in result:
        m = _RE_CVV_LABEL.search(text)
        if m:
            result["cvv"] = _clean_card_number(m.group(1))[-3:]

    # 既无拼接块也无标签，CVV 单独成行（仅3位数字），直接取该行
    if "cvv" not in result:
        for line in lines:
            m = _RE_CVV_STANDALONE.match(line)
            if m:
                result["cvv"] = _clean_card_number(m.group(1))
                break

    m = _RE_EXPIRY.search(text)
    if m:
        month = m.group(1).zfill(2)
        year = m.group(2)[-2:]
        result["expiry"] = f"{month}/{year}"

    for line in lines:
        up = _RE_NAME_EN.search(line)
        if up:
            candidate = up.group(1).strip()
            words = candidate.split()
            if 2 <= len(words) <= 4 and not any(w in _CARD_SKIP for w in words):
                result["cardholder"] = candidate
                break

    bank_matches = _RE_BANK_CN.findall(text)
    if bank_matches:
        # 同一银行名称可能在卡片正反面多次出现，取出现次数最多的一个，
        # 避免选到只出现一次的无关机构名称（次数相同时取首次出现的）
        counts = Counter(bank_matches)
        best_count = max(counts.values())
        candidate = next(b for b in bank_matches if counts[b] == best_count)
        result["bank"] = _correct_bank_name(candidate)
    else:
        up = text.upper()
        for abbr, full in _BANK_ABBR.items():
            if re.search(rf"\b{abbr}\b", up):
                result["bank"] = full
                break
        else:
            intl = _find_intl_bank(text)
            if intl:
                result["bank"] = intl

    return result


# ── 证件解析 ──────────────────────────────────────────────────────────────────

_RE_ID_CN = re.compile(
    r"\b([1-9]\d{5}"
    r"(?:18|19|20)\d{2}"
    r"(?:0[1-9]|1[0-2])"
    r"(?:0[1-9]|[12]\d|3[01])"
    r"\d{3}[\dXx])\b"
)
_RE_PASSPORT_CN = re.compile(r"\b([GEDged]\d{8})\b")
# 8 位数字日期（如 19900101）需独立出现，避免匹配身份证号等更长数字串中的子串
_RE_DATE = re.compile(
    r"(\d{4})[.年\-/](\d{1,2})[.月\-/](\d{1,2})日?"
    r"|(?<!\d)(\d{8})(?!\d)"
)
_RE_HAN = re.compile(r"[一-鿿]")
_LABEL_WORDS = {"姓名", "性别", "民族", "出生", "住址", "签发", "有效", "公民", "身份"}
# 证件背面常见的国徽页固定文字，避免被误判为姓名
_NAME_BLOCKLIST = {
    "中华人民",
    "人民共和",
    "共和国",
    "共和国居",
    "民共和国",
    "居民身份",
    "身份证",
    "中华人民共和国",
}


def _fmt_date(m: re.Match) -> str:
    if m.group(4):
        s = m.group(4)
        return f"{s[:4]}-{s[4:6]}-{s[6:]}"
    return f"{m.group(1)}-{m.group(2).zfill(2)}-{m.group(3).zfill(2)}"


def parse_id_card(text: str) -> dict:
    """从 OCR 文本中提取证件字段，返回非空字段字典。"""
    result: dict = {}
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    m = _RE_ID_CN.search(text)
    if m:
        num = m.group(1).upper()
        result["id_number"] = num
        result["id_type"] = "身份证"
        result["birth_date"] = f"{num[6:10]}-{num[10:12]}-{num[12:14]}"
        result["gender"] = "男" if int(num[16]) % 2 else "女"
    else:
        m = _RE_PASSPORT_CN.search(text)
        if m:
            result["id_number"] = m.group(1).upper()
            result["id_type"] = "护照"

    # 姓名（"姓名" 标签后，或独立 2-4 汉字行——仅在已识别到证件号/护照号的
    # 正面图像上尝试此回退，避免在背面（国徽页）将固定文字误判为姓名）
    name_m = re.search(r"姓\s*名\s*[:：]?\s*([一-鿿]{2,6})", text)
    if name_m:
        result["full_name"] = name_m.group(1)
    elif result.get("id_type"):
        for line in lines:
            chars = _RE_HAN.findall(line)
            if 2 <= len(chars) <= 4 and line not in _LABEL_WORDS and "族" not in line and "".join(chars) not in _NAME_BLOCKLIST:
                result["full_name"] = "".join(chars)
                break

    eth_m = re.search(r"民\s*族\s*[:：]?\s*([一-鿿]{1,4})", text)
    if eth_m:
        result["ethnicity"] = eth_m.group(1)

    # 住址（"住址" / "地址" 后续内容，可能跨行）
    addr_m = re.search(r"(?:住址|地址)\s*[:：]?\s*(.+)", text)
    if addr_m:
        result["address"] = addr_m.group(1).strip()

    # 签发机关（去除"签发机关"标签本身，仅保留机关名称）
    for line in lines:
        if any(kw in line for kw in ("公安局", "派出所", "公安分局")):
            result["issuing_authority"] = re.sub(r"^签发机关\s*[:：]?\s*", "", line)
            break
    if not result.get("issuing_authority"):
        auth_m = re.search(r"签发机关\s*[:：]?\s*(.+)", text)
        if auth_m:
            result["issuing_authority"] = auth_m.group(1).strip()

    date_section = re.search(r"有效期限?\s*[:：]?\s*(.+)", text)
    if date_section:
        span = date_section.group(1)
    elif result.get("id_type") == "身份证":
        # 身份证正面没有签发/有效期信息，避免把出生日期误判为签发日期
        span = ""
    else:
        span = text
    dates = [_fmt_date(m) for m in _RE_DATE.finditer(span)]
    if len(dates) >= 2:
        result["issue_date"], result["expiry_date"] = dates[0], dates[1]
    elif len(dates) == 1:
        result["issue_date"] = dates[0]

    return result
