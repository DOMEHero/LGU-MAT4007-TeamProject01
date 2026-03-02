"""Utility helpers for key handling, randomness, and encoding detection."""

from __future__ import annotations

import codecs
import hashlib
import secrets
from pathlib import Path
from typing import TypedDict

try:
    from charset_normalizer import from_bytes as charset_from_bytes
except ImportError:  # pragma: no cover - optional dependency fallback
    charset_from_bytes = None


VALID_AES_KEY_LENGTHS = {16, 24, 32}


class EncodingDetectionResult(TypedDict):
    is_text: bool
    detected_encoding: str | None
    encoding_confidence: float


def validate_aes_key(key: bytes) -> None:
    if len(key) not in VALID_AES_KEY_LENGTHS:
        raise ValueError("AES key must be 16, 24, or 32 bytes")


def derive_auth_key(aes_key: bytes) -> bytes:
    validate_aes_key(aes_key)
    return hashlib.sha256(b"aescbc-auth:" + aes_key).digest()


def random_iv() -> bytes:
    return secrets.token_bytes(16)


def hex_to_bytes(value: str, field_name: str) -> bytes:
    try:
        parsed = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid hex") from exc
    return parsed


def safe_download_filename(name: str | None, fallback: str = "download.bin") -> str:
    if not name:
        return fallback

    candidate = Path(name).name.strip()
    for token in ('"', ";", "\r", "\n"):
        candidate = candidate.replace(token, "")
    if not candidate:
        return fallback

    return candidate


def detect_text_encoding(data: bytes) -> EncodingDetectionResult:
    """Best-effort text encoding detection for byte payloads.

    Returns a dictionary with:
      - is_text: bool
      - detected_encoding: str | None
      - encoding_confidence: float (0.0 .. 1.0)
    """

    if not data:
        return {
            "is_text": True,
            "detected_encoding": "utf-8",
            "encoding_confidence": 1.0,
        }

    bom_map = (
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
    )

    for bom, encoding in bom_map:
        if data.startswith(bom):
            return {
                "is_text": True,
                "detected_encoding": encoding,
                "encoding_confidence": 1.0,
            }

    # NUL bytes are a strong signal for binary payloads.
    likely_binary = b"\x00" in data[:4096]

    try:
        data.decode("utf-8")
        return {
            "is_text": not likely_binary,
            "detected_encoding": "utf-8",
            "encoding_confidence": 0.99 if not likely_binary else 0.3,
        }
    except UnicodeDecodeError:
        pass

    if charset_from_bytes is not None:
        best = charset_from_bytes(data).best()
        if best is not None and best.encoding:
            coherence = float(getattr(best, "coherence", 0.0) or 0.0)
            encoding = best.encoding.lower()
            is_text = (not likely_binary) and coherence >= 0.2
            return {
                "is_text": is_text,
                "detected_encoding": encoding if is_text else None,
                "encoding_confidence": max(0.0, min(1.0, coherence)),
            }

    return {
        "is_text": False,
        "detected_encoding": None,
        "encoding_confidence": 0.0,
    }
