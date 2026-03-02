"""HMAC-SHA256 helpers."""

import hmac
import hashlib


def compute_hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac_sha256(key: bytes, data: bytes, expected_tag: bytes) -> bool:
    actual = compute_hmac_sha256(key, data)
    return hmac.compare_digest(actual, expected_tag)
