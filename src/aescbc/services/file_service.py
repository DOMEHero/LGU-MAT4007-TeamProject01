"""Service layer for text + file encryption with AES-CBC and HMAC."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping, TypedDict

from aescbc.crypto.aes import AESCore
from aescbc.crypto.auth.hmac_sha256 import compute_hmac_sha256, verify_hmac_sha256
from aescbc.crypto.modes.cbc import CBCMode
from aescbc.crypto.padding.pkcs7 import pkcs7_pad, pkcs7_unpad
from aescbc.crypto.utils import (
    derive_auth_key,
    detect_text_encoding,
    random_iv,
    validate_aes_key,
)


FILE_MAGIC = b"AESCBCF1"
METADATA_VERSION = 1


class FileMetadataDict(TypedDict):
    version: int
    filename: str | None
    content_type: str | None
    original_size: int
    is_text: bool
    detected_encoding: str | None
    encoding_confidence: float


class EncryptedFileBytesResult(TypedDict):
    encrypted_file: bytes
    metadata: FileMetadataDict


class DecryptedFileBytesResult(TypedDict):
    plaintext: bytes
    metadata: FileMetadataDict


@dataclass(frozen=True)
class FileMetadata:
    version: int
    filename: str | None
    content_type: str | None
    original_size: int
    is_text: bool
    detected_encoding: str | None
    encoding_confidence: float

    def to_dict(self) -> FileMetadataDict:
        return {
            "version": self.version,
            "filename": self.filename,
            "content_type": self.content_type,
            "original_size": self.original_size,
            "is_text": self.is_text,
            "detected_encoding": self.detected_encoding,
            "encoding_confidence": self.encoding_confidence,
        }

    @staticmethod
    def from_dict(data: Mapping[str, object]) -> "FileMetadata":
        version_raw = data.get("version", METADATA_VERSION)
        filename_raw = data.get("filename")
        content_type_raw = data.get("content_type")
        original_size_raw = data.get("original_size", 0)
        is_text_raw = data.get("is_text", False)
        detected_encoding_raw = data.get("detected_encoding")
        encoding_confidence_raw = data.get("encoding_confidence", 0.0)

        version = (
            int(version_raw)
            if isinstance(version_raw, (int, float, str, bytes, bytearray))
            else METADATA_VERSION
        )
        original_size = (
            int(original_size_raw)
            if isinstance(original_size_raw, (int, float, str, bytes, bytearray))
            else 0
        )
        encoding_confidence = (
            float(encoding_confidence_raw)
            if isinstance(encoding_confidence_raw, (int, float, str, bytes, bytearray))
            else 0.0
        )

        return FileMetadata(
            version=version,
            filename=filename_raw if isinstance(filename_raw, str) else None,
            content_type=content_type_raw if isinstance(content_type_raw, str) else None,
            original_size=original_size,
            is_text=bool(is_text_raw),
            detected_encoding=detected_encoding_raw if isinstance(detected_encoding_raw, str) else None,
            encoding_confidence=encoding_confidence,
        )


def encrypt_payload(plaintext: bytes, key: bytes, iv: bytes | None = None) -> dict[str, bytes]:
    validate_aes_key(key)

    use_iv = iv if iv is not None else random_iv()
    if len(use_iv) != 16:
        raise ValueError("IV must be 16 bytes")

    padded = pkcs7_pad(plaintext, block_size=16)
    cipher = AESCore(key)
    cbc = CBCMode(cipher, use_iv)
    ciphertext = cbc.encrypt(padded)

    auth_key = derive_auth_key(key)
    tag = compute_hmac_sha256(auth_key, use_iv + ciphertext)

    return {
        "iv": use_iv,
        "ciphertext": ciphertext,
        "tag": tag,
    }


def decrypt_payload(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    validate_aes_key(key)

    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if len(tag) != 32:
        raise ValueError("HMAC-SHA256 tag must be 32 bytes")

    auth_key = derive_auth_key(key)
    if not verify_hmac_sha256(auth_key, iv + ciphertext, tag):
        raise ValueError("Authentication failed: invalid HMAC")

    cipher = AESCore(key)
    cbc = CBCMode(cipher, iv)
    padded = cbc.decrypt(ciphertext)
    return pkcs7_unpad(padded, block_size=16)


def encrypt_text(
    plaintext: str,
    key: bytes,
    iv: bytes | None = None,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> dict[str, bytes]:
    return encrypt_payload(plaintext.encode(encoding, errors=errors), key, iv=iv)


def decrypt_text(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    tag: bytes,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> str:
    raw = decrypt_payload(ciphertext, key, iv, tag)
    return raw.decode(encoding, errors=errors)


def _pack_encrypted_file(
    ciphertext: bytes,
    iv: bytes,
    tag: bytes,
    metadata: FileMetadata,
) -> bytes:
    metadata_json = json.dumps(
        metadata.to_dict(),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(metadata_json) > 0xFFFFFFFF:
        raise ValueError("Metadata too large to pack")

    return FILE_MAGIC + len(metadata_json).to_bytes(4, "big") + metadata_json + iv + tag + ciphertext


def _unpack_encrypted_file(blob: bytes) -> tuple[FileMetadata, bytes, bytes, bytes]:
    if len(blob) < len(FILE_MAGIC) + 4 + 16 + 32 + 16:
        raise ValueError("Encrypted file blob is too short")

    if blob[: len(FILE_MAGIC)] != FILE_MAGIC:
        raise ValueError("Unsupported encrypted file format")

    offset = len(FILE_MAGIC)
    metadata_size = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4

    minimum_payload_size = metadata_size + 16 + 32 + 16
    if len(blob) < len(FILE_MAGIC) + 4 + minimum_payload_size:
        raise ValueError("Encrypted file blob is malformed")

    metadata_raw = blob[offset : offset + metadata_size]
    offset += metadata_size

    try:
        metadata_obj = json.loads(metadata_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Encrypted file metadata is invalid") from exc

    if not isinstance(metadata_obj, dict):
        raise ValueError("Encrypted file metadata must be a JSON object")

    metadata = FileMetadata.from_dict(metadata_obj)

    iv = blob[offset : offset + 16]
    offset += 16

    tag = blob[offset : offset + 32]
    offset += 32

    ciphertext = blob[offset:]
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Encrypted file ciphertext must be a non-empty multiple of 16 bytes")

    return metadata, iv, tag, ciphertext


def encrypt_file_bytes(
    content: bytes,
    key: bytes,
    filename: str | None = None,
    content_type: str | None = None,
    iv: bytes | None = None,
) -> EncryptedFileBytesResult:
    detection = detect_text_encoding(content)
    metadata = FileMetadata(
        version=METADATA_VERSION,
        filename=filename,
        content_type=content_type,
        original_size=len(content),
        is_text=bool(detection["is_text"]),
        detected_encoding=(
            str(detection["detected_encoding"])
            if detection["detected_encoding"] is not None
            else None
        ),
        encoding_confidence=float(detection["encoding_confidence"]),
    )

    payload = encrypt_payload(content, key=key, iv=iv)
    encrypted_blob = _pack_encrypted_file(
        ciphertext=payload["ciphertext"],
        iv=payload["iv"],
        tag=payload["tag"],
        metadata=metadata,
    )

    return {
        "encrypted_file": encrypted_blob,
        "metadata": metadata.to_dict(),
    }


def decrypt_file_bytes(encrypted_blob: bytes, key: bytes) -> DecryptedFileBytesResult:
    metadata, iv, tag, ciphertext = _unpack_encrypted_file(encrypted_blob)
    plaintext = decrypt_payload(ciphertext=ciphertext, key=key, iv=iv, tag=tag)

    if metadata.original_size != len(plaintext):
        raise ValueError("Decrypted size does not match metadata")

    return {
        "plaintext": plaintext,
        "metadata": metadata.to_dict(),
    }
