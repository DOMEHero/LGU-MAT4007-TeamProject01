"""HTTP routes for text and file encryption/decryption."""

from __future__ import annotations

import json

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response

from aescbc.api.schemas import (
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    HealthResponse,
)
from aescbc.crypto.utils import hex_to_bytes, safe_download_filename, validate_aes_key
from aescbc.services.file_service import (
    FileMetadataDict,
    decrypt_file_bytes,
    decrypt_text,
    encrypt_file_bytes,
    encrypt_text,
)

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.post("/encrypt", response_model=EncryptResponse)
def encrypt(req: EncryptRequest) -> EncryptResponse:
    try:
        key = hex_to_bytes(req.key_hex, "key_hex")
        validate_aes_key(key)
        iv = None if req.iv_hex is None else hex_to_bytes(req.iv_hex, "iv_hex")

        result = encrypt_text(
            plaintext=req.plaintext,
            key=key,
            iv=iv,
            encoding=req.encoding,
            errors=req.errors,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return EncryptResponse(
        iv_hex=result["iv"].hex(),
        ciphertext_hex=result["ciphertext"].hex(),
        tag_hex=result["tag"].hex(),
    )


@router.post("/decrypt", response_model=DecryptResponse)
def decrypt(req: DecryptRequest) -> DecryptResponse:
    try:
        key = hex_to_bytes(req.key_hex, "key_hex")
        validate_aes_key(key)
        ciphertext = hex_to_bytes(req.ciphertext_hex, "ciphertext_hex")
        iv = hex_to_bytes(req.iv_hex, "iv_hex")
        tag = hex_to_bytes(req.tag_hex, "tag_hex")

        plaintext = decrypt_text(
            ciphertext=ciphertext,
            key=key,
            iv=iv,
            tag=tag,
            encoding=req.encoding,
            errors=req.errors,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return DecryptResponse(plaintext=plaintext)


@router.post("/file/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    key_hex: str = Form(...),
    iv_hex: str | None = Form(None),
) -> Response:
    try:
        key = hex_to_bytes(key_hex, "key_hex")
        validate_aes_key(key)
        iv = None if not iv_hex else hex_to_bytes(iv_hex, "iv_hex")

        content = await file.read()
        result = encrypt_file_bytes(
            content=content,
            key=key,
            filename=file.filename,
            content_type=file.content_type,
            iv=iv,
        )

        metadata: FileMetadataDict = result["metadata"]
        source_name = file.filename or "encrypted"
        output_name = safe_download_filename(f"{source_name}.enc", "encrypted.enc")
        headers = {
            "Content-Disposition": f'attachment; filename="{output_name}"',
            "X-AESCBC-Metadata": json.dumps(metadata, separators=(",", ":")),
        }

        return Response(
            content=result["encrypted_file"],
            media_type="application/octet-stream",
            headers=headers,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/file/decrypt")
async def decrypt_file(file: UploadFile = File(...), key_hex: str = Form(...)) -> Response:
    try:
        key = hex_to_bytes(key_hex, "key_hex")
        validate_aes_key(key)

        encrypted_blob = await file.read()
        result = decrypt_file_bytes(encrypted_blob=encrypted_blob, key=key)

        metadata: FileMetadataDict = result["metadata"]
        raw_name = metadata.get("filename")
        if not isinstance(raw_name, str) or not raw_name:
            raw_name = file.filename.removesuffix(".enc") if file.filename else "decrypted.bin"

        output_name = safe_download_filename(raw_name, "decrypted.bin")
        content_type_value = metadata.get("content_type")
        content_type = content_type_value if isinstance(content_type_value, str) else None

        headers = {
            "Content-Disposition": f'attachment; filename="{output_name}"',
            "X-AESCBC-Metadata": json.dumps(metadata, separators=(",", ":")),
        }

        return Response(
            content=result["plaintext"],
            media_type=content_type or "application/octet-stream",
            headers=headers,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
