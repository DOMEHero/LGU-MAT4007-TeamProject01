"""Pydantic schemas for API requests/responses."""

from pydantic import BaseModel, Field


class EncryptRequest(BaseModel):
    plaintext: str = Field(..., description="Text to encrypt")
    key_hex: str = Field(..., description="AES key in hex (16/24/32 bytes)")
    iv_hex: str | None = Field(None, description="Optional 16-byte IV in hex")
    encoding: str = Field("utf-8", description="Text encoding")
    errors: str = Field("strict", description="Encoding/decoding error strategy")


class EncryptResponse(BaseModel):
    iv_hex: str
    ciphertext_hex: str
    tag_hex: str


class DecryptRequest(BaseModel):
    ciphertext_hex: str = Field(..., description="Ciphertext in hex")
    key_hex: str = Field(..., description="AES key in hex (16/24/32 bytes)")
    iv_hex: str = Field(..., description="16-byte IV in hex")
    tag_hex: str = Field(..., description="HMAC-SHA256 tag in hex")
    encoding: str = Field("utf-8", description="Text encoding")
    errors: str = Field("strict", description="Encoding/decoding error strategy")


class DecryptResponse(BaseModel):
    plaintext: str


class HealthResponse(BaseModel):
    status: str
