# aes-cbc-project

A small AES-CBC encryption implementation with a from-scratch AES core, PKCS#7 padding, HMAC-SHA256 authentication, FastAPI backend, and a web UI for text and file workflows.

## Quick Start

```bash
uv sync --group dev
uv run pytest
uv run uvicorn aescbc.main:app --reload --app-dir src
```

Open `http://127.0.0.1:8000`.

## API Endpoints

- `GET /api/health`
- `POST /api/encrypt` (JSON text encrypt)
- `POST /api/decrypt` (JSON text decrypt)
- `POST /api/file/encrypt` (multipart file upload -> encrypted file download)
- `POST /api/file/decrypt` (multipart encrypted file upload -> decrypted file download)

## File Encryption Notes

- Any file type is supported (text, image, audio, video, PDF, binary blobs).
- Encrypted files are wrapped in a project container format (downloaded as `.enc`) that stores:
  - metadata (filename, MIME type, text detection info)
  - IV
  - HMAC-SHA256 tag
  - ciphertext
- Text-like file encoding is auto-detected from raw bytes (best effort). Binary files are treated as raw bytes and preserved exactly.

## Security Note

This repository is for coursework and demonstration. Do not use this implementation as-is for production cryptographic workloads.

## Tip

For AES key generation, we recommend: [randomkeygen](https://randomkeygen.com/aes-key)
