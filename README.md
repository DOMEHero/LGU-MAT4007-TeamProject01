# aes-cbc-project

A small AES-CBC encryption implementation with a from-scratch AES core, PKCS#7 padding, HMAC-SHA256 authentication, FastAPI backend, and a web UI for text workflows.

## Quick Start

```bash
uv sync
uv run uvicorn aescbc.main:app --app-dir src
```

Open `http://127.0.0.1:8000`.

For development setup, architecture notes, API details, and change workflow, see [docs/dev-manual.md](docs/dev-manual.md).

## Security Note

This repository is for coursework and demonstration. Do not use this implementation as-is for production cryptographic workloads.

## Tip

For AES key generation, we recommend: [randomkeygen](https://randomkeygen.com/aes-key)
