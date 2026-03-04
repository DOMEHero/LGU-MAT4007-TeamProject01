# Development Manual

This guide is for collaborators who need to understand the codebase and make changes safely.

## Local Setup

Install the app plus development dependencies:

```bash
uv sync --group dev
```

## Daily Commands

Run the FastAPI app with autoreload:

```bash
uv run uvicorn aescbc.main:app --reload --app-dir src
```

Run the test suite:

```bash
uv run pytest
```

Open `http://127.0.0.1:8000` while the app is running.

## Project Layout

- `src/aescbc/main.py`: FastAPI entrypoint, root HTML route, static file mount, and template setup.
- `src/aescbc/api/routes.py`: HTTP endpoints and request handling.
- `src/aescbc/api/schemas.py`: Pydantic request and response models.
- `src/aescbc/services/text_service.py`: orchestration layer that composes padding, AES-CBC, and HMAC.
- `src/aescbc/crypto/`: cryptographic implementation details.
- `src/aescbc/web/templates/index.html`: server-rendered page shell.
- `src/aescbc/web/static/js/app.js`: browser-side API calls and UI logic.
- `src/aescbc/web/static/css/styles.css`: frontend styling.
- `tests/`: regression coverage for AES, CBC, padding, and API behavior.

## Request Flow

1. The browser UI in `src/aescbc/web/templates/index.html` and `src/aescbc/web/static/js/app.js` calls the API.
2. `src/aescbc/main.py` serves the page and mounts the `/static` assets.
3. `src/aescbc/api/routes.py` validates inputs, decodes hex fields, and maps domain errors to HTTP 400 responses.
4. `src/aescbc/services/text_service.py` runs the encryption or decryption pipeline.
5. The crypto modules under `src/aescbc/crypto/` perform the actual block cipher, mode, padding, and authentication work.

## Crypto Pipeline

1. AES core (`src/aescbc/crypto/aes/`) encrypts and decrypts 16-byte blocks.
2. CBC mode (`src/aescbc/crypto/modes/cbc.py`) chains blocks with the IV.
3. PKCS#7 (`src/aescbc/crypto/padding/pkcs7.py`) handles variable-length plaintext.
4. HMAC-SHA256 (`src/aescbc/crypto/auth/hmac_sha256.py`) authenticates `iv || ciphertext`.
5. The service layer in `src/aescbc/services/text_service.py` ties those pieces together for text payloads.

## API Endpoints

- `GET /api/health`: simple health check.
- `POST /api/encrypt`: accepts plaintext plus a hex AES key and returns `iv_hex`, `ciphertext_hex`, and `tag_hex`.
- `POST /api/decrypt`: accepts `ciphertext_hex`, `key_hex`, `iv_hex`, and `tag_hex`, then returns plaintext.

The request and response shapes live in `src/aescbc/api/schemas.py`. If you change endpoint contracts, update the schemas, routes, frontend JS, and API tests together.

## Security Decisions

- AES and HMAC do not share the same key material. The auth key is derived separately in `src/aescbc/crypto/utils.py`.
- HMAC is verified before decryption in `src/aescbc/services/text_service.py` so unauthenticated ciphertext is rejected early.
- Invalid AES key sizes, IV sizes, ciphertext structure, and tag lengths fail fast with `ValueError`, which the API turns into HTTP 400 responses.

## Where To Make Changes

- Crypto algorithm changes: start in `src/aescbc/crypto/` and keep or extend the vector-based tests in `tests/test_aes_core.py` and `tests/test_cbc_mode.py`.
- API behavior changes: update `src/aescbc/api/routes.py`, `src/aescbc/api/schemas.py`, and `tests/test_api.py`.
- Text encryption workflow changes: update `src/aescbc/services/text_service.py` and add service- or API-level regression coverage.
- Frontend changes: update `src/aescbc/web/templates/index.html`, `src/aescbc/web/static/js/app.js`, and `src/aescbc/web/static/css/styles.css`.

## Testing Expectations

- Run `uv run pytest` before handing off changes.
- Add or update tests when changing crypto behavior, endpoint contracts, or error handling.
- The existing suite covers AES known-answer vectors, CBC behavior, padding rules, and API roundtrips with tamper detection.
