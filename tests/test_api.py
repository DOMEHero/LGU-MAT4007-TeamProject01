from fastapi.testclient import TestClient

from aescbc.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_encrypt_then_decrypt_roundtrip():
    key_hex = "00112233445566778899aabbccddeeff"

    encrypt_response = client.post(
        "/api/encrypt",
        json={
            "plaintext": "Hello API",
            "key_hex": key_hex,
            "encoding": "utf-8",
        },
    )
    assert encrypt_response.status_code == 200
    enc_data = encrypt_response.json()

    decrypt_response = client.post(
        "/api/decrypt",
        json={
            "ciphertext_hex": enc_data["ciphertext_hex"],
            "key_hex": key_hex,
            "iv_hex": enc_data["iv_hex"],
            "tag_hex": enc_data["tag_hex"],
            "encoding": "utf-8",
        },
    )
    assert decrypt_response.status_code == 200
    assert decrypt_response.json()["plaintext"] == "Hello API"


def test_decrypt_rejects_tampered_tag():
    key_hex = "00112233445566778899aabbccddeeff"

    encrypt_response = client.post(
        "/api/encrypt",
        json={
            "plaintext": "Integrity check",
            "key_hex": key_hex,
        },
    )
    data = encrypt_response.json()

    bad_tag = "00" + data["tag_hex"][2:]

    decrypt_response = client.post(
        "/api/decrypt",
        json={
            "ciphertext_hex": data["ciphertext_hex"],
            "key_hex": key_hex,
            "iv_hex": data["iv_hex"],
            "tag_hex": bad_tag,
        },
    )

    assert decrypt_response.status_code == 400
    assert "Authentication failed" in decrypt_response.json()["detail"]


def test_file_encrypt_then_decrypt_roundtrip():
    key_hex = "00112233445566778899aabbccddeeff"
    original = b"\x00\x01\x02binary\x00payload\xFF"

    encrypt_response = client.post(
        "/api/file/encrypt",
        data={"key_hex": key_hex},
        files={"file": ("clip.bin", original, "application/octet-stream")},
    )

    assert encrypt_response.status_code == 200
    assert encrypt_response.headers.get("content-disposition", "").endswith('clip.bin.enc"')
    encrypted_blob = encrypt_response.content

    decrypt_response = client.post(
        "/api/file/decrypt",
        data={"key_hex": key_hex},
        files={"file": ("clip.bin.enc", encrypted_blob, "application/octet-stream")},
    )

    assert decrypt_response.status_code == 200
    assert decrypt_response.content == original
    assert decrypt_response.headers.get("content-disposition", "").endswith('clip.bin"')


def test_file_decrypt_rejects_tampered_blob():
    key_hex = "00112233445566778899aabbccddeeff"

    encrypt_response = client.post(
        "/api/file/encrypt",
        data={"key_hex": key_hex},
        files={"file": ("note.txt", b"hello file api", "text/plain")},
    )
    assert encrypt_response.status_code == 200

    tampered = bytearray(encrypt_response.content)
    tampered[-1] ^= 0x01

    decrypt_response = client.post(
        "/api/file/decrypt",
        data={"key_hex": key_hex},
        files={"file": ("note.txt.enc", bytes(tampered), "application/octet-stream")},
    )

    assert decrypt_response.status_code == 400
    assert "Authentication failed" in decrypt_response.json()["detail"]
