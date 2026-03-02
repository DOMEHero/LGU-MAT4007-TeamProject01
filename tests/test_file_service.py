from aescbc.services.file_service import decrypt_file_bytes, encrypt_file_bytes


def test_file_roundtrip_binary_content():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    content = bytes(range(256)) + b"\x00\x01\x02\x03"

    encrypted = encrypt_file_bytes(
        content=content,
        key=key,
        filename="sample.bin",
        content_type="application/octet-stream",
    )

    metadata = encrypted["metadata"]
    assert metadata["filename"] == "sample.bin"
    assert metadata["content_type"] == "application/octet-stream"
    assert metadata["is_text"] is False

    decrypted = decrypt_file_bytes(encrypted["encrypted_file"], key)
    assert decrypted["plaintext"] == content
    assert decrypted["metadata"]["original_size"] == len(content)


def test_file_roundtrip_text_with_encoding_detection():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    content = "你好，AES-CBC file pipeline".encode("utf-8")

    encrypted = encrypt_file_bytes(
        content=content,
        key=key,
        filename="sample.txt",
        content_type="text/plain",
    )

    metadata = encrypted["metadata"]
    assert metadata["filename"] == "sample.txt"
    assert metadata["is_text"] is True
    assert metadata["detected_encoding"] is not None

    decrypted = decrypt_file_bytes(encrypted["encrypted_file"], key)
    assert decrypted["plaintext"] == content


def test_file_decrypt_rejects_tampered_blob():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    content = b"sensitive payload"

    encrypted = encrypt_file_bytes(content=content, key=key)
    tampered = bytearray(encrypted["encrypted_file"])
    tampered[-1] ^= 0x01

    try:
        decrypt_file_bytes(bytes(tampered), key)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "Authentication failed" in str(exc)
