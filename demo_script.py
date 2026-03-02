"""Small end-to-end demo for AES-CBC + PKCS#7 + HMAC."""

from aescbc.services.file_service import decrypt_payload, encrypt_payload


def main() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    plaintext = "Hello AES-CBC project. 你好，世界。".encode("utf-8")

    payload = encrypt_payload(plaintext, key)
    restored = decrypt_payload(
        ciphertext=payload["ciphertext"],
        key=key,
        iv=payload["iv"],
        tag=payload["tag"],
    )

    print("Plaintext:", plaintext.decode("utf-8"))
    print("Ciphertext(hex):", payload["ciphertext"].hex())
    print("IV(hex):", payload["iv"].hex())
    print("HMAC(hex):", payload["tag"].hex())
    print("Roundtrip OK:", restored == plaintext)


if __name__ == "__main__":
    main()
