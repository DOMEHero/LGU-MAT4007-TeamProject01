import argparse

from aes.aes import AES


def demo_encoding(aes: AES, text: str, label: str, encoding: str | None = None):
    encrypted = aes.encrypt_text(text, encoding=encoding)
    decrypted = aes.decrypt_text(encrypted, encoding=encoding)
    print(f"[{label}]")
    print("Plaintext:", text)
    print("Cipher(hex):", encrypted.hex())
    print("Decrypted:", decrypted)
    print("Roundtrip OK:", decrypted == text)
    print()


def run_demo(key: list[int]):
    print("Running AES multi-encoding demo...")

    aes_utf8 = AES(key, text_encoding="utf-8")
    demo_encoding(aes_utf8, "Hello，世界", "Default utf-8")

    aes_gbk = AES(key, text_encoding="gbk", text_errors="strict")
    demo_encoding(aes_gbk, "你好，AES测试", "Default gbk")

    aes_utf16 = AES(key, text_encoding="utf-16-le")
    demo_encoding(aes_utf16, "多编码加解密", "Default utf-16-le")

    aes_override = AES(key, text_encoding="utf-8")
    demo_encoding(aes_override, "你好，按次指定gbk", "Per-call override gbk", encoding="gbk")

    raw = b"Hello, AES!12345"
    encrypted_block = aes_utf8.encrypt_block(raw)
    decrypted_block = aes_utf8.decrypt_block(encrypted_block)
    print("[Single block API]")
    print("Block roundtrip OK:", decrypted_block == raw)


def run_cli_once(key: list[int], text: str, encoding: str, errors: str):
    aes = AES(key, text_encoding=encoding, text_errors=errors)
    encrypted = aes.encrypt_text(text)
    decrypted = aes.decrypt_text(encrypted)
    print("[CLI mode]")
    print("Encoding:", encoding)
    print("Plaintext:", text)
    print("Cipher(hex):", encrypted.hex())
    print("Decrypted:", decrypted)
    print("Roundtrip OK:", decrypted == text)


def parse_args():
    parser = argparse.ArgumentParser(description="AES 多编码加解密演示")
    parser.add_argument("--text", type=str, help="待加密文本；提供后进入单次CLI模式")
    parser.add_argument("--encoding", type=str, default="utf-8", help="文本编码，默认 utf-8")
    parser.add_argument("--errors", type=str, default="strict", help="编码错误处理策略，默认 strict")
    return parser.parse_args()


def main():
    key = [0x24, 0x75, 0xa2, 0xb3, 0x34, 0x75, 0x56, 0x88, 0x31, 0xe2, 0x12, 0x00, 0x13, 0xaa, 0x54, 0x87]
    args = parse_args()
    if args.text is not None:
        run_cli_once(key, args.text, args.encoding, args.errors)
    else:
        run_demo(key)


if __name__ == "__main__":
    main()