"""Cipher Block Chaining mode implementation."""

from aescbc.crypto.aes.aes_core import AESCore


BLOCK_SIZE = 16


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Byte strings must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


class CBCMode:
    def __init__(self, cipher: AESCore, iv: bytes):
        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV must be 16 bytes")
        self.cipher = cipher
        self.iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) == 0 or len(plaintext) % BLOCK_SIZE != 0:
            raise ValueError("CBC encrypt requires non-empty data in 16-byte blocks")

        previous = self.iv
        out = bytearray()

        for offset in range(0, len(plaintext), BLOCK_SIZE):
            block = plaintext[offset : offset + BLOCK_SIZE]
            mixed = _xor_bytes(block, previous)
            encrypted = self.cipher.encrypt_block(mixed)
            out.extend(encrypted)
            previous = encrypted

        return bytes(out)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError("CBC decrypt requires non-empty data in 16-byte blocks")

        previous = self.iv
        out = bytearray()

        for offset in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[offset : offset + BLOCK_SIZE]
            decrypted = self.cipher.decrypt_block(block)
            plain_block = _xor_bytes(decrypted, previous)
            out.extend(plain_block)
            previous = block

        return bytes(out)
