from aes.block import Block
from aes.keyexpansion import KeyExpansion


class AES:
    def __init__(self, key, text_encoding: str = "utf-8", text_errors: str = "strict"):
        self.text_encoding = text_encoding
        self.text_errors = text_errors
        self.key = self._normalize_key(key, text_encoding, text_errors)
        self.Nk = len(self.key) // 4  # 密钥长度（以字为单位）
        self.Nr = self.Nk + 6         # 轮数
        self.expanded_key = KeyExpansion(list(self.key))

    # turn expanded_key into Block format for easier AddRoundKey operations
        self.expanded_key_blocks = [Block(bytes(byte for _ in self.expanded_key[i:i+4] for byte in _)) for i in range(0, len(self.expanded_key), 4)]


    @staticmethod
    def _normalize_key(key, text_encoding: str = "utf-8", text_errors: str = "strict") -> bytes:
        if isinstance(key, bytes):
            normalized = key
        elif isinstance(key, str):
            text = key.strip()
            if text.lower().startswith("0x"):
                text = text[2:]

            if len(text) in (32, 48, 64):
                try:
                    normalized = bytes.fromhex(text)
                except ValueError:
                    normalized = key.encode(text_encoding, errors=text_errors)
            else:
                normalized = key.encode(text_encoding, errors=text_errors)
        elif isinstance(key, int):
            if key < 0:
                raise ValueError("Key int must be non-negative")

            if key == 0:
                normalized = b"\x00"
            else:
                length = (key.bit_length() + 7) // 8
                normalized = key.to_bytes(length, byteorder="big")
        elif isinstance(key, list):
            if not all(isinstance(item, int) for item in key):
                raise TypeError("Key list must contain only integers")
            if not all(0 <= item <= 0xFF for item in key):
                raise ValueError("Key list items must be in range 0..255")
            normalized = bytes(key)
        else:
            raise TypeError("Key must be of type bytes, str, int, or list[int]")

        if len(normalized) not in (16, 24, 32):
            raise ValueError("Key must be exactly 16, 24, or 32 bytes after conversion")

        return normalized

    @staticmethod
    def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        if pad_len == 0:
            pad_len = block_size
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
        if len(data) == 0 or len(data) % block_size != 0:
            raise ValueError("Invalid padded data length")

        pad_len = data[-1]
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("Invalid PKCS#7 padding")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Invalid PKCS#7 padding bytes")
        return data[:-pad_len]

    def encrypt_block(self, plaintext: bytes) -> bytes:
        block = Block(plaintext)
        block = block ^ self.expanded_key_blocks[0]  # 初始轮密钥加
        for i in range(self.Nr):
            # 这里应该实现AES加密的各个步骤：AddRoundKey, SubBytes, ShiftRows, MixColumns等
            block.ByteSub()  # SubBytes
            block.ShiftRows()  # ShiftRows
            # MixColumns在最后一轮不执行
            if i != self.Nr - 1:
                # 这里应该实现MixColumns变换
                block.MixColumns()
                pass
            block = block ^ self.expanded_key_blocks[i + 1]
        return bytes(block)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        block = Block(ciphertext)
        block = block ^ self.expanded_key_blocks[self.Nr]

        for i in range(self.Nr - 1, 0, -1):
            block.InvShiftRows()
            block.InvByteSub()
            block = block ^ self.expanded_key_blocks[i]
            block.InvMixColumns()

        block.InvShiftRows()
        block.InvByteSub()
        block = block ^ self.expanded_key_blocks[0]
        return bytes(block)

    def encrypt_bytes(self, plaintext: bytes) -> bytes:
        padded = self._pkcs7_pad(plaintext)
        encrypted = bytearray()
        for i in range(0, len(padded), 16):
            encrypted.extend(self.encrypt_block(padded[i:i + 16]))
        return bytes(encrypted)

    def decrypt_bytes(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be a positive multiple of 16")

        decrypted = bytearray()
        for i in range(0, len(ciphertext), 16):
            decrypted.extend(self.decrypt_block(ciphertext[i:i + 16]))
        return self._pkcs7_unpad(bytes(decrypted))

    def encrypt_text(self, plaintext: str, encoding: str | None = None, errors: str | None = None) -> bytes:
        use_encoding = encoding or self.text_encoding
        use_errors = errors or self.text_errors
        data = plaintext.encode(use_encoding, errors=use_errors)
        return self.encrypt_bytes(data)

    def decrypt_text(self, ciphertext: bytes, encoding: str | None = None, errors: str | None = None) -> str:
        use_encoding = encoding or self.text_encoding
        use_errors = errors or self.text_errors
        data = self.decrypt_bytes(ciphertext)
        return data.decode(use_encoding, errors=use_errors)
    

# if __name__ == "__main__":
#     aes = AES([0x24, 0x75, 0xa2, 0xb3, 0x34, 0x75, 0x56, 0x88, 0x31, 0xe2, 0x12, 0x00, 0x13, 0xaa, 0x54, 0x87])
#     print(aes.expanded_key_blocks)