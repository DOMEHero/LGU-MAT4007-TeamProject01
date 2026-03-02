"""PKCS#7 padding helpers."""


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be between 1 and 255")

    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size

    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be between 1 and 255")
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding length")

    pad = data[-pad_len:]
    if pad != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data[:-pad_len]
