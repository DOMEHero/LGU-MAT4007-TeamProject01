"""Galois field arithmetic used by AES."""


def xtime(value: int) -> int:
    value &= 0xFF
    shifted = value << 1
    if value & 0x80:
        shifted ^= 0x11B
    return shifted & 0xFF


def gf_mul(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1

    return result & 0xFF


def gf_pow(base: int, exponent: int) -> int:
    base &= 0xFF
    result = 1

    while exponent > 0:
        if exponent & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exponent >>= 1

    return result & 0xFF


def gf_inv(value: int) -> int:
    value &= 0xFF
    if value == 0:
        return 0
    # In GF(2^8), a^254 = a^-1 for non-zero a.
    return gf_pow(value, 254)
