"""AES S-box tables generated from field inverse + affine transform."""

from aescbc.crypto.aes.galois import gf_inv


def _affine_transform(byte: int) -> int:
    constant = 0x63
    out = 0
    for i in range(8):
        bit = (
            ((byte >> i) & 1)
            ^ ((byte >> ((i + 4) % 8)) & 1)
            ^ ((byte >> ((i + 5) % 8)) & 1)
            ^ ((byte >> ((i + 6) % 8)) & 1)
            ^ ((byte >> ((i + 7) % 8)) & 1)
            ^ ((constant >> i) & 1)
        )
        out |= bit << i
    return out


def _generate_sboxes() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    inv_sbox = [0] * 256

    for value in range(256):
        mapped = _affine_transform(gf_inv(value))
        sbox[value] = mapped
        inv_sbox[mapped] = value

    return sbox, inv_sbox


SBOX, INV_SBOX = _generate_sboxes()
