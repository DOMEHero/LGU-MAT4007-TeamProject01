"""MixColumns transforms."""

from aescbc.crypto.aes.galois import gf_mul


State = list[list[int]]


def _mix_single_column(column: list[int]) -> list[int]:
    a0, a1, a2, a3 = column
    return [
        gf_mul(a0, 0x02) ^ gf_mul(a1, 0x03) ^ a2 ^ a3,
        a0 ^ gf_mul(a1, 0x02) ^ gf_mul(a2, 0x03) ^ a3,
        a0 ^ a1 ^ gf_mul(a2, 0x02) ^ gf_mul(a3, 0x03),
        gf_mul(a0, 0x03) ^ a1 ^ a2 ^ gf_mul(a3, 0x02),
    ]


def _inv_mix_single_column(column: list[int]) -> list[int]:
    a0, a1, a2, a3 = column
    return [
        gf_mul(a0, 0x0E) ^ gf_mul(a1, 0x0B) ^ gf_mul(a2, 0x0D) ^ gf_mul(a3, 0x09),
        gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0E) ^ gf_mul(a2, 0x0B) ^ gf_mul(a3, 0x0D),
        gf_mul(a0, 0x0D) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0E) ^ gf_mul(a3, 0x0B),
        gf_mul(a0, 0x0B) ^ gf_mul(a1, 0x0D) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0E),
    ]


def mix_columns(state: State) -> None:
    for col in range(4):
        column = [state[row][col] for row in range(4)]
        mixed = _mix_single_column(column)
        for row in range(4):
            state[row][col] = mixed[row] & 0xFF


def inv_mix_columns(state: State) -> None:
    for col in range(4):
        column = [state[row][col] for row in range(4)]
        mixed = _inv_mix_single_column(column)
        for row in range(4):
            state[row][col] = mixed[row] & 0xFF
