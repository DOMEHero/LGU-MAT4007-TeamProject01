"""SubBytes transforms for words and state matrices."""

from aescbc.crypto.aes.sbox import INV_SBOX, SBOX


State = list[list[int]]


def sub_word(word: list[int]) -> list[int]:
    return [SBOX[b & 0xFF] for b in word]


def inv_sub_word(word: list[int]) -> list[int]:
    return [INV_SBOX[b & 0xFF] for b in word]


def sub_bytes_state(state: State) -> None:
    for row in range(4):
        for col in range(4):
            state[row][col] = SBOX[state[row][col] & 0xFF]


def inv_sub_bytes_state(state: State) -> None:
    for row in range(4):
        for col in range(4):
            state[row][col] = INV_SBOX[state[row][col] & 0xFF]
