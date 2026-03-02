"""AddRoundKey operation."""


State = list[list[int]]


def add_round_key(state: State, round_key: bytes) -> None:
    if len(round_key) != 16:
        raise ValueError("Round key must be 16 bytes")

    for col in range(4):
        for row in range(4):
            state[row][col] ^= round_key[row + 4 * col]
            state[row][col] &= 0xFF
