"""AES block cipher core implementation."""

from aescbc.crypto.aes.addroundkey import add_round_key
from aescbc.crypto.aes.key_schedule import expand_key
from aescbc.crypto.aes.mixcolumns import inv_mix_columns, mix_columns
from aescbc.crypto.aes.shiftrows import inv_shift_rows, shift_rows
from aescbc.crypto.aes.subbytes import inv_sub_bytes_state, sub_bytes_state


State = list[list[int]]


def _bytes_to_state(block: bytes) -> State:
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")

    state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = block[row + 4 * col]
    return state


def _state_to_bytes(state: State) -> bytes:
    out: list[int] = []
    for col in range(4):
        for row in range(4):
            out.append(state[row][col] & 0xFF)
    return bytes(out)


class AESCore:
    """AES ECB primitive for single-block operations."""

    block_size = 16

    def __init__(self, key: bytes):
        self.key = self._normalize_key(key)
        self.round_keys = expand_key(self.key)
        self.nr = len(self.round_keys) - 1

    @staticmethod
    def _normalize_key(key: bytes | bytearray) -> bytes:
        if isinstance(key, bytearray):
            key = bytes(key)
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        return key

    def encrypt_block(self, plaintext_block: bytes) -> bytes:
        state = _bytes_to_state(plaintext_block)

        add_round_key(state, self.round_keys[0])

        for rnd in range(1, self.nr):
            sub_bytes_state(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, self.round_keys[rnd])

        sub_bytes_state(state)
        shift_rows(state)
        add_round_key(state, self.round_keys[self.nr])

        return _state_to_bytes(state)

    def decrypt_block(self, ciphertext_block: bytes) -> bytes:
        state = _bytes_to_state(ciphertext_block)

        add_round_key(state, self.round_keys[self.nr])

        for rnd in range(self.nr - 1, 0, -1):
            inv_shift_rows(state)
            inv_sub_bytes_state(state)
            add_round_key(state, self.round_keys[rnd])
            inv_mix_columns(state)

        inv_shift_rows(state)
        inv_sub_bytes_state(state)
        add_round_key(state, self.round_keys[0])

        return _state_to_bytes(state)
