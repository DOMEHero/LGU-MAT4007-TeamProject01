"""AES key expansion."""

from aescbc.crypto.aes.subbytes import sub_word


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def _rcon_sequence(length: int) -> list[int]:
    rcon = [0x00] * (length + 1)
    rcon[1] = 0x01
    for i in range(2, length + 1):
        value = rcon[i - 1] << 1
        if rcon[i - 1] & 0x80:
            value ^= 0x11B
        rcon[i] = value & 0xFF
    return rcon


def expand_key(key: bytes) -> list[bytes]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")

    nk = len(key) // 4
    nr = nk + 6
    nb = 4
    total_words = nb * (nr + 1)

    words: list[list[int]] = [list(key[i : i + 4]) for i in range(0, len(key), 4)]
    rcon = _rcon_sequence(total_words // nk + 1)

    for i in range(nk, total_words):
        temp = words[i - 1][:]

        if i % nk == 0:
            temp = sub_word(_rot_word(temp))
            temp[0] ^= rcon[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)

        next_word = [(words[i - nk][j] ^ temp[j]) & 0xFF for j in range(4)]
        words.append(next_word)

    round_keys: list[bytes] = []
    for round_index in range(nr + 1):
        key_bytes: list[int] = []
        base = round_index * nb
        for col in range(nb):
            key_bytes.extend(words[base + col])
        round_keys.append(bytes(key_bytes))

    return round_keys
