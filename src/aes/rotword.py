def RotWord(word: bytes) -> bytes:
    return word[1:] + [word[0]]
