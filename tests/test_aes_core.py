from aescbc.crypto.aes import AESCore


def test_aes_128_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    aes = AESCore(key)
    ciphertext = aes.encrypt_block(plaintext)
    assert ciphertext == expected
    assert aes.decrypt_block(ciphertext) == plaintext


def test_aes_192_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")

    aes = AESCore(key)
    ciphertext = aes.encrypt_block(plaintext)
    assert ciphertext == expected
    assert aes.decrypt_block(ciphertext) == plaintext


def test_aes_256_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

    aes = AESCore(key)
    ciphertext = aes.encrypt_block(plaintext)
    assert ciphertext == expected
    assert aes.decrypt_block(ciphertext) == plaintext
