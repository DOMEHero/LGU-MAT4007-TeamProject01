from aescbc.crypto.aes import AESCore
from aescbc.crypto.modes.cbc import CBCMode
from aescbc.crypto.padding.pkcs7 import pkcs7_pad, pkcs7_unpad


def test_nist_sp800_38a_cbc_vector():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    expected = bytes.fromhex(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"
    )

    cbc = CBCMode(AESCore(key), iv)
    ciphertext = cbc.encrypt(plaintext)
    assert ciphertext == expected
    assert cbc.decrypt(ciphertext) == plaintext


def test_cbc_roundtrip_with_padding():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    message = b"CBC mode needs block-aligned input after padding"

    padded = pkcs7_pad(message, 16)
    cbc = CBCMode(AESCore(key), iv)
    ciphertext = cbc.encrypt(padded)
    restored = pkcs7_unpad(cbc.decrypt(ciphertext), 16)

    assert restored == message
