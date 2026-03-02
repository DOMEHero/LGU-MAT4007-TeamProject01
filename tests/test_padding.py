import pytest

from aescbc.crypto.padding.pkcs7 import pkcs7_pad, pkcs7_unpad


def test_pkcs7_roundtrip():
    data = b"hello"
    padded = pkcs7_pad(data, 16)
    assert len(padded) == 16
    assert pkcs7_unpad(padded, 16) == data


def test_pkcs7_full_block_padding():
    data = b"A" * 16
    padded = pkcs7_pad(data, 16)
    assert len(padded) == 32
    assert padded[-1] == 16
    assert pkcs7_unpad(padded, 16) == data


def test_pkcs7_invalid_padding_raises():
    with pytest.raises(ValueError):
        pkcs7_unpad(b"abc", 16)

    with pytest.raises(ValueError):
        pkcs7_unpad(b"A" * 15 + b"\x00", 16)

    with pytest.raises(ValueError):
        pkcs7_unpad(b"A" * 14 + b"\x02\x03", 16)
