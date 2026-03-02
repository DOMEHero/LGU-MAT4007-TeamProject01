from aescbc.crypto.aes.key_schedule import expand_key


def test_round_key_counts():
    assert len(expand_key(bytes(16))) == 11
    assert len(expand_key(bytes(24))) == 13
    assert len(expand_key(bytes(32))) == 15


def test_aes128_known_round_keys():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    round_keys = expand_key(key)

    assert round_keys[0].hex() == "000102030405060708090a0b0c0d0e0f"
    assert round_keys[1].hex() == "d6aa74fdd2af72fadaa678f1d6ab76fe"
    assert round_keys[-1].hex() == "13111d7fe3944a17f307a78b4d2b30c5"


def test_aes256_known_round_key_segment():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    round_keys = expand_key(key)

    assert round_keys[0].hex() == "000102030405060708090a0b0c0d0e0f"
    assert round_keys[1].hex() == "101112131415161718191a1b1c1d1e1f"
    assert round_keys[2].hex() == "a573c29fa176c498a97fce93a572c09c"
