"""AES-128 / KDF / hex-helper tests (pytest)."""

import secrets

import pytest

from wps_attack import crypto


def test_aes128_fips197_vector():
    key = bytes(range(0x00, 0x10))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = crypto.aes128_cbc_encrypt(key, b"\x00" * 16, pt)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


@pytest.mark.parametrize("nblocks", [1, 2, 5])
def test_cbc_roundtrip(nblocks):
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    data = secrets.token_bytes(16 * nblocks)
    ct = crypto.aes128_cbc_encrypt(key, iv, data)
    assert len(ct) == len(data)
    assert ct != data
    assert crypto.aes128_cbc_decrypt(key, iv, ct) == data


def test_cbc_chaining_depends_on_previous_block():
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    p1, p2 = secrets.token_bytes(16), secrets.token_bytes(16)
    ct = crypto.aes128_cbc_encrypt(key, iv, p1 + p2)
    # flipping one plaintext bit must change both ciphertext blocks
    p1b = bytes([p1[0] ^ 1]) + p1[1:]
    ctb = crypto.aes128_cbc_encrypt(key, iv, p1b + p2)
    assert ct[:16] != ctb[:16] and ct[16:] != ctb[16:]


def test_sbox_is_permutation_and_inverse():
    assert len(set(crypto._SBOX)) == 256
    assert all(crypto._INV_SBOX[crypto._SBOX[i]] == i for i in range(256))


def test_wps_kdf_length_and_determinism():
    key = secrets.token_bytes(32)
    a = crypto.wps_kdf(key, b"label", 80)
    b = crypto.wps_kdf(key, b"label", 80)
    c = crypto.wps_kdf(key, b"label2", 80)
    assert len(a) == 80 and a == b and a != c


def test_hex2bin_separators():
    raw = b"\xde\xad\xbe\xef"
    assert crypto.hex2bin("deadbeef") == raw
    assert crypto.hex2bin("de:ad:be:ef") == raw
    assert crypto.hex2bin("de-ad-be-ef") == raw
    assert crypto.hex2bin("de ad be ef") == raw
    with pytest.raises(ValueError):
        crypto.hex2bin("de:ad:be", expected_len=4)
    with pytest.raises(ValueError):
        crypto.hex2bin("xyz")
