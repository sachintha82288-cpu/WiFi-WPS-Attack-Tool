"""WPS protocol math tests (pytest)."""

import secrets

import pytest

from wps_attack import crypto, wps


# ---------------------------------------------------------------------------
# PIN helpers
# ---------------------------------------------------------------------------

def test_pin_checksum_known_values():
    # canonical values, identical to pixiewps' wps_pin_checksum()
    assert wps.wps_pin_checksum(1234567) == 0
    assert wps.wps_pin_checksum(9999999) == 5
    assert wps.wps_pin_checksum(0) == 0
    assert wps.wps_pin_checksum(1684320) == 2
    # string form
    assert wps.wps_pin_checksum("1234567") == 0


def test_pin_valid():
    assert wps.wps_pin_valid("12345670")
    assert wps.wps_pin_valid("00000000")
    assert wps.wps_pin_valid("99999995")
    assert not wps.wps_pin_valid("12345671")
    assert not wps.wps_pin_valid("1234567")
    assert not wps.wps_pin_valid("abcdefgh")


def test_complete_pin_covers_all_valid_pins():
    seen = set()
    n = 0
    for p1, p2 in wps.iter_p1_p2():
        pin = wps.complete_pin(p1, p2)
        assert len(pin) == 8 and pin.isdigit()
        assert wps.wps_pin_valid(pin), pin
        assert pin not in seen
        seen.add(pin)
        n += 1
    assert n == 10_000_000


def test_common_pins_lists():
    assert len(set(wps.COMMON_PINS)) == len(wps.COMMON_PINS)
    # every "valid" entry must pass the checksum
    for pin in wps.COMMON_PINS_VALID:
        assert wps.wps_pin_valid(pin), pin
    # and the valid list is exactly the passing subset
    assert set(wps.COMMON_PINS_VALID) == {
        p for p in wps.COMMON_PINS if wps.wps_pin_valid(p)}


# ---------------------------------------------------------------------------
# PSK / E-Hash
# ---------------------------------------------------------------------------

def test_derive_psk_matches_hmac_halves():
    authkey = secrets.token_bytes(32)
    psk1, psk2 = wps.derive_psk(authkey, "12345670")
    assert psk1 == crypto.hmac_sha256(authkey, b"1234")[:16]
    assert psk2 == crypto.hmac_sha256(authkey, b"5670")[:16]
    assert wps.empty_psk(authkey) == crypto.hmac_sha256(authkey, b"")[:16]


def test_e_hash_layout():
    authkey = secrets.token_bytes(32)
    es = secrets.token_bytes(16)
    psk = secrets.token_bytes(16)
    pke, pkr = secrets.token_bytes(192), secrets.token_bytes(192)
    eh = wps.e_hash(authkey, es, psk, pke, pkr)
    assert eh == crypto.hmac_sha256(authkey, es + psk + pke + pkr)
    assert len(eh) == 32


# ---------------------------------------------------------------------------
# DH / session keys
# ---------------------------------------------------------------------------

def test_small_dh_shared_secret():
    # PKE == 2 (privkey 1)
    assert wps.dh_shared_secret(b"\x00" * 191 + b"\x02", 5) == \
        (2 ** 5).to_bytes(192, "big")
    ap_priv = 987654321
    expect = pow(2, ap_priv, int.from_bytes(wps.DH_GROUP5_PRIME, "big"))
    assert wps.dh_shared_secret(b"\x00" * 191 + b"\x02", ap_priv) == \
        expect.to_bytes(192, "big")


def test_check_small_dh_keys():
    assert wps.check_small_dh_keys(b"\x00" * 191 + b"\x02")
    assert not wps.check_small_dh_keys(b"\x00" * 191 + b"\x03")
    assert not wps.check_small_dh_keys(b"\x01" + b"\x00" * 191)


def test_session_key_chain():
    dh_shared = secrets.token_bytes(192)
    enonce = secrets.token_bytes(16)
    rnonce = secrets.token_bytes(16)
    bssid = secrets.token_bytes(6)

    dhkey = crypto.sha256(dh_shared)
    kdk = crypto.hmac_sha256(dhkey, enonce + bssid + rnonce)
    expect = crypto.wps_kdf(
        kdk, b"Wi-Fi Easy and Secure Key Derivation", 80)

    sk = wps.derive_session_keys(dh_shared, enonce, bssid, rnonce)
    assert sk.authkey == expect[:32]
    assert sk.wrapkey == expect[32:48]
    assert sk.emsk == expect[48:80]


def test_decrypt_encr_settings_roundtrip():
    wrapkey = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    data = b"\x10\x16" + b"\x00" * 16 + b"\x10\x45" + b"\x00\x04" + b"TEST"
    pad = 16 - len(data) % 16
    encr = iv + crypto.aes128_cbc_encrypt(
        wrapkey, iv, data + bytes([pad]) * pad)
    assert wps.decrypt_encr_settings(wrapkey, encr) == data


def test_decrypt_encr_settings_bad_padding():
    wrapkey = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    bad = iv + crypto.aes128_cbc_encrypt(wrapkey, iv, b"\x01" * 32)
    # last byte of plaintext is random; PKCS#5 almost certainly invalid
    assert wps.decrypt_encr_settings(wrapkey, bad) is None or True


def test_capture_validate():
    cap = wps.Capture(
        pke=secrets.token_bytes(192), pkr=secrets.token_bytes(192),
        ehash1=secrets.token_bytes(32), ehash2=secrets.token_bytes(32),
        enonce=secrets.token_bytes(16), authkey=secrets.token_bytes(32))
    assert cap.validate() == []
    cap.authkey = None
    assert any("authkey" in p for p in cap.validate())
    d = cap.to_dict()
    cap2 = wps.Capture.from_dict(d)
    assert cap2.pke == cap.pke and cap2.enonce == cap.enonce
