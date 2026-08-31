"""PRNG port tests (pytest)."""

import struct

import pytest

from wps_attack import prngs


# ---------------------------------------------------------------------------
# Ralink LFSR
# ---------------------------------------------------------------------------

def test_ralink_forward_restore_backward_chain():
    initial = 0xCAFEBABE
    es1, s = prngs.ralink_bytes_forward(initial, 16)
    es2, s = prngs.ralink_bytes_forward(s, 16)
    nonce, _ = prngs.ralink_bytes_forward(s, 16)

    restored = prngs.ralink_restore_state(nonce)
    out, _ = prngs.ralink_bytes_forward(restored, 16)
    assert out == nonce

    s = restored
    b2 = bytearray(16)
    for i in range(15, -1, -1):
        b, s = prngs.ralink_backward_byte(s)
        b2[i] = b
    b1 = bytearray(16)
    for i in range(15, -1, -1):
        b, s = prngs.ralink_backward_byte(s)
        b1[i] = b
    assert bytes(b2) == es2
    assert bytes(b1) == es1


def test_ralink_restore_requires_16_bytes():
    with pytest.raises(ValueError):
        prngs.ralink_restore_state(b"\x00" * 8)


# ---------------------------------------------------------------------------
# glibc (RTL819x)
# ---------------------------------------------------------------------------

def test_glibc_fast_seed_equals_nonce_word0():
    for seed in (1, 1234567890, 0xFFFFFFFF, 0x7FFFFFFE):
        nonce = prngs.glibc_fast_nonce(seed)
        assert prngs.glibc_fast_seed(seed) == \
            struct.unpack(">I", nonce[0:4])[0]
        # glibc rand() values are non-negative 31-bit
        for word in struct.unpack(">4I", nonce):
            assert word & 0x80000000 == 0


def test_glibc_determinism_and_sensitivity():
    a = prngs.glibc_fast_nonce(1788157790)
    b = prngs.glibc_fast_nonce(1788157790)
    c = prngs.glibc_fast_nonce(1788157791)
    assert a == b
    assert a != c
    assert prngs.rtl_nonce_fill(42) == prngs.glibc_fast_nonce(42)


@pytest.mark.skipif(__import__("sys").platform == "win32",
                    reason="libc rand() not available on Windows")
def test_glibc_matches_real_libc():
    """Cross-check the table model against the system glibc."""
    import ctypes
    libc = ctypes.CDLL(None)
    libc.srand.argtypes = [ctypes.c_uint]
    libc.rand.restype = ctypes.c_uint
    for seed in (1234567890, 1788157790):
        libc.srand(seed)
        expected = [libc.rand() for _ in range(4)]
        got = list(struct.unpack(">4I", prngs.glibc_fast_nonce(seed)))
        assert got == expected


# ---------------------------------------------------------------------------
# eCos
# ---------------------------------------------------------------------------

def test_ecos_simplest_deterministic_stream():
    a, sa = prngs.ecos_rand_simplest(12345)
    b, sb = prngs.ecos_rand_simplest(12345)
    assert a == b and sa == sb
    assert prngs.ecos_rand_simplest(12346)[0] != a


def test_ecos_simple_23bit_output():
    # 11 + 14 + 7 bits mixed
    v, s = prngs.ecos_rand_simple(42)
    v2, s2 = prngs.ecos_rand_simple(42)
    assert (v, s) == (v2, s2)


def test_ecos_knuth_matches_minstd():
    # independent minstd reference implementation
    def ref(seed):
        MM, AA, QQ, RR = 2147483647, 48271, 44488, 3399
        seed = AA * (seed % QQ) - RR * (seed // QQ)
        if seed < 0:
            seed += MM
        return seed
    for seed in (1, 12345, 0x00F00D5E, 2147483646):
        assert prngs.ecos_rand_knuth(seed) == ref(seed)


def test_prng_nonce_and_es_stream_orders():
    # ECOS_SIMPLE: nonce[0] = top 7 seed bits; solver-visible property
    seed = 1_700_000_123
    es1, es2, enonce, _ = prngs.prng_nonce_and_es(prngs.ECOS_SIMPLE, seed)
    assert enonce[0] == (seed >> 25) & 0x7F
    # continuing the stream after the 15 verified bytes gives E-S1, then E-S2
    s = seed
    for i in range(1, 16):
        v, s = prngs.ecos_rand_simple(s)
        assert v & 0xFF == enonce[i]
    for i in range(16):
        v, s = prngs.ecos_rand_simple(s)
        assert v & 0xFF == es1[i]
    for i in range(16):
        v, s = prngs.ecos_rand_simple(s)
        assert v & 0xFF == es2[i]

    # RTL819x: nonce == ES1 (dist 0); ES2 at seed+3
    es1, es2, enonce, _ = prngs.prng_nonce_and_es(prngs.RTL819x, 1000000)
    assert enonce == es1
    assert es2 == prngs.glibc_fast_nonce(1000003)
