"""Low-level cryptographic primitives used by the WPS protocol.

Everything here is implemented with the Python standard library where
possible (HMAC-SHA256 via ``hmac``/``hashlib``).  AES-128-CBC is used only
to decrypt WPS *Encrypted Settings* (M5/M7); a pure-Python AES is provided
as a fallback when the optional ``cryptography`` package is not installed.

The pure-Python AES is validated as follows:

* at import time the S-box is asserted to be a permutation, and the
  inverse S-box is *derived* as its functional inverse (no second table
  to mistype);
* the full AES-128 implementation is exercised against the official
  FIPS-197 test vector in the self-test suite, which proves the S-box
  itself.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from typing import Optional

__all__ = [
    "hmac_sha256",
    "sha256",
    "wps_kdf",
    "hex2bin",
    "bin2hex",
    "be32",
    "aes128_cbc_decrypt",
    "aes128_cbc_encrypt",
    "CryptoBackend",
]

# ---------------------------------------------------------------------------
# Hashing / MAC / KDF
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def be32(n: int) -> bytes:
    """Big-endian unsigned 32-bit encoding (WPS counter KDF layout)."""
    return struct.pack(">I", n & 0xFFFFFFFF)


def wps_kdf(key: bytes, label: bytes | str, res_len: int) -> bytes:
    """WPS key derivation function.

    ``out = concat(HMAC-SHA256{key}(i || label || keybits))`` for
    ``i = 1..ceil(res_len/32)``, truncated to ``res_len`` octets.

    Mirrors ``wps_kdf()`` from the wpa_supplicant/hostapd reference
    implementation ("Wi-Fi Easy and Secure Key Derivation").
    """
    if isinstance(label, str):
        label = label.encode("ascii")
    key_bits = be32(res_len * 8)
    out = b""
    i = 1
    while len(out) < res_len:
        out += hmac_sha256(key, be32(i) + label + key_bits)
        i += 1
    return out[:res_len]


# ---------------------------------------------------------------------------
# Hex helpers (pixiewps-compatible: tolerates ':' '-' ' ' separators)
# ---------------------------------------------------------------------------

_HEX_SEP_RE = re.compile(r"[:\x20-]")


def bin2hex(data: bytes) -> str:
    return data.hex()


def hex2bin(s: str, expected_len: Optional[int] = None) -> bytes:
    """Convert a hex string to bytes.

    Accepts plain hex or hex with ':', '-' or ' ' separators (same
    behaviour as pixiewps' ``hex_string_to_byte_array``).  When
    ``expected_len`` is given, raises ``ValueError`` on a mismatch.
    """
    cleaned = _HEX_SEP_RE.sub("", s.strip())
    if len(cleaned) % 2 != 0:
        raise ValueError(f"hex string has odd length: {len(cleaned)}")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hex string: {exc}") from exc
    if expected_len is not None and len(data) != expected_len:
        raise ValueError(
            f"expected {expected_len} bytes, got {len(data)} "
            f"(input: {s[:24]}...)"
        )
    return data


# ---------------------------------------------------------------------------
# AES-128 (CBC) — used for WPS Encrypted Settings
# ---------------------------------------------------------------------------
#
# Preferred backend: the `cryptography` package (Rust, very fast).
# Fallback: compact pure-Python AES-128 (encryption + decryption).

try:  # pragma: no cover - import guard
    from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        algorithms,
        modes,
    )

    _HAVE_CRYPOGRAPHY = True
except Exception:  # pragma: no cover
    _HAVE_CRYPOGRAPHY = False


class CryptoBackend:
    """Describes which AES backend is in use (reported in diagnostics)."""

    name = "cryptography" if _HAVE_CRYPOGRAPHY else "pure-python"

    @property
    def fast(self) -> bool:
        return _HAVE_CRYPOGRAPHY


# --- pure-Python AES-128 (fallback) ----------------------------------------

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
)


def _table_inverse(table) -> tuple:
    """Functional inverse of a 256-entry permutation table."""
    out = [0] * 256
    for i, v in enumerate(table):
        out[v] = i
    return tuple(out)


# The S-box must be a bijection (it is, in FIPS-197); assert before deriving
# the inverse from it so a corrupted table fails loudly at import time.
assert len(set(_SBOX)) == 256, "AES S-box is not a permutation"
# Inverse S-box = functional inverse of SBOX.  Correctness of _SBOX itself is
# proven by the FIPS-197 AES-128 test vector in the self-test suite.
_INV_SBOX = _table_inverse(_SBOX)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D)


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p


def _aes128_expand_key(key: bytes) -> list:
    """Return list of 11 round keys (each 16 bytes) for AES-128."""
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    round_keys = []
    for r in range(11):
        rk = bytearray()
        for c in range(4):
            rk += bytes(w[4 * r + c])
        round_keys.append(bytes(rk))
    return round_keys


def _add_round_key(state, rk):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= rk[r + 4 * c]


def _sub_bytes(state, sbox):
    for c in range(4):
        for r in range(4):
            state[r][c] = sbox[state[r][c]]


def _shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def _inv_shift_rows(state):
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]


def _mix_columns(state):
    new = []
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new.append([
            _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3],
            col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3],
            col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3),
            _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2),
        ])
    return [list(row) for row in zip(*new)]


def _inv_mix_columns(state):
    new = []
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new.append([
            _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13)
            ^ _gmul(col[3], 9),
            _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11)
            ^ _gmul(col[3], 13),
            _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14)
            ^ _gmul(col[3], 11),
            _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9)
            ^ _gmul(col[3], 14),
        ])
    return [list(row) for row in zip(*new)]


def _encrypt_block(block: bytes, round_keys) -> bytes:
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        _sub_bytes(state, _SBOX)
        _shift_rows(state)
        state = _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state, _SBOX)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[r][c]
    return bytes(out)


def _decrypt_block(block: bytes, round_keys) -> bytes:
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes(state, _INV_SBOX)
        _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)
    _inv_shift_rows(state)
    _sub_bytes(state, _INV_SBOX)
    _add_round_key(state, round_keys[0])
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[r][c]
    return bytes(out)


def _pure_aes128_cbc(key: bytes, iv: bytes, data: bytes,
                     encrypt: bool) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("AES-128-CBC requires 16-byte key and IV")
    if len(data) == 0 or len(data) % 16:
        raise ValueError("AES-CBC data must be a non-empty multiple of 16")
    round_keys = _aes128_expand_key(key)
    fn = _encrypt_block if encrypt else _decrypt_block
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if encrypt:
            # CBC encrypt: P -> CTE = AES(P XOR prev_CTE); chain on CTEs
            enc = bytes(a ^ b for a, b in zip(blk, prev))
            out += fn(enc, round_keys)
            prev = out[len(out) - 16:]
        else:
            # CBC decrypt: P = AES^-1(C) XOR prev_CTE; chain on CTEs
            dec = fn(blk, round_keys)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = blk
    return bytes(out)


def aes128_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if _HAVE_CRYPOGRAPHY:  # pragma: no cover - depends on env
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return enc.update(data) + enc.finalize()
    return _pure_aes128_cbc(key, iv, data, encrypt=True)


def aes128_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if _HAVE_CRYPOGRAPHY:  # pragma: no cover - depends on env
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(data) + d.finalize()
    return _pure_aes128_cbc(key, iv, data, encrypt=False)
