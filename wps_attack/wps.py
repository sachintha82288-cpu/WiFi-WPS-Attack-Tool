"""WPS protocol primitives.

Implements the pieces of the Wi-Fi Protected Setup protocol (WFA spec v2)
that are needed for offline PIN analysis, cross-checked against two
independent reference implementations:

* wpa_supplicant / hostapd (``src/wps/wps_common.c``,
  ``src/wps/wps_enrollee.c``) — the Wi-Fi Alliance reference code;
* pixiewps (https://github.com/wiire-a/pixiewps) — the offline pixie-dust
  tool that reaver integrates.

Key relations implemented here
------------------------------
PIN checksum (7-digit PIN -> check digit)::

    acc = 0
    while pin:
        acc += 3 * (pin % 10); pin //= 10
        acc +=      (pin % 10); pin //= 10
    check = (10 - acc % 10) % 10

PSK halves (per ``wps_derive_psk``)::

    PSK1 = HMAC-SHA256(AuthKey, ASCII(pin[:4]))[:16]
    PSK2 = HMAC-SHA256(AuthKey, ASCII(pin[4:]))[:16]

E-Hashes (per ``wps_build_e_hash``)::

    E-Hash1 = HMAC-SHA256(AuthKey, E-S1 || PSK1 || PKE || PKR)
    E-Hash2 = HMAC-SHA256(AuthKey, E-S2 || PSK2 || PKE || PKR)

Session keys (per ``wps_derive_keys``)::

    DHKey  = SHA-256(zeropad(g^(AB) mod p, 192))
    KDK    = HMAC-SHA256(DHKey, EnrolleeNonce || EnrolleeMAC || RegistrarNonce)
    AuthKey || KeyWrapKey || EMSK =
        KDF(KDK, "Wi-Fi Easy and Secure Key Derivation", 80)
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Iterator, Optional

from . import crypto
from .crypto import bin2hex, hex2bin  # noqa: F401  (re-export)

__all__ = [
    "DH_GROUP5_PRIME",
    "DH_GROUP5_GENERATOR",
    "WPS_RTL_PKE",
    "WPS_RTL_PRIV_KEY",
    "wps_pin_checksum",
    "wps_pin_valid",
    "complete_pin",
    "pin_candidates",
    "iter_p1_p2",
    "COMMON_PINS",
    "derive_psk",
    "empty_psk",
    "e_hash",
    "check_small_dh_keys",
    "dh_shared_secret",
    "derive_session_keys",
    "decrypt_encr_settings",
    "SessionKeys",
    "Capture",
]

# ---------------------------------------------------------------------------
# DH Group 5 (RFC 3526, 1536-bit MODP) — WPS mandatory group
# ---------------------------------------------------------------------------

DH_GROUP5_PRIME = bytes.fromhex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
)
assert len(DH_GROUP5_PRIME) == 192
_DH_P = int.from_bytes(DH_GROUP5_PRIME, "big")
DH_GROUP5_GENERATOR = 2

# ---------------------------------------------------------------------------
# Realtek (RTL819x) fixed enrollee DH key pair (from pixiewps).
# Some Realtek APs ship a *static* DH key; when PKE equals this constant
# the shared secret can be computed without any other secret material.
# ---------------------------------------------------------------------------

WPS_RTL_PKE = bytes.fromhex(
    "D0141B15656E96B85FCEAD2E8E76330D"  # 16
    "2B1AC1576BB026E7A328C0E1BAF8CF91"  # 32
    "664371174C08EE12EC92B0519C54879F"  # 48
    "21255BE5A8770E1FA1880470EF423C90"  # 64
    "E34D7847A6FCB4924563D1AF1DB0C481"  # 80
    "EAD9852C519BF1DD429C163951CF6918"  # 96
    "1B132AEA2A3684CAF35BC54ACA1B20C8"  # 112
    "8BB3B7339FF7D56E09139D77F0AC5807"  # 128
    "9097938251DBBE75E86715CC6B7C0CA9"  # 144
    "45FA8DD8D661BEB73B414032798DADEE"  # 160
    "32B5DD61BF105F18D89217760B75C5D9"  # 176
    "66A5A490472CEBA9E3B4224F3D89FB2B"  # 192
)
assert len(WPS_RTL_PKE) == 192
WPS_RTL_PRIV_KEY = bytes([0x55]) * 192  # SET_RTL_PRIV_KEY(x) == memset(x, 0x55, 192)

# ---------------------------------------------------------------------------
# PIN helpers
# ---------------------------------------------------------------------------


def wps_pin_checksum(pin7) -> int:
    """Compute the WPS PIN check digit from a 7-digit PIN (int or str).

    Exactly mirrors ``wps_pin_checksum()`` from wpa_supplicant and
    pixiewps: digits are processed least-significant first with
    alternating weights 3 and 1.
    """
    if isinstance(pin7, str):
        if len(pin7) != 7 or not pin7.isdigit():
            raise ValueError("pin7 string must be exactly 7 digits")
        pin7 = int(pin7)
    if not (0 <= pin7 <= 9999999):
        raise ValueError("pin7 must be a 0..9999999 integer")
    acc = 0
    p = pin7
    while p:
        acc += 3 * (p % 10)
        p //= 10
        acc += p % 10
        p //= 10
    return (10 - acc % 10) % 10


def wps_pin_valid(pin8: str | int) -> bool:
    """True if an 8-digit PIN's final check digit is valid."""
    if isinstance(pin8, str):
        if len(pin8) != 8 or not pin8.isdigit():
            return False
        pin8 = int(pin8)
    if not (0 <= pin8 <= 99999999):
        return False
    return wps_pin_checksum(pin8 // 10) == pin8 % 10


def complete_pin(p1: int, p2: int) -> str:
    """Build the full 8-digit PIN from its two free halves.

    ``p1`` = first 4 free digits (0..9999), ``p2`` = next 3 free digits
    (0..999); the 8th digit is the check digit.
    """
    if not (0 <= p1 <= 9999) or not (0 <= p2 <= 999):
        raise ValueError("p1 must be 0..9999 and p2 0..999")
    base7 = p1 * 1000 + p2
    check = wps_pin_checksum(base7)
    return f"{p1:04d}{p2:03d}{check}"


def iter_p1_p2() -> Iterator[tuple[int, int]]:
    """Yield all (p1, p2) pairs covering the 10^7 valid WPS PINs."""
    for p1 in range(10000):
        for p2 in range(1000):
            yield p1, p2


def pin_candidates() -> Iterator[str]:
    """Yield all 10^7 check-digit-valid 8-digit WPS PINs."""
    return (complete_pin(p1, p2) for p1, p2 in iter_p1_p2())


#: Well-known factory-default WPS PINs (sorted by observed frequency on
#: consumer hardware).  Many of these do NOT satisfy the WPS checksum —
#: cheap firmware frequently skips check-digit validation, so they are
#: still seen in the wild.  The offline solver's second-half search
#: covers both valid and non-conformant candidates, and the analyzer
#: flags any recovered PIN that appears here.
COMMON_PINS: tuple[str, ...] = (
    "12345670",  # ubiquitous default (TP-Link, many ISP routers)
    "00000000",
    "11223344",
    "11111111",
    "16843205",
    "00102030",
    "20121230",
    "12345678",
    "55555555",
    "99999999",
    "88888888",
    "65432109",
    "10101010",
    "01010101",
    "20111230",
    "12121212",
    "22222222",
    "00001234",
    "33333333",
)

#: The checksum-valid subset of COMMON_PINS (accepted by spec-conformant
#: APs without any non-conformant behaviour).
COMMON_PINS_VALID: tuple[str, ...] = tuple(
    pin for pin in COMMON_PINS if wps_pin_valid(pin))


# ---------------------------------------------------------------------------
# PSK / E-Hash derivation
# ---------------------------------------------------------------------------


def derive_psk(authkey: bytes, pin: str) -> tuple[bytes, bytes]:
    """PSK1/PSK2 from the full PIN (per ``wps_derive_psk``)."""
    if len(authkey) != 32:
        raise ValueError("authkey must be 32 bytes")
    if len(pin) not in (4, 8):
        raise ValueError("pin must be a 4- or 8-digit string")
    half = (len(pin) + 1) // 2
    psk1 = crypto.hmac_sha256(authkey, pin[:half].encode("ascii"))[:16]
    if len(pin) == 4:
        psk2 = psk1
    else:
        psk2 = crypto.hmac_sha256(authkey, pin[half:].encode("ascii"))[:16]
    return psk1, psk2


def empty_psk(authkey: bytes) -> bytes:
    """PSK for the 'empty PIN' special case (HMAC over empty data)."""
    return crypto.hmac_sha256(authkey, b"")[:16]


def e_hash(authkey: bytes, es: bytes, psk: bytes, pke: bytes,
           pkr: bytes) -> bytes:
    """E-Hash = HMAC-SHA256(AuthKey, E-S || PSK || PKE || PKR)."""
    return crypto.hmac_sha256(authkey, es + psk + pke + pkr)


# ---------------------------------------------------------------------------
# Diffie-Hellman / session key derivation
# ---------------------------------------------------------------------------


def check_small_dh_keys(pkey: bytes) -> bool:
    """True if the 192-byte DH public key encodes the value 2 (privkey 1)."""
    return len(pkey) == 192 and pkey[-1] == 0x02 and not any(pkey[:-1])


def dh_shared_secret(pubkey: bytes, privkey: int) -> bytes:
    """g^(AB) mod p as a 192-byte big-endian value (zeropadded)."""
    if len(pubkey) != 192:
        raise ValueError("pubkey must be 192 bytes")
    shared = pow(int.from_bytes(pubkey, "big"), privkey, _DH_P)
    return shared.to_bytes(192, "big")


@dataclass
class SessionKeys:
    dhkey: bytes
    kdk: bytes
    authkey: bytes
    wrapkey: bytes
    emsk: bytes


def derive_session_keys(dh_shared: bytes, enrollee_nonce: bytes,
                        enrollee_mac: bytes, registrar_nonce: bytes) -> SessionKeys:
    """DHKey/KDK/AuthKey/KeyWrapKey/EMSK (per ``wps_derive_keys``).

    ``enrollee_mac`` is the MAC of the device acting as *enrollee* — in a
    reaver-style attack that is the target AP's BSSID.
    """
    for name, v in (("dh_shared", dh_shared), ("enrollee_nonce",
                                               enrollee_nonce),
                    ("enrollee_mac", enrollee_mac),
                    ("registrar_nonce", registrar_nonce)):
        if v is None:
            raise ValueError(f"{name} is required")
    if len(dh_shared) != 192:
        raise ValueError("dh_shared must be 192 bytes")
    if len(enrollee_nonce) != 16 or len(registrar_nonce) != 16:
        raise ValueError("nonces must be 16 bytes")
    if len(enrollee_mac) != 6:
        raise ValueError("enrollee_mac must be 6 bytes")
    dhkey = crypto.sha256(dh_shared)
    kdk = crypto.hmac_sha256(
        dhkey, enrollee_nonce + enrollee_mac + registrar_nonce)
    keys = crypto.wps_kdf(kdk, b"Wi-Fi Easy and Secure Key Derivation", 80)
    return SessionKeys(
        dhkey=dhkey,
        kdk=kdk,
        authkey=keys[:32],
        wrapkey=keys[32:48],
        emsk=keys[48:80],
    )


def decrypt_encr_settings(wrapkey: bytes, encr: bytes) -> Optional[bytes]:
    """Decrypt WPS Encrypted Settings (AES-128-CBC, PKCS#5 padding).

    Returns the padded plaintext without the PKCS#5 padding, or ``None``
    on failure.
    """
    if wrapkey is None or encr is None:
        return None
    block = 16
    if len(encr) < 2 * block or len(encr) % block:
        return None
    iv, ct = encr[:block], encr[block:]
    try:
        plain = crypto.aes128_cbc_decrypt(wrapkey, iv, ct)
    except Exception:
        return None
    pad = plain[-1]
    if pad == 0 or pad > len(plain) or plain[-pad:] != bytes([pad]) * pad:
        return None
    return plain[:-pad]


# ---------------------------------------------------------------------------
# Capture — the data an attacker extracts from one WPS exchange
# ---------------------------------------------------------------------------


@dataclass
class Capture:
    """Values captured from a WPS M1/M2/M3 exchange.

    Naming follows the WPS protocol where the *target AP* is the enrollee
    (reaver acts as registrar):

    * ``pke``       — AP (enrollee) DH public key, from M1 (192 bytes)
    * ``pkr``       — attacker (registrar) DH public key, from M2 (192 bytes)
    * ``ehash1``    — AP's E-Hash1, from M3 (32 bytes)
    * ``ehash2``    — AP's E-Hash2, from M3 (32 bytes)
    * ``enonce``    — AP (enrollee) nonce, from M1 (16 bytes)
    * ``rnonce``    — attacker (registrar) nonce, from M2 (16 bytes)
    * ``bssid``     — AP MAC address (enrollee MAC, 6 bytes)
    * ``authkey``   — shared AuthKey (32 bytes); optional, derivable when
      the DH shared secret is known (small-DH or RTL819x fixed key)
    """

    pke: bytes = None
    pkr: bytes = None
    ehash1: bytes = None
    ehash2: bytes = None
    enonce: bytes = None
    rnonce: bytes = None
    bssid: bytes = None
    authkey: bytes = None
    small_dh: bool = False
    meta: dict = field(default_factory=dict)

    def validate(self, need_authkey: bool = True) -> list[str]:
        """Return a list of human-readable problems (empty when OK)."""
        problems = []
        for name, val, size in (
            ("pke", self.pke, 192),
            ("pkr", self.pkr, 192),
            ("ehash1", self.ehash1, 32),
            ("ehash2", self.ehash2, 32),
            ("enonce", self.enonce, 16),
        ):
            if val is None:
                problems.append(f"missing {name}")
            elif len(val) != size:
                problems.append(f"{name} must be {size} bytes (got {len(val)})")
        if self.rnonce is not None and len(self.rnonce) != 16:
            problems.append("rnonce must be 16 bytes")
        if self.bssid is not None and len(self.bssid) != 6:
            problems.append("bssid must be 6 bytes")
        if self.authkey is not None and len(self.authkey) != 32:
            problems.append("authkey must be 32 bytes")
        if need_authkey and self.authkey is None:
            if self.small_dh:
                pass  # derivable from PKE alone
            elif self.pke is not None and self.pke == WPS_RTL_PKE:
                if self.rnonce is None or self.bssid is None:
                    problems.append(
                        "RTL819x fixed-key authkey derivation needs "
                        "rnonce and bssid")
            else:
                problems.append(
                    "authkey missing (provide it, use --dh-small, or rely "
                    "on the RTL819x fixed-key path)")
        return problems

    # -- (de)serialization --------------------------------------------------

    def to_dict(self) -> dict:
        d = {}
        for k in ("pke", "pkr", "ehash1", "ehash2", "enonce", "rnonce",
                  "bssid", "authkey"):
            v = getattr(self, k)
            d[k] = v.hex() if v is not None else None
        d["small_dh"] = self.small_dh
        d["meta"] = dict(self.meta)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Capture":
        def b(k):
            v = d.get(k)
            return crypto.hex2bin(v) if v else None
        return cls(
            pke=b("pke"), pkr=b("pkr"), ehash1=b("ehash1"), ehash2=b("ehash2"),
            enonce=b("enonce"), rnonce=b("rnonce"), bssid=b("bssid"),
            authkey=b("authkey"),
            small_dh=bool(d.get("small_dh", False)),
            meta=dict(d.get("meta") or {}),
        )
