"""Synthetic vulnerable-AP simulator.

Generates *realistic* WPS exchange captures the way vulnerable firmware
does, so the offline solver can be exercised end-to-end **without any
WiFi hardware**: pick a PIN, a weak-PRNG mode and a seed (normally the
AP's uptime in seconds), and get back exactly the values an attacker
extracts from M1/M2/M3 (PKE, PKR, E-Hash1, E-Hash2, E-Nonce, R-Nonce,
BSSID, AuthKey).

The PRNG stream order per mode matches ``prngs.prng_nonce_and_es`` and
therefore the solver's reconstruction path, so a capture produced here is
always crackable by ``PixieSolver.auto()`` (that round-trip is what the
self-test asserts).
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from . import prngs, wps
from .wps import Capture, SessionKeys

__all__ = ["ApConfig", "simulated_capture", "SimulationResult"]

# PRNG modes accepted by the simulator
PRNG_MODES = (
    "rt",            # Ralink LFSR
    "rtl819x",       # Realtek glibc rand
    "ecos-simple",   # Broadcom eCos simple LCG
    "ecos-simplest", # eCos simplest LCG
    "ecos-knuth",    # eCos Knuth minstd LCG
    "zero",          # E-S1 = E-S2 = 0
    "nonce-clone",   # E-S1 = E-S2 = E-Nonce
    "random",        # secure random nonces (negative control)
)

_PRNG_BY_NAME = {
    "rt": prngs.RT,
    "rtl819x": prngs.RTL819x,
    "ecos-simple": prngs.ECOS_SIMPLE,
    "ecos-simplest": prngs.ECOS_SIMPLEST,
    "ecos-knuth": prngs.ECOS_KNUTH,
}


@dataclass
class ApConfig:
    """Parameters of the simulated (vulnerable) access point."""

    pin: str
    prng_mode: str = "rtl819x"
    seed: Optional[int] = None          # default: current unix time ("uptime")
    bssid: bytes = None                 # default: random locally-administered
    registrar_mac: bytes = None         # attacker (reaver) MAC
    registrar_nonce: bytes = None       # default: random 16 bytes
    use_rtl_fixed_key: Optional[bool] = None  # auto: True for rtl819x
    small_dh: bool = False              # attacker uses DH privkey 1
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.prng_mode not in PRNG_MODES:
            raise ValueError(
                f"prng_mode must be one of {PRNG_MODES}, got {self.prng_mode}")
        if self.seed is None:
            self.seed = int(time.time())
        if self.bssid is None:
            self.bssid = bytes([0x02, *secrets.token_bytes(5)])
        if self.registrar_mac is None:
            self.registrar_mac = bytes([0x02, *secrets.token_bytes(5)])
        if self.registrar_nonce is None:
            self.registrar_nonce = secrets.token_bytes(16)
        if self.use_rtl_fixed_key is None:
            self.use_rtl_fixed_key = (self.prng_mode == "rtl819x")


@dataclass
class SimulationResult:
    capture: Capture
    secret_nonce_seed: int
    mode: str
    keys: SessionKeys
    detail: dict = field(default_factory=dict)


def simulated_capture(cfg: ApConfig,
                      attacker_privkey: Optional[int] = None) -> SimulationResult:
    """Build a capture the way a real vulnerable AP + reaver exchange would.

    If ``attacker_privkey`` is given, the attacker (registrar) DH private
    key is fixed to it (used by tests to pin the AuthKey); otherwise a
    random 20-byte-ish exponent is generated.
    """
    if cfg.small_dh:
        attacker_privkey = 1
    if attacker_privkey is None:
        attacker_privkey = secrets.randbits(2048)

    # --- AP (enrollee) side -------------------------------------------------
    p = wps.DH_GROUP5_PRIME
    P = int.from_bytes(p, "big")

    if cfg.use_rtl_fixed_key:
        # Realtek fixed enrollee key (the interesting real-world case)
        pke = wps.WPS_RTL_PKE
        ap_privkey = int.from_bytes(wps.WPS_RTL_PRIV_KEY, "big")
    else:
        ap_privkey = secrets.randbits(2048)
        pke = (pow(wps.DH_GROUP5_GENERATOR, ap_privkey, P)).to_bytes(192, "big")

    pk_r = (pow(wps.DH_GROUP5_GENERATOR, attacker_privkey, P)).to_bytes(
        192, "big")

    # AP nonce (E-Nonce) + secret nonces from the (weak) PRNG
    if cfg.prng_mode in _PRNG_BY_NAME:
        mode = _PRNG_BY_NAME[cfg.prng_mode]
        es1, es2, enonce, _info = prngs.prng_nonce_and_es(mode, cfg.seed)
    elif cfg.prng_mode == "zero":
        es1 = es2 = enonce = b"\x00" * 16
    elif cfg.prng_mode == "nonce-clone":
        enonce = secrets.token_bytes(16)
        es1 = es2 = enonce
    else:  # random (secure) nonces — solver must NOT find a PIN
        enonce = secrets.token_bytes(16)
        es1 = secrets.token_bytes(16)
        es2 = secrets.token_bytes(16)

    # --- session keys (both sides compute the same values) ------------------
    dh_shared = pow(int.from_bytes(pke, "big"), attacker_privkey, P).to_bytes(
        192, "big")
    keys = wps.derive_session_keys(
        dh_shared,
        enrollee_nonce=enonce,      # AP is the enrollee
        enrollee_mac=cfg.bssid,
        registrar_nonce=cfg.registrar_nonce,
    )

    # --- AP hashes (M3) — with the *real* PIN --------------------------------
    psk1, psk2 = wps.derive_psk(keys.authkey, cfg.pin)
    ehash1 = wps.e_hash(keys.authkey, es1, psk1, pke, pk_r)
    ehash2 = wps.e_hash(keys.authkey, es2, psk2, pke, pk_r)

    capture = Capture(
        pke=pke,
        pkr=pk_r,
        ehash1=ehash1,
        ehash2=ehash2,
        enonce=enonce,
        rnonce=cfg.registrar_nonce,
        bssid=cfg.bssid,
        authkey=keys.authkey,
        small_dh=cfg.small_dh,
        meta={
            "simulated": True,
            "sim_prng_mode": cfg.prng_mode,
            "sim_seed": cfg.seed,
            "sim_pin": cfg.pin,
        },
    )
    return SimulationResult(
        capture=capture,
        secret_nonce_seed=cfg.seed,
        mode=cfg.prng_mode,
        keys=keys,
        detail={"pke_fixed": cfg.use_rtl_fixed_key, "small_dh": cfg.small_dh},
    )
