"""Offline solver tests: simulator -> solver round-trips (pytest).

These are the acceptance tests for the pixie-dust engine: a synthetic
vulnerable AP capture must be cracked back to the exact PIN, and a
secure-random capture must NOT.
"""

import time

import pytest

from wps_attack import prngs
from wps_attack.pixiedust import PixieSolver
from wps_attack.simulator import ApConfig, simulated_capture


def _solve(cfg):
    sim = simulated_capture(cfg)
    solver = PixieSolver(sim.capture, progress=lambda m: None)
    return solver.auto(), sim


# ---------------------------------------------------------------------------
# Auto mode (realistic captures)
# ---------------------------------------------------------------------------

def test_roundtrip_rtl819x_default_range():
    # seed just inside the default +/-1 day window
    cfg = ApConfig(pin="12345670", prng_mode="rtl819x",
                   seed=int(time.time()) - 3600)
    res, sim = _solve(cfg)
    assert res.found
    assert res.pin == "12345670"
    assert res.mode == "rtl819x"
    assert res.seeds["nonce_seed"] == cfg.seed
    assert res.duration < 60


def test_roundtrip_rt():
    cfg = ApConfig(pin="25801128", prng_mode="rt", seed=0x0BADF00D)
    res, _ = _solve(cfg)
    assert res.found and res.pin == "25801128"
    assert res.mode == "rt"


def test_roundtrip_ecos_simple():
    cfg = ApConfig(pin="46317800", prng_mode="ecos-simple",
                   seed=1_700_000_123)
    res, _ = _solve(cfg)
    assert res.found and res.pin == "46317800"
    assert res.mode == "ecos-simple"


def test_special_case_zero():
    cfg = ApConfig(pin="00000000", prng_mode="zero", seed=1,
                   use_rtl_fixed_key=False)
    res, _ = _solve(cfg)
    assert res.found and res.pin == "00000000"


def test_special_case_nonce_clone():
    cfg = ApConfig(pin="00000000", prng_mode="nonce-clone", seed=1,
                   use_rtl_fixed_key=False)
    res, _ = _solve(cfg)
    assert res.found and res.pin == "00000000"


# ---------------------------------------------------------------------------
# Explicit modes (not in the auto list)
# ---------------------------------------------------------------------------

def test_roundtrip_ecos_simplest_explicit():
    seed = 0x001A2B3C
    cfg = ApConfig(pin="11111115", prng_mode="ecos-simplest", seed=seed)
    sim = simulated_capture(cfg)
    res = PixieSolver(sim.capture, progress=lambda m: None).auto(
        modes=[prngs.ECOS_SIMPLEST], ec_limit=seed + 1)
    assert res.found and res.pin == "11111115"
    assert res.mode == "ecos-simplest"


def test_roundtrip_ecos_knuth_explicit():
    seed = 0x00F00D5E
    cfg = ApConfig(pin="00000000", prng_mode="ecos-knuth", seed=seed)
    sim = simulated_capture(cfg)
    res = PixieSolver(sim.capture, progress=lambda m: None).auto(
        modes=[prngs.ECOS_KNUTH], ec_limit=seed + 1)
    assert res.found and res.pin == "00000000"
    assert res.mode == "ecos-knuth"


# ---------------------------------------------------------------------------
# Negative controls
# ---------------------------------------------------------------------------

def test_secure_random_nonces_not_found():
    cfg = ApConfig(pin="12345670", prng_mode="random", seed=1,
                   use_rtl_fixed_key=False)
    res, _ = _solve(cfg)
    assert not res.found


def test_incomplete_capture_raises():
    from wps_attack.wps import Capture
    import secrets
    cap = Capture(
        pke=secrets.token_bytes(192), pkr=secrets.token_bytes(192),
        ehash1=secrets.token_bytes(32), ehash2=secrets.token_bytes(32),
        enonce=secrets.token_bytes(16), authkey=secrets.token_bytes(32))
    cap.ehash1 = cap.ehash1[:16]  # truncate
    with pytest.raises(ValueError):
        PixieSolver(cap)


def test_rtl819x_seed_outside_range_reports_not_found():
    # seed 2 days in the past: outside the default +/-1 day window
    cfg = ApConfig(pin="12345670", prng_mode="rtl819x",
                   seed=int(time.time()) - 2 * 86400)
    res, _ = _solve(cfg)
    assert not res.found
    # but explicit range finds it
    sim = simulated_capture(cfg)
    res2 = PixieSolver(sim.capture, progress=lambda m: None).auto(
        modes=[prngs.RTL819x],
        rtl_start=int(time.time()) - 86400,
        rtl_end=int(time.time()) - 3 * 86400)
    assert res2.found and res2.pin == "12345670"
