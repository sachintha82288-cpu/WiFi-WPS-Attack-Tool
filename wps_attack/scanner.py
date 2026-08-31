"""WPS access-point discovery.

Live scanning shells out to ``wash`` (aircrack-ng suite) on a
monitor-mode interface; saved wash output can also be parsed from a file.
Both paths produce the same :class:`ApRecord` list, which the analyzer
turns into a risk assessment.

wash output format (one line per AP, columnar)::

    BSSID           Channel WPS Locked PIN          R    #    Signal  UUID  SSID
    00:11:22:33:44:55 6     Y   N    12345670       1    0   -50 dBm  ...  CoffeeShop
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

__all__ = ["ApRecord", "wash_available", "run_wash", "parse_wash_output",
           "scan"]

_MAC_RE = re.compile(
    r"^\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"
    r"(\d+)\s+"                      # channel
    r"([YN])\s+"                     # WPS
    r"([YN])\s+"                     # Locked
    r"(\S{0,10})\s+"                 # PIN (may be empty / "-")
    r"(\d+)\s+"                      # retries (R)
    r"(\d+)\s+"                      # attempts (#)
    r"(-?\d+\s*dBm)\s+"              # signal
    r"([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{12})\s*"  # UUID (RFC 4122 8-4-4-4-12)
    r"(.*\S)?\s*$"                   # SSID (optional)
)


@dataclass
class ApRecord:
    """One WPS-capable AP as reported by wash."""

    bssid: str
    channel: int
    wps: bool
    locked: bool
    pin: Optional[str] = None        # PIN advertised/knowable, if any
    retries: int = 0
    attempts: int = 0
    signal_dbm: int = 0
    uuid: str = ""
    ssid: str = ""
    source: str = "wash"             # 'wash' | filename | 'manual'

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid, "channel": self.channel,
            "wps": self.wps, "locked": self.locked, "pin": self.pin,
            "retries": self.retries, "attempts": self.attempts,
            "signal_dbm": self.signal_dbm, "uuid": self.uuid,
            "ssid": self.ssid, "source": self.source,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ApRecord":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


def wash_available() -> bool:
    return shutil.which("wash") is not None


def parse_wash_output(text: str, source: str = "wash") -> list[ApRecord]:
    """Parse wash's columnar output into ApRecord objects."""
    records = []
    for line in text.splitlines():
        m = _MAC_RE.match(line)
        if not m:
            continue
        (bssid, channel, wps, locked, pin, retries, attempts, signal,
         uuid, ssid) = m.groups()
        records.append(ApRecord(
            bssid=bssid.upper(),
            channel=int(channel),
            wps=(wps == "Y"),
            locked=(locked == "Y"),
            pin=None if pin in ("", "-") else pin,
            retries=int(retries),
            attempts=int(attempts),
            signal_dbm=int(signal.split()[0]),
            uuid=uuid,
            ssid=(ssid or "").strip(),
            source=source,
        ))
    return records


def run_wash(iface: str, timeout: int = 15, wash_bin: Optional[str] = None):
    """Run wash on the interface; returns (records, raw_output)."""
    if not wash_available():
        raise RuntimeError(
            "wash not found. Install aircrack-ng (provides wash) or parse "
            "a saved wash file with --wash-file")
    wash_bin = wash_bin or "wash"
    cmd = [wash_bin, "-i", iface, "--retries", "1"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 5)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"wash timed out after {timeout}s on {iface}") from exc
    raw = (proc.stdout or "") + (proc.stderr or "")
    return parse_wash_output(raw, source=f"wash -i {iface}"), raw


def scan(iface: Optional[str] = None, wash_file: Optional[str] = None,
         timeout: int = 15, manual: Optional[list[dict]] = None
         ) -> list[ApRecord]:
    """Discover WPS APs.  Exactly one of iface / wash_file / manual."""
    if wash_file:
        with open(wash_file, "r", encoding="utf-8", errors="replace") as fh:
            return parse_wash_output(fh.read(), source=wash_file)
    if manual:
        return [ApRecord(source="manual", **m) for m in manual]
    if iface:
        records, _raw = run_wash(iface, timeout=timeout)
        return records
    raise ValueError("provide --iface, --wash-file or manual records")
