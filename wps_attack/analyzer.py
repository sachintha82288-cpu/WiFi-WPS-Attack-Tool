"""WPS security risk analysis.

Turns scan records and attack/capture outcomes into a scored,
remediation-ready assessment.  The scoring model is deliberately simple
and transparent: each applicable finding adds a weight; mitigations
subtract.  Total score maps to a rating:

    >= 80  CRITICAL      WPS PIN effectively recoverable
    >= 55  HIGH          strong offline/online attack paths open
    >= 30  MEDIUM        attack feasible with effort / partial mitigations
    >   0  LOW           minor exposure
    == 0   NONE          no WPS exposure detected
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .scanner import ApRecord
from .wps import COMMON_PINS, wps_pin_valid

__all__ = ["Finding", "Assessment", "analyze_ap", "score_rating",
           "bruteforce_eta"]

# (id, title, severity, weight)
_F = {
    "WPS_ENABLED":        ("WPS protocol enabled",            "MEDIUM",  15),
    "PIN_ADVERTISED":     ("WPS PIN advertised/known",        "CRITICAL", 40),
    "PIN_DEFAULT":        ("WPS PIN is a known default",      "HIGH",     25),
    "PIXIE_DUST":         ("Pixie-dust vulnerable (rekey off / pxD success)", "CRITICAL", 35),
    "LOCKOUT_OFF":        ("No WPS lockout (brute force unimpeded)", "HIGH", 20),
    "PIN_WEAK":           ("Low-entropy / predictable WPS PIN", "MEDIUM", 15),
    "REKEY_ON":           ("Rekey present (mitigates pixie dust)", "INFO", -15),
    "WPS_LOCKED":         ("WPS currently locked (temporary mitigation)", "INFO", -5),
    "WPS_V2_RRSK":        ("WPS 2.0 / RRSK in use (mitigates offline PIN)", "INFO", -10),
}

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class Finding:
    fid: str
    title: str
    severity: str
    weight: int
    detail: str = ""
    evidence: list = field(default_factory=list)
    remediation: str = ""


def score_rating(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def bruteforce_eta(pin_length: int = 8, per_attempt_sec: float = 1.0,
                   lockout_every: int = 10, lockout_sec: float = 300.0
                   ) -> tuple[float, str]:
    """Estimate online brute-force time for a WPS PIN.

    8-digit WPS PINs have 10^7 valid values (check digit).  ``per_attempt_sec``
    is the average seconds per attempt (reaver is ~1-2 s/attempt on typical
    APs); ``lockout_every``/``lockout_sec`` model a lockout after N bad
    attempts.  Returns (seconds, human-readable).
    """
    attempts = 10 ** (pin_length - 1)
    total = attempts * per_attempt_sec
    if lockout_every > 1:
        total += (attempts / lockout_every) * lockout_sec
    days = total / 86400
    if days >= 1:
        human = f"~{days:.0f} days ({days / 365:.1f} years)"
    else:
        human = f"~{total / 3600:.1f} hours"
    return total, human


@dataclass
class Assessment:
    bssid: str
    ssid: str
    assessed_at: str
    findings: list
    score: int
    rating: str
    eta: Optional[tuple] = None
    pin: Optional[str] = None
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "assessed_at": self.assessed_at,
            "score": self.score,
            "rating": self.rating,
            "pin": self.pin,
            "eta_seconds": self.eta[0] if self.eta else None,
            "eta_human": self.eta[1] if self.eta else None,
            "findings": [
                {
                    "id": f.fid, "title": f.title, "severity": f.severity,
                    "weight": f.weight, "detail": f.detail,
                    "evidence": f.evidence, "remediation": f.remediation,
                } for f in self.findings
            ],
            "notes": self.notes,
        }


def analyze_ap(ap: Optional[ApRecord] = None,
               pin: Optional[str] = None,
               pixie_success: bool = False,
               rekey: Optional[bool] = None,
               wps_version: Optional[str] = None,
               rrsk: bool = False,
               pin_length: int = 8) -> Assessment:
    """Build an Assessment from any combination of evidence.

    ``ap``      — scan record (WPS flag, lockout state, advertised PIN)
    ``pin``     — a PIN known/recovered (strongest possible evidence)
    ``pixie_success`` — a pixie-dust attack succeeded against this AP
    ``rekey``   — rekey observed (True/False); None = unknown
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())
    findings: list[Finding] = []
    notes: list[str] = []
    score = 0

    def add(fid: str, detail: str = "", evidence: Optional[list] = None,
            remediation: str = ""):
        title, severity, weight = _F[fid]
        findings.append(Finding(fid, title, severity, weight, detail,
                                evidence or [], remediation))

    wps_on = True
    if ap is not None and not ap.wps:
        wps_on = False
        notes.append("AP does not advertise WPS - nothing to assess.")

    if pin is not None:
        if pin in COMMON_PINS:
            add("PIN_DEFAULT",
                f"Recovered/known PIN {pin} is a widely shipped factory "
                "default.",
                [f"pin={pin}"],
                "Change the WPS PIN immediately and disable WPS if "
                "possible.")
        else:
            notes.append(f"PIN {pin} recovered/known (not in the common "
                         "default list).")
        add("PIN_ADVERTISED" if (ap and ap.pin) else "PIN_WEAK",
            "The WPS PIN is known to an attacker; the WPA-PSK can be "
            "recovered by completing the WPS registrar exchange.",
            [f"pin={pin}"],
            "Disable WPS and rotate the network passphrase.")
    elif ap is not None and ap.pin:
        add("PIN_ADVERTISED",
            "wash reports the WPS PIN as known/advertised by the AP.",
            [f"advertised pin={ap.pin}"],
            "Disable WPS immediately.")

    if wps_on:
        add("WPS_ENABLED",
            "Wi-Fi Protected Setup is active on this AP.",
            [],
            "Disable WPS in the AP configuration; WPS PIN auth is "
            "structurally weaker than the WPA-PSK.")
        if ap is not None and not ap.locked and rekey is not True:
            add("LOCKOUT_OFF",
                "No lockout is currently reported; online brute force of "
                "the 10^7 valid PINs is unimpeded.",
                [],
                "Enable WPS lockout / rekey if the vendor supports it; "
                "preferably disable WPS.")
        if ap is not None and ap.locked:
            add("WPS_LOCKED",
                "WPS is currently locked (temporary rate-limit).",
                ["locked=Y in wash output"])
        if rekey is False or pixie_success:
            add("PIXIE_DUST",
                "The AP does not rekey (or a pixie-dust attack already "
                "succeeded): the PIN is recoverable offline from a "
                "single WPS exchange, typically in minutes.",
                ["rekey=no" if rekey is False else "pxd attack succeeded"],
                "Update the firmware (Ralink/Realtek/Broadcom pxD fixes) "
                "or disable WPS.")
        if rekey is True:
            add("REKEY_ON", "Rekey observed - mitigates offline PIN "
                "recovery via E-Hash analysis.")
        if wps_version is not None and wps_version.startswith("2"):
            add("WPS_V2_RRSK", "WPS 2.0 in use.")
        if rrsk:
            add("WPS_V2_RRSK", "Registrar Request Secure Connection "
                "(RRSK) enabled.")
        if pin is not None and pin_length == 8:
            if not wps_pin_valid(pin):
                notes.append("Recovered PIN fails the WPS checksum test "
                             "(non-conformant AP or parse issue).")

    if wps_on:
        for f in findings:
            score += f.weight
        eta, eta_human = bruteforce_eta(pin_length)
        eta_out = (eta, eta_human)
    else:
        eta_out = None

    return Assessment(
        bssid=ap.bssid if ap else "",
        ssid=(ap.ssid if ap else ""),
        assessed_at=now,
        findings=findings,
        score=max(0, score),
        rating=score_rating(score),
        eta=eta_out,
        pin=pin,
        notes=notes,
    )
