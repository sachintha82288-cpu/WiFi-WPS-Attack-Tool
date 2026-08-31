"""WiFi WPS Attack & Security Analysis Tool.

A security-testing toolkit for analysing and attacking Wi-Fi Protected Setup
(WPS) in an *authorized* penetration-test context:

* Offline WPS PIN recovery (Pixie Dust / pixiewps algorithm, pure Python)
* WPS AP discovery (wash integration + output parsing)
* Live WPS attack orchestration (reaver integration: pixie-dust + brute force)
* WPS configuration risk analysis and reporting

Only use against networks you own or have explicit written permission to
test. Unauthorised access to computer networks is illegal in most
jurisdictions.
"""

__version__ = "1.0.0"
__author__ = "WiFi-WPS-Attack-Tool contributors"

__all__ = [
    "__version__",
    "analyzer",
    "cli",
    "crypto",
    "pixiedust",
    "prngs",
    "reaver_ctl",
    "report",
    "scanner",
    "selftest",
    "simulator",
    "state",
    "wps",
]
