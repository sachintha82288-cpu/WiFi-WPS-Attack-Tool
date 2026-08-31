"""Scanner + analyzer tests (pytest)."""

from wps_attack.analyzer import analyze_ap, bruteforce_eta, score_rating
from wps_attack.scanner import ApRecord, parse_wash_output

SAMPLE = """\
    BSSID     Channel   WPS   Locked  Pin         R #     Signal      UUID    SSID
    00:11:22:33:44:55     6   Y       N       12345670      1 0     -50 dBm  462a72b6-6345-4111-a199-001122334455  CoffeeShop
    aa:bb:cc:dd:ee:ff     11  Y       Y       -             0 0     -70 dBm  462a72b6-6345-4111-a199-001122334455  LockedAP
    11:22:33:44:55:66     6   N       N       -             0 0     -80 dBm  462a72b6-6345-4111-a199-001122334455  NoWPS
"""


def test_parse_wash_output():
    aps = parse_wash_output(SAMPLE)
    assert len(aps) == 3
    a = aps[0]
    assert a.bssid == "00:11:22:33:44:55"
    assert a.channel == 6
    assert a.wps and not a.locked
    assert a.pin == "12345670"
    assert a.signal_dbm == -50
    assert a.ssid == "CoffeeShop"
    assert aps[1].locked and aps[1].pin is None
    assert not aps[2].wps


def test_ap_record_roundtrip():
    ap = ApRecord(bssid="AA:BB:CC:DD:EE:FF", channel=1, wps=True,
                  locked=False)
    d = ap.to_dict()
    assert ApRecord.from_dict(d) == ap


def test_analyzer_ratings():
    aps = parse_wash_output(SAMPLE)
    # known PIN + no lockout + pxD success -> CRITICAL
    a1 = analyze_ap(aps[0], pin="12345670", pixie_success=True, rekey=False)
    assert a1.rating == "CRITICAL"
    # WPS on, locked, nothing else -> LOW
    a2 = analyze_ap(aps[1])
    assert a2.rating in ("LOW", "MEDIUM")
    # no WPS at all -> NONE
    a3 = analyze_ap(aps[2])
    assert a3.rating == "NONE"


def test_analyzer_default_pin_flagged():
    aps = parse_wash_output(SAMPLE)
    a = analyze_ap(aps[0], pin="12345670")
    fids = {f.fid for f in a.findings}
    assert "PIN_DEFAULT" in fids
    assert "PIN_ADVERTISED" in fids


def test_bruteforce_eta_sane():
    eta, human = bruteforce_eta()
    assert eta > 10 ** 7  # > 10^7 seconds minimum
    assert "days" in human
    # lockouts make it slower, never faster
    eta_no_lock, _ = bruteforce_eta(lockout_every=0)
    assert eta >= eta_no_lock


def test_score_rating_boundaries():
    assert score_rating(0) == "NONE"
    assert score_rating(1) == "LOW"
    assert score_rating(30) == "MEDIUM"
    assert score_rating(55) == "HIGH"
    assert score_rating(80) == "CRITICAL"
