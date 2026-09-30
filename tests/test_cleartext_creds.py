"""Tests for CleartextCredsDetector."""

from pcapsentinel.detectors.cleartext_creds import CleartextCredsDetector
from pcapsentinel.models import PacketEvent, Severity


def test_http_basic_auth_detection():
    detector = CleartextCredsDetector({})

    ev = PacketEvent(
        ts=100.0,
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        src_mac=None,
        dst_mac=None,
        proto="TCP",
        src_port=49152,
        dst_port=80,
        tcp_flags="PA",
        length=200,
        app={
            "http_auth": {
                "username": "superadmin",
                "password": "***REDACTED***",
            }
        },
    )

    alerts = detector.process(ev)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "cleartext_creds"
    assert alert.src == "192.168.1.50"
    assert alert.dst == "192.168.1.1"
    assert alert.severity >= Severity.MEDIUM
    assert alert.score == 1.0
    assert alert.evidence["protocol"] == "HTTP"
    assert alert.evidence["username"] == "superadmin"
    assert alert.evidence["password"] == "***REDACTED***"


def test_ftp_credentials_detection():
    detector = CleartextCredsDetector({})

    # 1. USER command packet
    ev_user = PacketEvent(
        ts=150.0,
        src_ip="10.0.0.25",
        dst_ip="10.0.0.1",
        src_mac=None,
        dst_mac=None,
        proto="TCP",
        src_port=50001,
        dst_port=21,
        tcp_flags="PA",
        length=70,
        app={"ftp_cmd": {"cmd": "USER", "arg": "ftpuser"}},
    )
    alerts1 = detector.process(ev_user)
    assert len(alerts1) == 0  # Wait for PASS command

    # 2. PASS command packet
    ev_pass = PacketEvent(
        ts=151.0,
        src_ip="10.0.0.25",
        dst_ip="10.0.0.1",
        src_mac=None,
        dst_mac=None,
        proto="TCP",
        src_port=50001,
        dst_port=21,
        tcp_flags="PA",
        length=80,
        app={"ftp_cmd": {"cmd": "PASS", "arg": "***REDACTED***"}},
    )
    alerts2 = detector.process(ev_pass)
    assert len(alerts2) == 1
    alert = alerts2[0]
    assert alert.detector == "cleartext_creds"
    assert alert.evidence["protocol"] == "FTP"
    assert alert.evidence["username"] == "ftpuser"
    assert alert.evidence["password"] == "***REDACTED***"


def test_disabled_detector():
    detector = CleartextCredsDetector({"cleartext_creds": {"enabled": False}})
    ev = PacketEvent(
        ts=100.0,
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        src_mac=None,
        dst_mac=None,
        proto="TCP",
        src_port=49152,
        dst_port=80,
        tcp_flags="PA",
        length=200,
        app={"http_auth": {"username": "admin", "password": "***REDACTED***"}},
    )
    alerts = detector.process(ev)
    assert len(alerts) == 0
