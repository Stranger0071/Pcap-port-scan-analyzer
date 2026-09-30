"""Tests for data models and configuration manager."""

import pytest
from pcapsentinel.models import Alert, PacketEvent, Severity
from pcapsentinel.config import load_config, DEFAULT_CONFIG


def test_severity_ordering():
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH > Severity.LOW
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.LOW <= Severity.MEDIUM


def test_packet_event_immutable():
    event = PacketEvent(
        ts=100.0,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        proto="TCP",
        src_port=12345,
        dst_port=80,
        tcp_flags="S",
        length=60,
    )
    assert event.ts == 100.0
    assert event.src_ip == "192.168.1.10"
    assert event.tcp_flags == "S"

    with pytest.raises(Exception):
        event.ts = 200.0  # dataclass is frozen


def test_alert_to_dict():
    alert = Alert(
        id="ALT-1001",
        detector="port_scan",
        severity=Severity.HIGH,
        src="192.168.1.50",
        dst="192.168.1.1",
        start_ts=10.0,
        end_ts=25.0,
        score=0.95,
        summary="SYN port scan detected",
        evidence={"distinct_ports": 50, "scan_type": "syn"},
    )
    d = alert.to_dict()
    assert d["id"] == "ALT-1001"
    assert d["detector"] == "port_scan"
    assert d["severity"] == "HIGH"
    assert d["duration_seconds"] == 15.0
    assert d["score"] == 0.95
    assert d["evidence"]["distinct_ports"] == 50


def test_load_config_defaults():
    cfg = load_config()
    assert cfg["window_seconds"] == 30
    assert cfg["port_scan"]["min_distinct_ports"] == 20
    assert cfg["port_scan"]["window_seconds"] == 10
    assert cfg["cleartext_creds"]["enabled"] is True


def test_load_config_overrides():
    overrides = {
        "port_scan": {
            "min_distinct_ports": 5,
        },
        "state_ttl_seconds": 120,
    }
    cfg = load_config(overrides=overrides)
    assert cfg["port_scan"]["min_distinct_ports"] == 5
    # deep merge preserved nested untouched fields:
    assert cfg["port_scan"]["window_seconds"] == 10
    assert cfg["state_ttl_seconds"] == 120
