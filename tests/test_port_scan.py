"""Tests for PortScanDetector."""

from pcapsentinel.detectors.port_scan import PortScanDetector
from pcapsentinel.models import PacketEvent, Severity


def make_tcp_event(ts: float, src_ip: str, dst_ip: str, dst_port: int, flags: str) -> PacketEvent:
    return PacketEvent(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        proto="TCP",
        src_port=50000 + (dst_port % 1000),
        dst_port=dst_port,
        tcp_flags=flags,
        length=54,
    )


def test_syn_port_scan_detection():
    cfg = {
        "port_scan": {
            "min_distinct_ports": 15,
            "window_seconds": 10.0,
            "slow_window_seconds": 300.0,
            "slow_min_distinct_ports": 30,
        }
    }
    detector = PortScanDetector(cfg)

    alerts = []
    # Send 20 SYN packets to distinct ports within 2 seconds
    for i in range(20):
        ev = make_tcp_event(
            ts=100.0 + (i * 0.1),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            dst_port=1000 + i,
            flags="S",
        )
        new_alerts = detector.process(ev)
        alerts.extend(new_alerts)

    assert len(alerts) >= 1
    first_alert = alerts[0]
    assert first_alert.detector == "port_scan"
    assert first_alert.src == "192.168.1.100"
    assert first_alert.evidence["scan_type"] == "syn"
    assert first_alert.evidence["distinct_ports_count"] >= 15
    assert first_alert.severity in (Severity.MEDIUM, Severity.HIGH)


def test_fin_port_scan_detection():
    cfg = {
        "port_scan": {
            "min_distinct_ports": 10,
            "window_seconds": 10.0,
        }
    }
    detector = PortScanDetector(cfg)

    alerts = []
    for i in range(12):
        ev = make_tcp_event(
            ts=200.0 + (i * 0.2),
            src_ip="10.0.0.50",
            dst_ip="10.0.0.1",
            dst_port=2000 + i,
            flags="F",
        )
        alerts.extend(detector.process(ev))

    assert len(alerts) >= 1
    assert alerts[0].evidence["scan_type"] == "fin"


def test_null_port_scan_detection():
    cfg = {
        "port_scan": {
            "min_distinct_ports": 10,
            "window_seconds": 10.0,
        }
    }
    detector = PortScanDetector(cfg)

    alerts = []
    for i in range(12):
        ev = make_tcp_event(
            ts=300.0 + (i * 0.2),
            src_ip="10.0.0.60",
            dst_ip="10.0.0.1",
            dst_port=3000 + i,
            flags="",  # NULL scan
        )
        alerts.extend(detector.process(ev))

    assert len(alerts) >= 1
    assert alerts[0].evidence["scan_type"] == "null"


def test_xmas_port_scan_detection():
    cfg = {
        "port_scan": {
            "min_distinct_ports": 10,
            "window_seconds": 10.0,
        }
    }
    detector = PortScanDetector(cfg)

    alerts = []
    for i in range(12):
        ev = make_tcp_event(
            ts=400.0 + (i * 0.2),
            src_ip="10.0.0.70",
            dst_ip="10.0.0.1",
            dst_port=4000 + i,
            flags="FPU",  # Xmas scan
        )
        alerts.extend(detector.process(ev))

    assert len(alerts) >= 1
    assert alerts[0].evidence["scan_type"] == "xmas"


def test_benign_traffic_no_alert():
    cfg = {
        "port_scan": {
            "min_distinct_ports": 10,
            "window_seconds": 10.0,
        }
    }
    detector = PortScanDetector(cfg)

    alerts = []
    # Regular web browsing to ports 80 and 443 multiple times
    for i in range(50):
        ev = make_tcp_event(
            ts=500.0 + (i * 0.1),
            src_ip="192.168.1.5",
            dst_ip="93.184.216.34",
            dst_port=80 if i % 2 == 0 else 443,
            flags="S",
        )
        alerts.extend(detector.process(ev))

    assert len(alerts) == 0


def test_slow_port_scan_detection():
    cfg = {
        "port_scan": {
            "min_distinct_ports": 15,
            "window_seconds": 5.0,
            "slow_window_seconds": 60.0,
            "slow_min_distinct_ports": 10,
        }
    }
    detector = PortScanDetector(cfg)

    alerts = []
    # Send 12 probes separated by 2 seconds each (24 seconds total)
    # This will never trip the 5s fast window (at most 3 ports per 5s)
    # but trips the 60s slow window
    for i in range(12):
        ev = make_tcp_event(
            ts=1000.0 + (i * 2.0),
            src_ip="192.168.1.99",
            dst_ip="192.168.1.1",
            dst_port=8000 + i,
            flags="S",
        )
        alerts.extend(detector.process(ev))

    assert len(alerts) >= 1
    assert "slow_" in alerts[0].evidence["scan_type"]
