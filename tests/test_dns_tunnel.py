"""Tests for DNSTunnelDetector and Shannon entropy calculations."""

from pcapsentinel.detectors.dns_tunnel import DNSTunnelDetector, extract_parent_domain, shannon_entropy
from pcapsentinel.models import PacketEvent, Severity


def make_dns_event(ts: float, src_ip: str, qname: str, qtype: int = 1) -> PacketEvent:
    return PacketEvent(
        ts=ts,
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        proto="UDP",
        src_port=53535,
        dst_port=53,
        tcp_flags=None,
        length=75,
        app={
            "dns": {
                "qr": 0,  # Query
                "qname": qname,
                "qtype": qtype,
            }
        },
    )


def test_shannon_entropy():
    # Empty string
    assert shannon_entropy("") == 0.0

    # Low entropy: regular english dictionary words
    low_entropy = shannon_entropy("google")
    assert low_entropy < 2.5

    # High entropy: random alphanumeric / hex string (dnscat2 payload)
    high_entropy = shannon_entropy("a8f3d9b1c7e42f60ab5e9d3c")
    assert high_entropy > 3.5


def test_extract_parent_domain():
    assert extract_parent_domain("example.com") == "example.com"
    assert extract_parent_domain("foo.example.com") == "example.com"
    assert extract_parent_domain("data.tunnel.exfil.org") == "exfil.org"


def test_single_query_high_entropy_long_label():
    cfg = {
        "dns_tunnel": {
            "max_label_length": 30,
            "min_entropy": 3.5,
        }
    }
    detector = DNSTunnelDetector(cfg)

    # Label with 36 random characters and high entropy
    payload = "d9f8a3c2b1e74f0a9c8b7e6d5a4f3b2c1e0d"
    qname = f"{payload}.tunnel.evil.com"
    ev = make_dns_event(100.0, "10.0.0.15", qname, qtype=16)  # TXT record

    alerts = detector.process(ev)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "dns_tunnel"
    assert alert.src == "10.0.0.15"
    assert alert.evidence["parent_domain"] == "evil.com"
    assert alert.evidence["single_query_trip"] is True
    assert alert.evidence["max_label_length"] >= 30
    assert alert.evidence["max_entropy"] >= 3.5


def test_volume_subdomain_tunneling():
    cfg = {
        "dns_tunnel": {
            "min_unique_subdomains": 15,
            "min_entropy": 4.5,
            "window_seconds": 60.0,
        }
    }
    detector = DNSTunnelDetector(cfg)

    alerts = []
    # Emit 20 unique subdomains with randomized hex chunks
    for i in range(20):
        hex_token = f"chunk{i:04x}abcdef12345"
        qname = f"{hex_token}.exfiltration.net"
        ev = make_dns_event(200.0 + i, "192.168.1.80", qname)
        alerts.extend(detector.process(ev))

    assert len(alerts) >= 1
    first_alert = alerts[0]
    assert first_alert.detector == "dns_tunnel"
    assert first_alert.evidence["parent_domain"] == "exfiltration.net"
    assert first_alert.evidence["unique_subdomains_count"] >= 15


def test_domain_allowlist():
    cfg = {
        "dns_tunnel": {
            "max_label_length": 20,
            "min_entropy": 2.5,
            "domain_allowlist": ["akadns.net", "cloudflaressl.com"],
        }
    }
    detector = DNSTunnelDetector(cfg)

    # Query to allowlisted domain
    qname = "a1b2c3d4e5f6g7h8i9j0.cloudflaressl.com"
    ev = make_dns_event(10.0, "10.0.0.5", qname)
    alerts = detector.process(ev)
    assert len(alerts) == 0


def test_benign_dns_traffic():
    detector = DNSTunnelDetector({})

    normal_queries = [
        "google.com",
        "www.google.com",
        "mail.google.com",
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
    ]

    alerts = []
    for i, q in enumerate(normal_queries):
        ev = make_dns_event(100.0 + i, "10.0.0.5", q)
        alerts.extend(detector.process(ev))

    assert len(alerts) == 0
