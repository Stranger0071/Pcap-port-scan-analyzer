"""Tests for ARPSpoofDetector."""

from pcapsentinel.detectors.arp_spoof import ARPSpoofDetector
from pcapsentinel.models import PacketEvent, Severity


def make_arp_event(ts: float, hwsrc: str, psrc: str, is_gratuitous: bool = False, op: int = 2) -> PacketEvent:
    return PacketEvent(
        ts=ts,
        src_ip=psrc,
        dst_ip="192.168.1.100",
        src_mac=hwsrc,
        dst_mac="ff:ff:ff:ff:ff:ff",
        proto="ARP",
        src_port=None,
        dst_port=None,
        tcp_flags=None,
        length=42,
        app={
            "arp": {
                "op": op,
                "hwsrc": hwsrc,
                "psrc": psrc,
                "hwdst": "ff:ff:ff:ff:ff:ff",
                "pdst": "192.168.1.100",
                "is_gratuitous": is_gratuitous,
            }
        },
    )


def test_arp_spoofing_detection():
    detector = ARPSpoofDetector({})

    # 1. Normal ARP: 192.168.1.1 is at legitimate MAC 00:11:22:33:44:55
    ev1 = make_arp_event(100.0, "00:11:22:33:44:55", "192.168.1.1")
    alerts1 = detector.process(ev1)
    assert len(alerts1) == 0

    # 2. Rogue ARP: 192.168.1.1 claimed by attacker MAC aa:bb:cc:dd:ee:ff
    ev2 = make_arp_event(102.0, "aa:bb:cc:dd:ee:ff", "192.168.1.1")
    alerts2 = detector.process(ev2)
    assert len(alerts2) == 1

    alert = alerts2[0]
    assert alert.detector == "arp_spoof"
    assert alert.severity == Severity.HIGH
    assert alert.score == 0.95
    assert alert.src == "aa:bb:cc:dd:ee:ff"
    assert alert.dst == "192.168.1.1"
    assert alert.evidence["victim_ip"] == "192.168.1.1"
    assert alert.evidence["original_mac"] == "00:11:22:33:44:55"
    assert alert.evidence["spoofed_mac"] == "aa:bb:cc:dd:ee:ff"
    assert alert.evidence["change_type"] == "mac_binding_conflict"


def test_gratuitous_arp_override():
    detector = ARPSpoofDetector({})

    ev1 = make_arp_event(10.0, "00:00:00:00:00:01", "10.0.0.1")
    assert len(detector.process(ev1)) == 0

    # Gratuitous ARP reply overriding the binding
    ev2 = make_arp_event(12.0, "00:00:00:00:00:99", "10.0.0.1", is_gratuitous=True)
    alerts = detector.process(ev2)
    assert len(alerts) == 1
    assert alerts[0].evidence["change_type"] == "gratuitous_arp_override"
    assert alerts[0].evidence["is_gratuitous"] is True


def test_arp_allowlist_mac():
    cfg = {
        "arp_spoof": {
            "allowlist_macs": ["00:50:56:00:00:01"],
        }
    }
    detector = ARPSpoofDetector(cfg)

    # Initial mapping with another MAC
    ev1 = make_arp_event(1.0, "11:22:33:44:55:66", "192.168.1.254")
    detector.process(ev1)

    # Allowlisted MAC claims the IP -> should be ignored
    ev2 = make_arp_event(2.0, "00:50:56:00:00:01", "192.168.1.254")
    alerts = detector.process(ev2)
    assert len(alerts) == 0


def test_arp_idle_eviction():
    detector = ARPSpoofDetector({})

    ev1 = make_arp_event(10.0, "00:11:22:33:44:55", "192.168.1.1")
    detector.process(ev1)
    assert "192.168.1.1" in detector.ip_mac_table

    # Evict at ts=350 with ttl=300 (cutoff 50 > 10)
    detector.evict_idle(current_ts=350.0, ttl_seconds=300.0)
    assert "192.168.1.1" not in detector.ip_mac_table
