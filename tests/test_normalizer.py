"""Tests for packet normalization and secret redaction."""

import base64
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from pcapsentinel.normalizer import canonicalize_tcp_flags, normalize_packet


def test_canonicalize_tcp_flags():
    # SYN (0x02)
    assert canonicalize_tcp_flags(0x02) == "S"
    # SYN-ACK (0x12)
    assert canonicalize_tcp_flags(0x12) == "SA"
    # FIN (0x01)
    assert canonicalize_tcp_flags(0x01) == "F"
    # NULL (0x00)
    assert canonicalize_tcp_flags(0x00) == ""
    # Xmas: FIN (0x01) + PSH (0x08) + URG (0x20) = 0x29
    assert canonicalize_tcp_flags(0x29) == "FPU"
    # None
    assert canonicalize_tcp_flags(None) == ""


def test_normalize_tcp_packet():
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
          IP(src="10.0.0.5", dst="10.0.0.1") / \
          TCP(sport=44321, dport=80, flags="S")

    ev = normalize_packet(pkt)
    assert ev.proto == "TCP"
    assert ev.src_ip == "10.0.0.5"
    assert ev.dst_ip == "10.0.0.1"
    assert ev.src_mac == "00:11:22:33:44:55"
    assert ev.dst_mac == "66:77:88:99:aa:bb"
    assert ev.src_port == 44321
    assert ev.dst_port == 80
    assert ev.tcp_flags == "S"


def test_normalize_http_basic_auth_redaction():
    # Construct an HTTP request with Basic authorization
    raw_creds = "admin:supersecretpassword123"
    b64_creds = base64.b64encode(raw_creds.encode()).decode()
    http_payload = f"GET /secret HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic {b64_creds}\r\n\r\n"

    pkt = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=50000, dport=80) / Raw(load=http_payload)
    ev = normalize_packet(pkt)

    assert "http_auth" in ev.app
    auth = ev.app["http_auth"]
    assert auth["username"] == "admin"
    assert auth["password"] == "***REDACTED***"
    assert "supersecretpassword123" not in str(ev)


def test_normalize_ftp_credentials_redaction():
    # FTP USER command
    user_pkt = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=50000, dport=21) / Raw(load="USER anonymous\r\n")
    user_ev = normalize_packet(user_pkt)
    assert user_ev.app["ftp_cmd"] == {"cmd": "USER", "arg": "anonymous"}

    # FTP PASS command
    pass_pkt = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=50000, dport=21) / Raw(load="PASS topsecret999\r\n")
    pass_ev = normalize_packet(pass_pkt)
    assert pass_ev.app["ftp_cmd"] == {"cmd": "PASS", "arg": "***REDACTED***"}
    assert "topsecret999" not in str(pass_ev)


def test_normalize_dns_packet():
    pkt = Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=53000, dport=53) / \
          DNS(rd=1, qd=DNSQR(qname="test.example.com", qtype=16))

    ev = normalize_packet(pkt)
    assert ev.proto == "UDP"
    assert "dns" in ev.app
    assert ev.app["dns"]["qname"] == "test.example.com"
    assert ev.app["dns"]["qtype"] == 16


def test_normalize_arp_packet():
    pkt = Ether(src="aa:bb:cc:dd:ee:ff") / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1", pdst="192.168.1.100")
    ev = normalize_packet(pkt)
    assert ev.proto == "ARP"
    assert ev.src_ip == "192.168.1.1"
    assert "arp" in ev.app
    assert ev.app["arp"]["op"] == 2
    assert ev.app["arp"]["hwsrc"] == "aa:bb:cc:dd:ee:ff"
