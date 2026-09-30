"""Normalizes raw Scapy packets into clean, redacted PacketEvent instances."""

import base64
import re
from typing import Any, Dict, Optional
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet, Raw

from pcapsentinel.models import PacketEvent

# Regex for HTTP Basic Authorization header
HTTP_BASIC_AUTH_RE = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
FTP_CMD_RE = re.compile(r"^(USER|PASS)\s+(.*)\r?\n?$", re.IGNORECASE)


def canonicalize_tcp_flags(flags_val: Any) -> str:
    """Canonicalize TCP flags to a predictable ordered string.

    Ordered as: F (FIN), S (SYN), R (RST), P (PSH), A (ACK), U (URG), E (ECE), C (CWR).
    NULL scan is represented by empty string "".
    """
    if flags_val is None:
        return ""

    flags_int = int(flags_val)
    flag_order = [
        (0x01, "F"),
        (0x02, "S"),
        (0x04, "R"),
        (0x08, "P"),
        (0x10, "A"),
        (0x20, "U"),
        (0x40, "E"),
        (0x80, "C"),
    ]
    result = []
    for bit, char in flag_order:
        if flags_int & bit:
            result.append(char)
    return "".join(result)


def parse_app_hints(packet: Packet, proto: str, src_port: Optional[int], dst_port: Optional[int]) -> Dict[str, Any]:
    """Parse application-layer hints with strict secret redaction at parse time."""
    app: Dict[str, Any] = {}

    # 1. DNS parsing
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        dns_info: Dict[str, Any] = {
            "qr": int(dns_layer.qr),  # 0 = query, 1 = response
            "opcode": int(dns_layer.opcode),
            "rcode": int(dns_layer.rcode),
        }
        if packet.haslayer(DNSQR):
            qname_raw = dns_layer[DNSQR].qname
            if isinstance(qname_raw, bytes):
                qname = qname_raw.decode("utf-8", errors="ignore").rstrip(".")
            else:
                qname = str(qname_raw).rstrip(".")
            dns_info["qname"] = qname
            dns_info["qtype"] = int(dns_layer[DNSQR].qtype)
        app["dns"] = dns_info

    # 2. ARP parsing
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        is_gratuitous = (
            arp_layer.op == 2 and (
                arp_layer.psrc == arp_layer.pdst or
                str(arp_layer.hwdst).lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
            )
        )
        app["arp"] = {
            "op": int(arp_layer.op),  # 1 = request, 2 = reply
            "hwsrc": str(arp_layer.hwsrc).lower() if arp_layer.hwsrc else None,
            "psrc": str(arp_layer.psrc) if arp_layer.psrc else None,
            "hwdst": str(arp_layer.hwdst).lower() if arp_layer.hwdst else None,
            "pdst": str(arp_layer.pdst) if arp_layer.pdst else None,
            "is_gratuitous": is_gratuitous,
        }

    # 3. Payload-based inspection for credentials (HTTP Basic & FTP)
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        payload_text = payload.decode("latin-1", errors="ignore")

        # Check HTTP Basic Auth (usually on TCP ports 80, 8080, 8000, or any plain HTTP)
        match_auth = HTTP_BASIC_AUTH_RE.search(payload_text)
        if match_auth:
            b64_creds = match_auth.group(1).strip()
            username = "unknown"
            try:
                decoded = base64.b64decode(b64_creds).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    username, _ = decoded.split(":", 1)
                else:
                    username = decoded
            except Exception:
                pass
            app["http_auth"] = {
                "username": username,
                "password": "***REDACTED***",
            }

        # Check FTP Command (port 21 or FTP command syntax)
        if src_port == 21 or dst_port == 21 or payload_text.startswith(("USER ", "PASS ", "user ", "pass ")):
            for line in payload_text.splitlines():
                match_ftp = FTP_CMD_RE.match(line)
                if match_ftp:
                    cmd = match_ftp.group(1).upper()
                    arg = match_ftp.group(2).strip()
                    if cmd == "PASS":
                        app["ftp_cmd"] = {
                            "cmd": "PASS",
                            "arg": "***REDACTED***",
                        }
                    else:
                        app["ftp_cmd"] = {
                            "cmd": cmd,
                            "arg": arg,
                        }

    return app


def normalize_packet(packet: Packet) -> PacketEvent:
    """Normalize a raw Scapy packet into a standardized PacketEvent."""
    ts = float(getattr(packet, "time", 0.0))
    length = len(packet)

    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    if packet.haslayer(Ether):
        src_mac = str(packet[Ether].src).lower() if packet[Ether].src else None
        dst_mac = str(packet[Ether].dst).lower() if packet[Ether].dst else None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    proto = "OTHER"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None

    if packet.haslayer(IP):
        src_ip = str(packet[IP].src)
        dst_ip = str(packet[IP].dst)
    elif packet.haslayer(IPv6):
        src_ip = str(packet[IPv6].src)
        dst_ip = str(packet[IPv6].dst)
    elif packet.haslayer(ARP):
        src_ip = str(packet[ARP].psrc) if packet[ARP].psrc else None
        dst_ip = str(packet[ARP].pdst) if packet[ARP].pdst else None
        if not src_mac and packet[ARP].hwsrc:
            src_mac = str(packet[ARP].hwsrc).lower()
        if not dst_mac and packet[ARP].hwdst:
            dst_mac = str(packet[ARP].hwdst).lower()
        proto = "ARP"

    if packet.haslayer(TCP):
        proto = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        tcp_flags = canonicalize_tcp_flags(packet[TCP].flags)
    elif packet.haslayer(UDP):
        proto = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        proto = "ICMP"

    app = parse_app_hints(packet, proto, src_port, dst_port)

    return PacketEvent(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac=src_mac,
        dst_mac=dst_mac,
        proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        length=length,
        app=app,
    )
