"""Utility to generate synthetic pcap captures for unit/integration tests and demonstrations."""

from pathlib import Path
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.utils import wrpcap


def generate_all_fixtures(target_dir: str | Path) -> dict[str, Path]:
    dest = Path(target_dir)
    dest.mkdir(parents=True, exist_ok=True)

    files = {}
    base_ts = 1700000000.0

    # 1. SYN Scan Capture
    syn_pkts = []
    for i in range(25):
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
              IP(src="192.168.56.10", dst="192.168.56.20") / \
              TCP(sport=40000 + i, dport=1000 + i, flags="S")
        pkt.time = base_ts + (i * 0.05)
        syn_pkts.append(pkt)
    syn_file = dest / "syn_scan.pcap"
    wrpcap(str(syn_file), syn_pkts)
    files["syn_scan"] = syn_file

    # 2. Xmas Scan Capture
    xmas_pkts = []
    for i in range(25):
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
              IP(src="192.168.56.15", dst="192.168.56.20") / \
              TCP(sport=50000 + i, dport=2000 + i, flags="FPU")
        pkt.time = base_ts + (i * 0.05)
        xmas_pkts.append(pkt)
    xmas_file = dest / "xmas_scan.pcap"
    wrpcap(str(xmas_file), xmas_pkts)
    files["xmas_scan"] = xmas_file

    # 3. Cleartext Credentials (HTTP Basic Auth & FTP Login)
    cred_pkts = []
    http_payload = (
        "POST /login HTTP/1.1\r\n"
        "Host: auth.internal\r\n"
        "Authorization: Basic YWRtaW46c3VwZXJzZWNyZXRwYXNz\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    p1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
         IP(src="192.168.56.30", dst="192.168.56.40") / \
         TCP(sport=49152, dport=80, flags="PA") / Raw(load=http_payload)
    p1.time = base_ts + 1.0
    cred_pkts.append(p1)

    p2 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
         IP(src="192.168.56.30", dst="192.168.56.50") / \
         TCP(sport=49153, dport=21, flags="PA") / Raw(load="USER dev\r\n")
    p2.time = base_ts + 2.0
    cred_pkts.append(p2)

    p3 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
         IP(src="192.168.56.30", dst="192.168.56.50") / \
         TCP(sport=49153, dport=21, flags="PA") / Raw(load="PASS secretftp99\r\n")
    p3.time = base_ts + 2.5
    cred_pkts.append(p3)

    cred_file = dest / "cleartext_creds.pcap"
    wrpcap(str(cred_file), cred_pkts)
    files["cleartext_creds"] = cred_file

    # 4. Benign Capture (repeated HTTP requests to ports 80/443 without alerts)
    benign_pkts = []
    for i in range(20):
        pkt_req = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                  IP(src="192.168.56.5", dst="93.184.216.34") / \
                  TCP(sport=35000, dport=80 if i % 2 == 0 else 443, flags="PA") / \
                  Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        pkt_req.time = base_ts + (i * 0.5)
        benign_pkts.append(pkt_req)

        pkt_res = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / \
                  IP(src="93.184.216.34", dst="192.168.56.5") / \
                  TCP(sport=80 if i % 2 == 0 else 443, dport=35000, flags="PA") / \
                  Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
        pkt_res.time = base_ts + (i * 0.5) + 0.05
        benign_pkts.append(pkt_res)

    benign_file = dest / "benign.pcap"
    wrpcap(str(benign_file), benign_pkts)
    files["benign"] = benign_file

    # 5. ARP Spoofing Capture
    arp_pkts = []
    # Legitimate mapping: 192.168.56.1 is at 00:50:56:c0:00:01
    legit_arp = Ether(src="00:50:56:c0:00:01", dst="ff:ff:ff:ff:ff:ff") / \
                ARP(op=2, hwsrc="00:50:56:c0:00:01", psrc="192.168.56.1",
                    hwdst="00:11:22:33:44:55", pdst="192.168.56.10")
    legit_arp.time = base_ts + 1.0
    arp_pkts.append(legit_arp)

    # Rogue spoofed reply: 192.168.56.1 is claimed by attacker 00:0c:29:ab:cd:ef
    rogue_arp = Ether(src="00:0c:29:ab:cd:ef", dst="00:11:22:33:44:55") / \
                ARP(op=2, hwsrc="00:0c:29:ab:cd:ef", psrc="192.168.56.1",
                    hwdst="00:11:22:33:44:55", pdst="192.168.56.10")
    rogue_arp.time = base_ts + 3.0
    arp_pkts.append(rogue_arp)

    arp_file = dest / "arp_spoof.pcap"
    wrpcap(str(arp_file), arp_pkts)
    files["arp_spoof"] = arp_file

    # 6. DNS Tunneling Capture
    dns_pkts = []
    # Simulate high-entropy encoded chunks queried under tunnel.exfil.org
    tokens = [
        "a9f4c3d2e1b80f7e6a5d4c3b2a1e0f9d8c7b",
        "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
        "c8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1",
        "d2f3a4b5c6e7f8a9b0c1d2e3f4a5b6c7d8e9",
        "e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
        "f3b2a1e0f9d8c7b6a5d4c3b2a1e0f9d8c7b6",
        "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f",
        "1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a",
        "2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f",
        "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
        "4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f",
        "5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a",
    ]
    for i, token in enumerate(tokens):
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
              IP(src="192.168.56.99", dst="8.8.8.8") / \
              UDP(sport=50000 + i, dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=f"{token}.tunnel.exfil.org", qtype=16))
        pkt.time = base_ts + (i * 0.2)
        dns_pkts.append(pkt)

    dns_file = dest / "dns_tunnel.pcap"
    wrpcap(str(dns_file), dns_pkts)
    files["dns_tunnel"] = dns_file

    return files


if __name__ == "__main__":
    generated = generate_all_fixtures(Path(__file__).parent)
    for name, path in generated.items():
        print(f"Generated fixture: {name} -> {path}")
