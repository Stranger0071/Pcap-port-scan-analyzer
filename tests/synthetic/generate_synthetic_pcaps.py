"""Utility to generate synthetic pcap captures for unit/integration tests and demonstrations."""

from pathlib import Path
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
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
    # HTTP Basic: admin:supersecretpass
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

    # FTP Login: USER dev / PASS secretftp99
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
        # Client sends HTTP GET
        pkt_req = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                  IP(src="192.168.56.5", dst="93.184.216.34") / \
                  TCP(sport=35000, dport=80 if i % 2 == 0 else 443, flags="PA") / \
                  Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        pkt_req.time = base_ts + (i * 0.5)
        benign_pkts.append(pkt_req)

        # Server sends response
        pkt_res = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / \
                  IP(src="93.184.216.34", dst="192.168.56.5") / \
                  TCP(sport=80 if i % 2 == 0 else 443, dport=35000, flags="PA") / \
                  Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
        pkt_res.time = base_ts + (i * 0.5) + 0.05
        benign_pkts.append(pkt_res)

    benign_file = dest / "benign.pcap"
    wrpcap(str(benign_file), benign_pkts)
    files["benign"] = benign_file

    return files


if __name__ == "__main__":
    generated = generate_all_fixtures(Path(__file__).parent)
    for name, path in generated.items():
        print(f"Generated fixture: {name} -> {path}")
