"""Tests for StreamingPcapReader."""

from pathlib import Path
import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from pcapsentinel.reader import StreamingPcapReader


def test_streaming_pcap_reader(tmp_path: Path):
    pcap_path = tmp_path / "sample.pcap"

    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80, flags="S")
        for i in range(5)
    ]
    # Set explicit timestamps
    for i, pkt in enumerate(pkts):
        pkt.time = 1000.0 + i

    wrpcap(str(pcap_path), pkts)

    reader = StreamingPcapReader(pcap_path)
    streamed = list(reader.read_packets())

    assert len(streamed) == 5
    assert reader.stats.total_packets == 5
    assert reader.stats.valid_packets == 5
    assert reader.stats.malformed_packets == 0
    assert reader.stats.start_time == 1000.0
    assert reader.stats.end_time == 1004.0
    assert reader.stats.duration_seconds == 4.0


def test_reader_file_not_found():
    with pytest.raises(FileNotFoundError):
        StreamingPcapReader("non_existent_file.pcap")
