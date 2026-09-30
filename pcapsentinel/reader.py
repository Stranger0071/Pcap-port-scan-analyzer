"""Streaming pcap/pcapng reader that does not load entire files into memory."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Optional
import scapy.utils
from scapy.packet import Packet


@dataclass
class CaptureStats:
    filepath: str
    file_size_bytes: int = 0
    total_packets: int = 0
    valid_packets: int = 0
    malformed_packets: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    @property
    def duration_seconds(self) -> float:
        if self.start_time is not None and self.end_time is not None:
            return max(0.0, self.end_time - self.start_time)
        return 0.0


class StreamingPcapReader:
    """Streams packets from a pcap/pcapng file with malformed-packet resilience."""

    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"Capture file not found: {self.filepath}")

        self.stats = CaptureStats(
            filepath=str(self.filepath.resolve()),
            file_size_bytes=self.filepath.stat().st_size,
        )

    def read_packets(self) -> Generator[Packet, None, None]:
        """Yield packets one by one. Malformed packets are counted and safely skipped."""
        reader = None
        try:
            reader = scapy.utils.PcapReader(str(self.filepath))
            while True:
                try:
                    packet = reader.read_packet()
                    if packet is None:
                        break
                    self.stats.total_packets += 1
                except EOFError:
                    break
                except Exception:
                    self.stats.total_packets += 1
                    self.stats.malformed_packets += 1
                    continue

                # Record packet timestamp bounds
                pkt_time = float(getattr(packet, "time", 0.0))
                if pkt_time > 0:
                    if self.stats.start_time is None or pkt_time < self.stats.start_time:
                        self.stats.start_time = pkt_time
                    if self.stats.end_time is None or pkt_time > self.stats.end_time:
                        self.stats.end_time = pkt_time

                self.stats.valid_packets += 1
                yield packet

        except Exception as e:
            # If the pcap file header itself is corrupt or unreadable
            if self.stats.total_packets == 0:
                raise ValueError(f"Unable to read capture file header: {e}") from e
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
