"""Core data models for PcapSentinel."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        ranks = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}
        return ranks[self]

    def __ge__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


@dataclass(frozen=True)
class PacketEvent:
    ts: float  # epoch seconds
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_mac: Optional[str]
    dst_mac: Optional[str]
    proto: str  # "TCP" | "UDP" | "ARP" | "ICMP" | "OTHER"
    src_port: Optional[int]
    dst_port: Optional[int]
    tcp_flags: Optional[str]  # e.g. "S", "SA", "F", "" (NULL), "FPU" (Xmas)
    length: int
    app: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    id: str
    detector: str
    severity: Severity
    src: str
    dst: Optional[str]
    start_ts: float
    end_ts: float
    score: float  # 0.0 to 1.0 confidence or anomaly score
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "detector": self.detector,
            "severity": self.severity.value,
            "src": self.src,
            "dst": self.dst,
            "start_ts": round(self.start_ts, 4),
            "end_ts": round(self.end_ts, 4),
            "duration_seconds": round(max(0.0, self.end_ts - self.start_ts), 4),
            "score": round(self.score, 4),
            "summary": self.summary,
            "evidence": self.evidence,
        }
