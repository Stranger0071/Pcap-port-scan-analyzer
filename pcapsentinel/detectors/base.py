"""Abstract base class for all PcapSentinel detectors."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from pcapsentinel.models import Alert, PacketEvent


class Detector(ABC):
    """Base class that all threat detectors must implement."""

    name: str = "base_detector"

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg

    @abstractmethod
    def process(self, ev: PacketEvent) -> List[Alert]:
        """Process a single packet event, update state, and return any newly triggered alerts."""
        raise NotImplementedError

    def finalize(self) -> List[Alert]:
        """Called once at the end of the packet stream to flush any pending alerts."""
        return []

    def evict_idle(self, current_ts: float, ttl_seconds: float) -> None:
        """Evict tracked state that has been idle longer than ttl_seconds.

        Args:
            current_ts: Timestamp of current packet stream (not wall clock).
            ttl_seconds: Max allowable idle duration in seconds.
        """
        pass
