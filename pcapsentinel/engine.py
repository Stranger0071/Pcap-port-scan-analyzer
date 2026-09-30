"""Core detection engine that dispatches events to registered detectors."""

from typing import Any, Dict, List, Optional
from pcapsentinel.detectors.base import Detector
from pcapsentinel.models import Alert, PacketEvent


class DetectionEngine:
    """Coordinates packet event dispatching and lifecycle management across detectors."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.state_ttl = float(config.get("state_ttl_seconds", 300))
        self.sweep_interval = float(config.get("sweep_interval_seconds", 30))
        self.detectors: List[Detector] = []
        self._last_sweep_ts: Optional[float] = None
        self._alerts: List[Alert] = []

    def register_detector(self, detector: Detector) -> None:
        """Register a detector instance into the engine."""
        self.detectors.append(detector)

    def process_event(self, ev: PacketEvent) -> List[Alert]:
        """Dispatch a single PacketEvent to all detectors and manage state sweeps."""
        new_alerts: List[Alert] = []

        # Perform periodic state cleanup based on packet timestamp progression
        if ev.ts > 0:
            if self._last_sweep_ts is None:
                self._last_sweep_ts = ev.ts
            elif (ev.ts - self._last_sweep_ts) >= self.sweep_interval:
                self._sweep_state(ev.ts)
                self._last_sweep_ts = ev.ts

        # Dispatch event to all detectors
        for detector in self.detectors:
            try:
                alerts = detector.process(ev)
                if alerts:
                    new_alerts.extend(alerts)
                    self._alerts.extend(alerts)
            except Exception as e:
                # Log or handle detector exception without crashing core pipeline
                pass

        return new_alerts

    def _sweep_state(self, current_ts: float) -> None:
        """Trigger TTL eviction across all registered detectors."""
        for detector in self.detectors:
            try:
                detector.evict_idle(current_ts, self.state_ttl)
            except Exception:
                pass

    def finalize(self) -> List[Alert]:
        """Signal end of capture stream and gather any remaining alerts."""
        final_alerts: List[Alert] = []
        for detector in self.detectors:
            try:
                alerts = detector.finalize()
                if alerts:
                    final_alerts.extend(alerts)
                    self._alerts.extend(alerts)
            except Exception:
                pass
        return final_alerts

    def get_all_alerts(self) -> List[Alert]:
        """Return all raw alerts collected by the engine."""
        return list(self._alerts)
