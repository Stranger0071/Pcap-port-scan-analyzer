"""Tests for DetectionEngine lifecycle and event dispatch."""

from typing import List
from pcapsentinel.detectors.base import Detector
from pcapsentinel.engine import DetectionEngine
from pcapsentinel.models import Alert, PacketEvent, Severity


class DummyDetector(Detector):
    name = "dummy_detector"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.processed_count = 0
        self.swept_times = 0

    def process(self, ev: PacketEvent) -> List[Alert]:
        self.processed_count += 1
        if ev.dst_port == 9999:
            return [
                Alert(
                    id=f"DUMMY-{self.processed_count}",
                    detector=self.name,
                    severity=Severity.LOW,
                    src=ev.src_ip or "unknown",
                    dst=ev.dst_ip,
                    start_ts=ev.ts,
                    end_ts=ev.ts,
                    score=0.5,
                    summary="Dummy alert triggered",
                )
            ]
        return []

    def evict_idle(self, current_ts: float, ttl_seconds: float) -> None:
        self.swept_times += 1

    def finalize(self) -> List[Alert]:
        return [
            Alert(
                id="DUMMY-FINAL",
                detector=self.name,
                severity=Severity.LOW,
                src="finalize",
                dst=None,
                start_ts=0,
                end_ts=0,
                score=0.1,
                summary="Finalize alert",
            )
        ]


def test_detection_engine_lifecycle():
    cfg = {"state_ttl_seconds": 60, "sweep_interval_seconds": 10}
    engine = DetectionEngine(cfg)
    dummy = DummyDetector(cfg)
    engine.register_detector(dummy)

    # Event 1 at ts=10
    ev1 = PacketEvent(
        ts=10.0,
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        src_mac=None,
        dst_mac=None,
        proto="TCP",
        src_port=1000,
        dst_port=80,
        tcp_flags="S",
        length=54,
    )
    alerts1 = engine.process_event(ev1)
    assert len(alerts1) == 0
    assert dummy.processed_count == 1
    assert dummy.swept_times == 0

    # Event 2 at ts=25 (advances packet time by 15s >= 10s sweep_interval)
    ev2 = PacketEvent(
        ts=25.0,
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        src_mac=None,
        dst_mac=None,
        proto="TCP",
        src_port=1001,
        dst_port=9999,
        tcp_flags="S",
        length=54,
    )
    alerts2 = engine.process_event(ev2)
    assert len(alerts2) == 1
    assert alerts2[0].id == "DUMMY-2"
    assert dummy.swept_times == 1

    # Finalize
    final_alerts = engine.finalize()
    assert len(final_alerts) == 1
    assert final_alerts[0].id == "DUMMY-FINAL"

    all_alerts = engine.get_all_alerts()
    assert len(all_alerts) == 2
