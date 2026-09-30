"""Tests for AlertAggregator."""

from pcapsentinel.aggregator import AlertAggregator
from pcapsentinel.models import Alert, Severity


def test_aggregator_merges_overlapping_port_scans():
    agg = AlertAggregator(merge_gap_seconds=10.0)

    alert1 = Alert(
        id="ALT-1",
        detector="port_scan",
        severity=Severity.MEDIUM,
        src="192.168.1.50",
        dst="192.168.1.1",
        start_ts=10.0,
        end_ts=15.0,
        score=0.8,
        summary="SYN scan partial",
        evidence={
            "scan_type": "syn",
            "distinct_ports_count": 20,
            "sample_ports": [80, 81, 82],
            "total_probes": 20,
        },
    )

    alert2 = Alert(
        id="ALT-2",
        detector="port_scan",
        severity=Severity.HIGH,
        src="192.168.1.50",
        dst="192.168.1.1",
        start_ts=18.0,  # starts within 10s of alert1.end_ts
        end_ts=25.0,
        score=0.95,
        summary="SYN scan extended",
        evidence={
            "scan_type": "syn",
            "distinct_ports_count": 45,
            "sample_ports": [80, 83, 84, 85],
            "total_probes": 30,
        },
    )

    merged = agg.aggregate([alert1, alert2])

    assert len(merged) == 1
    m = merged[0]
    assert m.src == "192.168.1.50"
    assert m.start_ts == 10.0
    assert m.end_ts == 25.0
    assert m.severity == Severity.HIGH  # Highest severity preserved
    assert m.score == 0.95  # Highest score preserved
    assert m.evidence["total_probes"] == 50
    assert 80 in m.evidence["sample_ports"]
    assert 85 in m.evidence["sample_ports"]
    assert m.evidence["merged_alerts_count"] == 2


def test_aggregator_severity_sorting():
    agg = AlertAggregator()

    a_low = Alert(
        id="A-LOW",
        detector="port_scan",
        severity=Severity.LOW,
        src="10.0.0.1",
        dst="10.0.0.2",
        start_ts=1.0,
        end_ts=2.0,
        score=0.5,
        summary="low",
    )
    a_high = Alert(
        id="A-HIGH",
        detector="cleartext_creds",
        severity=Severity.HIGH,
        src="10.0.0.3",
        dst="10.0.0.4",
        start_ts=1.0,
        end_ts=2.0,
        score=0.9,
        summary="high",
    )
    a_med = Alert(
        id="A-MED",
        detector="port_scan",
        severity=Severity.MEDIUM,
        src="10.0.0.5",
        dst="10.0.0.6",
        start_ts=1.0,
        end_ts=2.0,
        score=0.7,
        summary="med",
    )

    results = agg.aggregate([a_low, a_med, a_high])
    assert len(results) == 3
    assert results[0].severity == Severity.HIGH
    assert results[1].severity == Severity.MEDIUM
    assert results[2].severity == Severity.LOW
