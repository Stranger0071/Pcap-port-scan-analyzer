"""Tests for JSONReporter and MarkdownReporter."""

import json
from pathlib import Path
from pcapsentinel.models import Alert, Severity
from pcapsentinel.reader import CaptureStats
from pcapsentinel.reporters.json_reporter import JSONReporter
from pcapsentinel.reporters.markdown_reporter import MarkdownReporter


def test_json_and_markdown_reporters(tmp_path: Path):
    stats = CaptureStats(
        filepath=str(tmp_path / "dummy.pcap"),
        file_size_bytes=10240,
        total_packets=100,
        valid_packets=98,
        malformed_packets=2,
        start_time=1000.0,
        end_time=1015.0,
    )

    alerts = [
        Alert(
            id="ALT-001",
            detector="port_scan",
            severity=Severity.HIGH,
            src="192.168.1.100",
            dst="192.168.1.1",
            start_ts=1000.0,
            end_ts=1010.0,
            score=0.95,
            summary="SYN scan detected",
            evidence={"distinct_ports_count": 25, "scan_type": "syn"},
        ),
        Alert(
            id="ALT-002",
            detector="cleartext_creds",
            severity=Severity.MEDIUM,
            src="192.168.1.50",
            dst="192.168.1.1",
            start_ts=1012.0,
            end_ts=1012.0,
            score=1.0,
            summary="Cleartext credentials",
            evidence={"protocol": "HTTP", "username": "admin", "password": "***REDACTED***"},
        ),
    ]

    cfg = {"window_seconds": 30}

    # 1. JSON Reporter
    json_rep = JSONReporter(stats, alerts, cfg)
    json_path = tmp_path / "report.json"
    written_json = json_rep.write_to_file(json_path)

    assert written_json.exists()
    with open(written_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["capture_metadata"]["total_packets"] == 100
    assert data["capture_metadata"]["malformed_packets"] == 2
    assert data["summary"]["total_alerts"] == 2
    assert data["summary"]["alerts_by_severity"]["HIGH"] == 1
    assert data["summary"]["alerts_by_severity"]["MEDIUM"] == 1
    assert len(data["alerts"]) == 2
    assert data["alerts"][0]["id"] == "ALT-001"

    # 2. Markdown Reporter
    md_rep = MarkdownReporter(stats, alerts, cfg)
    md_path = tmp_path / "report.md"
    written_md = md_rep.write_to_file(md_path)

    assert written_md.exists()
    content = written_md.read_text(encoding="utf-8")
    assert "# PcapSentinel Threat Analysis Report" in content
    assert "Executive Summary" in content
    assert "Top Offending Sources" in content
    assert "192.168.1.100" in content
    assert "***REDACTED***" in content
