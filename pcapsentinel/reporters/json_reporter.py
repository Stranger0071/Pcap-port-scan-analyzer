"""JSON reporter for emitting machine-readable analysis results."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from pcapsentinel.models import Alert
from pcapsentinel.reader import CaptureStats


class JSONReporter:
    """Serializes capture statistics and aggregated alerts to a JSON file."""

    def __init__(self, stats: CaptureStats, alerts: List[Alert], config: Dict[str, Any]):
        self.stats = stats
        self.alerts = alerts
        self.config = config

    def generate_report_dict(self) -> Dict[str, Any]:
        """Build the structured report dictionary."""
        # Severity counts
        by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_detector: Dict[str, int] = {}
        src_counts: Dict[str, int] = {}

        for a in self.alerts:
            sev = a.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_detector[a.detector] = by_detector.get(a.detector, 0) + 1
            src_counts[a.src] = src_counts.get(a.src, 0) + 1

        top_offenders = [
            {"src": src, "alert_count": count}
            for src, count in sorted(src_counts.items(), key=lambda item: item[1], reverse=True)
        ]

        return {
            "version": "0.1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "capture_metadata": {
                "filepath": self.stats.filepath,
                "file_size_bytes": self.stats.file_size_bytes,
                "total_packets": self.stats.total_packets,
                "valid_packets": self.stats.valid_packets,
                "malformed_packets": self.stats.malformed_packets,
                "duration_seconds": round(self.stats.duration_seconds, 4),
                "start_time": self.stats.start_time,
                "end_time": self.stats.end_time,
            },
            "summary": {
                "total_alerts": len(self.alerts),
                "alerts_by_severity": by_severity,
                "alerts_by_detector": by_detector,
                "top_offenders": top_offenders[:10],
            },
            "config": self.config,
            "alerts": [alert.to_dict() for alert in self.alerts],
        }

    def write_to_file(self, output_path: str | Path) -> Path:
        """Write the generated JSON report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        report_data = self.generate_report_dict()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        return path
