"""Prometheus text exposition format metrics exporter for PcapSentinel."""

from pathlib import Path
from typing import Any, Dict, List

from pcapsentinel.models import Alert

# Canonical detector names always emitted (even with zero counts)
_DETECTORS = ["port_scan", "cleartext_creds", "arp_spoof", "dns_tunnel", "ml_anomaly"]
_SEVERITIES = ["LOW", "MEDIUM", "HIGH"]


class MetricsExporter:
    """Generates Prometheus text exposition format metrics from a completed analysis run."""

    def __init__(self, alerts: List[Alert], stats: Any, config: Dict[str, Any]):
        """
        Args:
            alerts: Aggregated alert list from the analysis pipeline.
            stats: CaptureStats object (has .valid_packets, .malformed_packets, .duration_seconds).
            config: Loaded PcapSentinel config dict (currently unused but kept for future labels).
        """
        self.alerts = alerts
        self.stats = stats
        self.config = config

    def generate(self) -> str:
        """Render Prometheus text format metrics string."""
        lines: List[str] = []

        # --- Packet counters ---
        lines += [
            "# HELP pcapsentinel_packets_total Total packets processed",
            "# TYPE pcapsentinel_packets_total counter",
            f"pcapsentinel_packets_total {self.stats.valid_packets}",
        ]
        lines += [
            "# HELP pcapsentinel_malformed_packets_total Malformed or corrupt packets skipped",
            "# TYPE pcapsentinel_malformed_packets_total counter",
            f"pcapsentinel_malformed_packets_total {self.stats.malformed_packets}",
        ]
        lines += [
            "# HELP pcapsentinel_capture_duration_seconds Duration of the analysed capture in seconds",
            "# TYPE pcapsentinel_capture_duration_seconds gauge",
            f"pcapsentinel_capture_duration_seconds {round(self.stats.duration_seconds, 4)}",
        ]

        # --- Alert counts per detector x severity ---
        # Build lookup: (detector, severity) -> count
        counts: Dict[tuple, int] = {}
        for det in _DETECTORS:
            for sev in _SEVERITIES:
                counts[(det, sev)] = 0
        for alert in self.alerts:
            key = (alert.detector, alert.severity.value)
            if key in counts:
                counts[key] = counts.get(key, 0) + 1

        lines += [
            "# HELP pcapsentinel_alerts_total Total alerts generated, by detector and severity",
            "# TYPE pcapsentinel_alerts_total counter",
        ]
        for det in _DETECTORS:
            for sev in _SEVERITIES:
                val = counts.get((det, sev), 0)
                lines.append(f'pcapsentinel_alerts_total{{detector="{det}",severity="{sev}"}} {val}')

        # --- Max alert score per detector ---
        max_scores: Dict[str, float] = {det: 0.0 for det in _DETECTORS}
        for alert in self.alerts:
            if alert.detector in max_scores:
                max_scores[alert.detector] = max(max_scores[alert.detector], alert.score)

        lines += [
            "# HELP pcapsentinel_alert_score_max Maximum alert score by detector",
            "# TYPE pcapsentinel_alert_score_max gauge",
        ]
        for det in _DETECTORS:
            lines.append(f'pcapsentinel_alert_score_max{{detector="{det}"}} {round(max_scores[det], 4)}')

        return "\n".join(lines) + "\n"

    def write_to_file(self, path: Path) -> Path:
        """Write Prometheus metrics to a file and return the written path."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate(), encoding="utf-8")
        return path
