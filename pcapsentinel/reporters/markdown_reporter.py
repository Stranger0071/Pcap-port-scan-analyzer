"""Markdown reporter for generating human-readable security analysis reports."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from pcapsentinel.models import Alert
from pcapsentinel.reader import CaptureStats


class MarkdownReporter:
    """Generates a comprehensive Markdown report summarizing findings and evidence."""

    def __init__(self, stats: CaptureStats, alerts: List[Alert], config: Dict[str, Any]):
        self.stats = stats
        self.alerts = alerts
        self.config = config

    def generate_report_markdown(self) -> str:
        """Construct the Markdown report content."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        file_mb = round(self.stats.file_size_bytes / (1024 * 1024), 3)

        high_count = sum(1 for a in self.alerts if a.severity.value == "HIGH")
        med_count = sum(1 for a in self.alerts if a.severity.value == "MEDIUM")
        low_count = sum(1 for a in self.alerts if a.severity.value == "LOW")

        # Top offenders
        src_map: Dict[str, Dict[str, Any]] = {}
        for a in self.alerts:
            if a.src not in src_map:
                src_map[a.src] = {"count": 0, "detectors": set(), "max_sev": a.severity}
            src_map[a.src]["count"] += 1
            src_map[a.src]["detectors"].add(a.detector)
            if a.severity > src_map[a.src]["max_sev"]:
                src_map[a.src]["max_sev"] = a.severity

        top_offenders = sorted(src_map.items(), key=lambda item: item[1]["count"], reverse=True)

        lines: List[str] = [
            "# PcapSentinel Threat Analysis Report",
            "",
            f"**Generated:** {now}  ",
            f"**Target Capture:** `{self.stats.filepath}`  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| **File Size** | {file_mb} MB ({self.stats.file_size_bytes} bytes) |",
            f"| **Total Packets** | {self.stats.total_packets:,} |",
            f"| **Valid Processed Packets** | {self.stats.valid_packets:,} |",
            f"| **Malformed / Skipped Packets** | {self.stats.malformed_packets} |",
            f"| **Capture Duration** | {round(self.stats.duration_seconds, 2)} seconds |",
            f"| **Total Security Alerts** | **{len(self.alerts)}** |",
            f"| **Alerts Breakdown** | **HIGH**: {high_count} | **MEDIUM**: {med_count} | **LOW**: {low_count} |",
            "",
        ]

        # Top Offenders Table
        lines.extend([
            "## 2. Top Offending Sources",
            "",
        ])

        if top_offenders:
            lines.extend([
                "| Source IP | Alert Count | Max Severity | Threat Categories |",
                "|---|---|---|---|",
            ])
            for src, info in top_offenders[:5]:
                detectors_str = ", ".join(sorted(info["detectors"]))
                lines.append(f"| `{src}` | {info['count']} | **{info['max_sev'].value}** | {detectors_str} |")
            lines.append("")
        else:
            lines.extend([
                "_No suspicious network sources identified in this capture._",
                "",
            ])

        # Detailed Findings
        lines.extend([
            "## 3. Detailed Security Findings",
            "",
        ])

        if not self.alerts:
            lines.extend([
                "_Zero alerts triggered. Traffic appears benign according to configured thresholds._",
                "",
            ])
        else:
            for idx, a in enumerate(self.alerts, 1):
                dst_str = f"`{a.dst}`" if a.dst else "_Multiple / Broadcast_"
                lines.extend([
                    f"### Finding #{idx}: [{a.severity.value}] {a.summary}",
                    "",
                    f"- **Alert ID:** `{a.id}`",
                    f"- **Detector:** `{a.detector}`",
                    f"- **Confidence Score:** `{a.score}`",
                    f"- **Source Endpoint:** `{a.src}`",
                    f"- **Target Endpoint:** {dst_str}",
                    f"- **Observed Window:** `{round(a.start_ts, 2)}s` to `{round(a.end_ts, 2)}s` (Duration: `{round(max(0.0, a.end_ts - a.start_ts), 2)}s`)",
                    "",
                    "**Collected Evidence:**",
                    "",
                    "| Evidence Key | Value |",
                    "|---|---|",
                ])

                for k, v in a.evidence.items():
                    if isinstance(v, list):
                        v_str = ", ".join(str(item) for item in v[:12])
                        if len(v) > 12:
                            v_str += f"... (+{len(v) - 12} more)"
                    else:
                        v_str = str(v)
                    lines.append(f"| `{k}` | `{v_str}` |")

                lines.append("")

        # Known Limitations
        lines.extend([
            "---",
            "",
            "## 4. Detection Engineering Notes & Limitations",
            "",
            "- **Slow Port Scans:** Scans intentionally staggered below probe rate thresholds (`min_distinct_ports` per `window_seconds`) may require secondary window tuning.",
            "- **Credential Visibility:** Cleartext credential detection applies to unencrypted sessions (e.g. HTTP, FTP, Telnet). Encrypted protocols (TLS/SSH) are not inspected.",
            "- **Data Privacy:** Passwords and secrets are strictly redacted (`***REDACTED***`) immediately during raw packet ingestion and never logged.",
            "",
        ])

        return "\n".join(lines)

    def write_to_file(self, output_path: str | Path) -> Path:
        """Write Markdown report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.generate_report_markdown()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
