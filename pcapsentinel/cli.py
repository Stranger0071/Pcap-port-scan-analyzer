"""Command Line Interface for PcapSentinel."""

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

from pcapsentinel import __version__
from pcapsentinel.aggregator import AlertAggregator
from pcapsentinel.config import load_config
from pcapsentinel.detectors.arp_spoof import ARPSpoofDetector
from pcapsentinel.detectors.cleartext_creds import CleartextCredsDetector
from pcapsentinel.detectors.dns_tunnel import DNSTunnelDetector
from pcapsentinel.detectors.port_scan import PortScanDetector
from pcapsentinel.engine import DetectionEngine
from pcapsentinel.normalizer import normalize_packet
from pcapsentinel.reader import StreamingPcapReader
from pcapsentinel.reporters.json_reporter import JSONReporter
from pcapsentinel.reporters.markdown_reporter import MarkdownReporter


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="pcapsentinel",
        description="PcapSentinel: Network Traffic Threat Analyzer",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a PCAP or PCAPNG capture file")
    analyze_parser.add_argument("capture", help="Path to pcap/pcapng capture file")
    analyze_parser.add_argument("--config", "-c", default=None, help="Path to custom YAML config")
    analyze_parser.add_argument("--out-dir", "-o", default=".", help="Directory to write output reports")
    analyze_parser.add_argument("--min-ports", type=int, default=None, help="Override min_distinct_ports for port scan")
    analyze_parser.add_argument("--window", type=float, default=None, help="Override window_seconds for port scan")
    analyze_parser.add_argument("--no-json", action="store_true", help="Disable report.json generation")
    analyze_parser.add_argument("--no-markdown", action="store_true", help="Disable report.md generation")

    return parser


def run_analysis(
    capture_path: str | Path,
    config_path: str | Path | None = None,
    out_dir: str | Path = ".",
    overrides: Dict[str, Any] | None = None,
    emit_json: bool = True,
    emit_markdown: bool = True,
) -> Dict[str, Any]:
    """Execute the core streaming analysis pipeline."""
    pcap_path = Path(capture_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"Capture file not found: {pcap_path}")

    # Load configuration
    config = load_config(config_path, overrides=overrides)

    # Ingestion & Detection
    reader = StreamingPcapReader(pcap_path)
    engine = DetectionEngine(config)

    # Register detectors
    engine.register_detector(PortScanDetector(config))
    engine.register_detector(CleartextCredsDetector(config))
    engine.register_detector(ARPSpoofDetector(config))
    engine.register_detector(DNSTunnelDetector(config))

    # Process packet stream
    for raw_pkt in reader.read_packets():
        ev = normalize_packet(raw_pkt)
        engine.process_event(ev)

    engine.finalize()
    raw_alerts = engine.get_all_alerts()

    # Aggregate & Merge
    aggregator = AlertAggregator(merge_gap_seconds=config.get("window_seconds", 30.0))
    alerts = aggregator.aggregate(raw_alerts)

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    json_file = None
    md_file = None

    if emit_json:
        json_rep = JSONReporter(reader.stats, alerts, config)
        json_file = json_rep.write_to_file(out_path / "report.json")

    if emit_markdown:
        md_rep = MarkdownReporter(reader.stats, alerts, config)
        md_file = md_rep.write_to_file(out_path / "report.md")

    return {
        "stats": reader.stats,
        "alerts": alerts,
        "json_report": str(json_file) if json_file else None,
        "markdown_report": str(md_file) if md_file else None,
    }


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "analyze":
        overrides: Dict[str, Any] = {}
        if args.min_ports is not None:
            overrides.setdefault("port_scan", {})["min_distinct_ports"] = args.min_ports
        if args.window is not None:
            overrides.setdefault("port_scan", {})["window_seconds"] = args.window

        print(f"\n[+] Analyzing network capture: {args.capture}")
        try:
            result = run_analysis(
                capture_path=args.capture,
                config_path=args.config,
                out_dir=args.out_dir,
                overrides=overrides if overrides else None,
                emit_json=not args.no_json,
                emit_markdown=not args.no_markdown,
            )
        except Exception as e:
            print(f"[-] Analysis error: {e}", file=sys.stderr)
            return 1

        stats = result["stats"]
        alerts = result["alerts"]

        high_count = sum(1 for a in alerts if a.severity.value == "HIGH")
        med_count = sum(1 for a in alerts if a.severity.value == "MEDIUM")
        low_count = sum(1 for a in alerts if a.severity.value == "LOW")

        print("\n" + "=" * 60)
        print("                ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"  Processed Packets   : {stats.valid_packets:,}")
        print(f"  Malformed Packets   : {stats.malformed_packets}")
        print(f"  Capture Duration    : {round(stats.duration_seconds, 2)}s")
        print(f"  Total Alerts Found  : {len(alerts)}")
        print(f"  Severity Breakdown  : HIGH={high_count}, MEDIUM={med_count}, LOW={low_count}")
        print("=" * 60)

        if alerts:
            print("\nTop Alerts Detected:")
            for a in alerts[:5]:
                print(f"  - [{a.severity.value}] {a.summary} (Score: {a.score})")
            if len(alerts) > 5:
                print(f"  ... and {len(alerts) - 5} more alerts.")

        print("\nReports Generated:")
        if result["markdown_report"]:
            print(f"  Markdown : {result['markdown_report']}")
        if result["json_report"]:
            print(f"  JSON     : {result['json_report']}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
