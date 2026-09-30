"""Evaluation engine comparing detector alerts against ground-truth labels."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from pcapsentinel.evaluation.labels import CaptureLabel, ExpectedAlert, load_labels
from pcapsentinel.models import Alert


@dataclass
class MetricScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        total = self.tp + self.fp
        return round(self.tp / total, 4) if total > 0 else (1.0 if self.tp == 0 and self.fn == 0 else 0.0)

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return round(self.tp / total, 4) if total > 0 else (1.0 if self.fp == 0 else 0.0)

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        return round(2 * (p * r) / (p + r), 4) if (p + r) > 0 else 0.0


@dataclass
class EvaluationReport:
    total_captures: int
    by_detector: Dict[str, MetricScore] = field(default_factory=dict)
    by_split: Dict[str, MetricScore] = field(default_factory=dict)
    overall: MetricScore = field(default_factory=MetricScore)

    def format_table(self) -> str:
        """Format metrics into a clean text table."""
        lines = [
            "=" * 72,
            "                   PCAPSENTINEL BENCHMARK EVALUATION",
            "=" * 72,
            f"Captures Evaluated: {self.total_captures}",
            "",
            "DETECTOR PERFORMANCE:",
            f"{'Detector':<20} {'TP':<6} {'FP':<6} {'FN':<6} {'Precision':<11} {'Recall':<10} {'F1-Score':<10}",
            "-" * 72,
        ]

        for det, m in sorted(self.by_detector.items()):
            lines.append(
                f"{det:<20} {m.tp:<6} {m.fp:<6} {m.fn:<6} {m.precision:<11.3f} {m.recall:<10.3f} {m.f1:<10.3f}"
            )

        lines.extend([
            "-" * 72,
            "",
            "DATASET SPLIT PERFORMANCE:",
            f"{'Split':<20} {'TP':<6} {'FP':<6} {'FN':<6} {'Precision':<11} {'Recall':<10} {'F1-Score':<10}",
            "-" * 72,
        ])

        for sp, m in sorted(self.by_split.items()):
            lines.append(
                f"{sp:<20} {m.tp:<6} {m.fp:<6} {m.fn:<6} {m.precision:<11.3f} {m.recall:<10.3f} {m.f1:<10.3f}"
            )

        lines.extend([
            "-" * 72,
            f"{'OVERALL':<20} {self.overall.tp:<6} {self.overall.fp:<6} {self.overall.fn:<6} "
            f"{self.overall.precision:<11.3f} {self.overall.recall:<10.3f} {self.overall.f1:<10.3f}",
            "=" * 72,
        ])

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the evaluation report to a JSON-compatible dictionary."""

        def _score_dict(m: MetricScore) -> Dict[str, Any]:
            return {
                "tp": m.tp,
                "fp": m.fp,
                "fn": m.fn,
                "precision": m.precision,
                "recall": m.recall,
                "f1": m.f1,
            }

        return {
            "total_captures": self.total_captures,
            "overall": _score_dict(self.overall),
            "by_detector": {det: _score_dict(m) for det, m in sorted(self.by_detector.items())},
            "by_split": {sp: _score_dict(m) for sp, m in sorted(self.by_split.items())},
        }

    def save_report(self, out_path: "str | Path") -> Path:
        """Write the evaluation report as a JSON file and return the written path."""
        import json

        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path


class Evaluator:
    """Evaluates detection performance against ground-truth labels."""

    def __init__(self, labels_path: str | Path, base_dir: Optional[str | Path] = None):
        self.labels_path = Path(labels_path)
        self.base_dir = Path(base_dir) if base_dir else Path(".")
        self.labels = load_labels(self.labels_path)

    def _matches(self, alert: Alert, expected: ExpectedAlert) -> bool:
        """Check if an alert satisfies an expected ground-truth label."""
        if alert.detector != expected.detector:
            return False

        if alert.src.lower() != expected.src.lower():
            return False

        if expected.scan_type:
            alert_scan_type = alert.evidence.get("scan_type", "")
            if expected.scan_type not in alert_scan_type:
                return False

        if expected.start is not None and expected.end is not None:
            # Overlap check
            overlap = max(alert.start_ts, expected.start) <= min(alert.end_ts, expected.end)
            if not overlap:
                return False

        return True

    def _matches_ml(self, alert: Alert, expected: ExpectedAlert) -> bool:
        """Match an ML outlier to any labelled malicious activity.

        Ground truth labels describe the attack type detected by deterministic
        rules, not a separate ML-specific type.  ML is therefore scored as an
        independent binary anomaly detector on the same capture labels.
        """
        if alert.src.lower() != expected.src.lower():
            return False
        if expected.start is not None and expected.end is not None:
            return max(alert.start_ts, expected.start) <= min(alert.end_ts, expected.end)
        return True

    def evaluate_all(
        self,
        config_path: Optional[str | Path] = None,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> EvaluationReport:
        """Run analysis on all labeled captures and calculate precision, recall, and F1."""
        from pcapsentinel.cli import run_analysis

        report = EvaluationReport(total_captures=len(self.labels))

        all_detectors = {"port_scan", "cleartext_creds", "arp_spoof", "dns_tunnel"}
        for det in all_detectors:
            report.by_detector[det] = MetricScore()

        for label in self.labels:
            split_key = label.split
            if split_key not in report.by_split:
                report.by_split[split_key] = MetricScore()

            pcap_path = self.base_dir / label.capture
            if not pcap_path.exists():
                pcap_path = Path(label.capture)

            result = run_analysis(
                capture_path=pcap_path,
                config_path=config_path,
                overrides=overrides,
                emit_json=False,
                emit_markdown=False,
            )
            alerts = result["alerts"]
            rule_alerts = [alert for alert in alerts if alert.detector != "ml_anomaly"]
            ml_alerts = [alert for alert in alerts if alert.detector == "ml_anomaly"]

            # Match alerts to expected labels
            matched_alerts: Set[int] = set()
            matched_expected: Set[int] = set()

            for exp_idx, exp in enumerate(label.expected):
                for alt_idx, alert in enumerate(rule_alerts):
                    if alt_idx in matched_alerts:
                        continue
                    if self._matches(alert, exp):
                        matched_alerts.add(alt_idx)
                        matched_expected.add(exp_idx)
                        break

            # Tabulate True Positives
            tp_count = len(matched_expected)
            fn_count = len(label.expected) - len(matched_expected)
            fp_count = len(rule_alerts) - len(matched_alerts)

            # Update overall and split metrics
            report.overall.tp += tp_count
            report.overall.fp += fp_count
            report.overall.fn += fn_count

            report.by_split[split_key].tp += tp_count
            report.by_split[split_key].fp += fp_count
            report.by_split[split_key].fn += fn_count

            # Update per-detector metrics
            for exp_idx in matched_expected:
                det = label.expected[exp_idx].detector
                if det not in report.by_detector:
                    report.by_detector[det] = MetricScore()
                report.by_detector[det].tp += 1

            for exp_idx, exp in enumerate(label.expected):
                if exp_idx not in matched_expected:
                    det = exp.detector
                    if det not in report.by_detector:
                        report.by_detector[det] = MetricScore()
                    report.by_detector[det].fn += 1

            for alt_idx, alert in enumerate(rule_alerts):
                if alt_idx not in matched_alerts:
                    det = alert.detector
                    if det not in report.by_detector:
                        report.by_detector[det] = MetricScore()
                    report.by_detector[det].fp += 1

            # Score ML independently against the same expected attack labels.
            # It is intentionally excluded from the deterministic overall and
            # split scores above, which preserves their historical meaning.
            if overrides and overrides.get("ml", {}).get("enabled"):
                ml_score = report.by_detector.setdefault("ml_anomaly", MetricScore())
                matched_ml_alerts: Set[int] = set()
                matched_ml_expected: Set[int] = set()
                for exp_idx, expected in enumerate(label.expected):
                    for alt_idx, alert in enumerate(ml_alerts):
                        if alt_idx not in matched_ml_alerts and self._matches_ml(alert, expected):
                            matched_ml_alerts.add(alt_idx)
                            matched_ml_expected.add(exp_idx)
                            break
                ml_score.tp += len(matched_ml_expected)
                ml_score.fp += len(ml_alerts) - len(matched_ml_alerts)
                ml_score.fn += len(label.expected) - len(matched_ml_expected)

        return report
