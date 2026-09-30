"""Tests for benchmark evaluation and metric scoring."""

import json
import tempfile
from pathlib import Path

from pcapsentinel.cli import main
from pcapsentinel.evaluation.evaluate import Evaluator, EvaluationReport, MetricScore


def test_metric_score_calculations():
    # Perfect score
    s1 = MetricScore(tp=10, fp=0, fn=0)
    assert s1.precision == 1.0
    assert s1.recall == 1.0
    assert s1.f1 == 1.0

    # Partial score
    s2 = MetricScore(tp=8, fp=2, fn=2)
    # Precision: 8 / 10 = 0.8
    # Recall: 8 / 10 = 0.8
    # F1: 0.8
    assert s2.precision == 0.8
    assert s2.recall == 0.8
    assert s2.f1 == 0.8

    # Zero cases
    s3 = MetricScore(tp=0, fp=5, fn=0)
    assert s3.precision == 0.0
    assert s3.recall == 0.0
    assert s3.f1 == 0.0


def test_evaluator_against_ground_truth():
    evaluator = Evaluator(labels_path="data/labels.yaml")
    report = evaluator.evaluate_all()

    assert report.total_captures == 6
    # All 6 expected detections should be matched — perfect recall on synthetic set
    assert report.overall.tp == 6
    assert report.overall.fp == 0
    assert report.overall.fn == 0
    assert report.overall.precision == 1.0
    assert report.overall.recall == 1.0
    assert report.overall.f1 == 1.0

    # Per-detector TP counts
    assert report.by_detector["port_scan"].tp == 2       # syn and xmas
    assert report.by_detector["cleartext_creds"].tp == 2  # HTTP + FTP
    assert report.by_detector["arp_spoof"].tp == 1
    assert report.by_detector["dns_tunnel"].tp == 1

    # No false positives anywhere
    for det, m in report.by_detector.items():
        assert m.fp == 0, f"{det} produced unexpected FPs"

    # Split validation
    assert report.by_split["tuning"].tp == 4   # syn, xmas, http+ftp
    assert report.by_split["held_out"].tp == 2  # arp + dns

    # Check text formatting
    table = report.format_table()
    assert "BENCHMARK EVALUATION" in table
    assert "DETECTOR PERFORMANCE:" in table
    assert "DATASET SPLIT PERFORMANCE:" in table
    assert "OVERALL" in table


def test_evaluation_report_to_dict():
    """EvaluationReport.to_dict() must return a JSON-serialisable structure with all keys."""
    report = EvaluationReport(
        total_captures=2,
        by_detector={"port_scan": MetricScore(tp=1, fp=0, fn=0)},
        by_split={"tuning": MetricScore(tp=1, fp=0, fn=0)},
        overall=MetricScore(tp=1, fp=0, fn=0),
    )
    d = report.to_dict()

    assert d["total_captures"] == 2
    assert d["overall"]["tp"] == 1
    assert d["overall"]["precision"] == 1.0
    assert "port_scan" in d["by_detector"]
    assert d["by_detector"]["port_scan"]["f1"] == 1.0
    assert "tuning" in d["by_split"]
    # Must be JSON serialisable with no exceptions
    json.dumps(d)


def test_evaluation_report_save_report(tmp_path):
    """EvaluationReport.save_report() must write valid JSON to the specified path."""
    report = EvaluationReport(
        total_captures=1,
        by_detector={"arp_spoof": MetricScore(tp=1, fp=0, fn=0)},
        by_split={"held_out": MetricScore(tp=1, fp=0, fn=0)},
        overall=MetricScore(tp=1, fp=0, fn=0),
    )
    out_file = tmp_path / "eval_results.json"
    saved = report.save_report(out_file)

    assert saved == out_file
    assert out_file.exists()

    data = json.loads(out_file.read_text())
    assert data["total_captures"] == 1
    assert data["overall"]["recall"] == 1.0
    assert "arp_spoof" in data["by_detector"]


def test_cli_evaluate_command(capsys):
    exit_code = main(["evaluate", "--labels", "data/labels.yaml"])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "Running benchmark evaluation" in captured.out
    assert "BENCHMARK EVALUATION" in captured.out
    assert "OVERALL" in captured.out


def test_cli_evaluate_dataset_dir_flag(capsys):
    """--dataset-dir (and legacy --base-dir) should resolve relative pcap paths."""
    exit_code = main(["evaluate", "--labels", "data/labels.yaml", "--dataset-dir", "."])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "OVERALL" in captured.out


def test_cli_evaluate_out_flag(tmp_path, capsys):
    """--out should save evaluation results as a JSON file."""
    out_file = str(tmp_path / "eval.json")
    exit_code = main(["evaluate", "--labels", "data/labels.yaml", "--out", out_file])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "Evaluation results saved to" in captured.out

    data = json.loads(Path(out_file).read_text())
    assert data["total_captures"] == 6
    assert data["overall"]["tp"] == 6

