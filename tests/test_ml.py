"""Tests for Phase 5: ML Anomaly Detection, Feature Extraction, and Metrics Exporter."""

import json
from pathlib import Path
import pytest

from pcapsentinel.cli import main, run_analysis
from pcapsentinel.config import DEFAULT_CONFIG
from pcapsentinel.evaluation.evaluate import Evaluator
from pcapsentinel.ml.features import FeatureExtractor, FlowWindow
from pcapsentinel.ml.infer import AnomalyDetector
from pcapsentinel.ml.train import train_model
from pcapsentinel.models import Alert, PacketEvent, Severity
from pcapsentinel.reader import CaptureStats
from pcapsentinel.reporters.metrics_exporter import MetricsExporter


def test_feature_extractor_synthetic():
    extractor = FeatureExtractor(window_seconds=10.0)

    # 1. Packet without src_ip should be ignored
    ev_no_ip = PacketEvent(
        ts=1.0,
        src_ip=None,
        dst_ip="192.168.1.1",
        src_mac="00:11:22:33:44:55",
        dst_mac="ff:ff:ff:ff:ff:ff",
        proto="ARP",
        src_port=None,
        dst_port=None,
        tcp_flags=None,
        length=42,
    )
    assert extractor.update(ev_no_ip) == []

    # 2. Add normal TCP packets
    # SYN packet
    ev_syn = PacketEvent(
        ts=2.0,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.10",
        src_mac=None,
        dst_mac=None,
        proto="TCP",
        src_port=12345,
        dst_port=80,
        tcp_flags="S",
        length=60,
    )
    assert extractor.update(ev_syn) == []

    # ACK packet
    ev_ack = PacketEvent(
        ts=3.0,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.10",
        src_mac=None,
        dst_mac=None,
        proto="TCP",
        src_port=12345,
        dst_port=80,
        tcp_flags="A",
        length=100,
    )
    assert extractor.update(ev_ack) == []

    # DNS packet
    ev_dns = PacketEvent(
        ts=4.0,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.1",
        src_mac=None,
        dst_mac=None,
        proto="UDP",
        src_port=53123,
        dst_port=53,
        tcp_flags=None,
        length=80,
        app={"dns": {"qname": "test.example.com", "qr": 0}},
    )
    assert extractor.update(ev_dns) == []

    # Trigger window rollover with an event at ts=15.0 (>= 2.0 + 10.0)
    ev_next = PacketEvent(
        ts=15.0,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.20",
        src_mac=None,
        dst_mac=None,
        proto="TCP",
        src_port=12346,
        dst_port=443,
        tcp_flags="S",
        length=60,
    )
    rolled = extractor.update(ev_next)
    assert len(rolled) == 1
    rolled_fw = rolled[0]
    assert rolled_fw.src_ip == "10.0.0.1"
    assert len(rolled_fw.features) == 8

    # Features:
    # 0: two distinct connections in a ten-second window = 12/minute.
    assert rolled_fw.features[0] == 12
    # 1: distinct_dst_ips = 2 ("192.168.1.10", "192.168.1.1")
    assert rolled_fw.features[1] == 2
    # 2: distinct_dst_ports = 2 (80, 53)
    assert rolled_fw.features[2] == 2
    # 3: syn_count = 1
    assert rolled_fw.features[3] == 1
    # 4: SYN-to-SYN/ACK ratio = 1 / 1 = 1.0
    assert rolled_fw.features[4] == 1.0
    # 6: mean_pkt_len = (60 + 100 + 80) / 3 = 80.0
    assert rolled_fw.features[6] == 80.0

    # Finalize should flush the in-progress window started at ts=15.0
    final_windows = extractor.finalize()
    assert len(final_windows) == 1
    assert final_windows[0].features[0] == 6


def test_train_model_insufficient_data(tmp_path):
    # Empty capture list => 0 windows => raises ValueError
    config = {
        "ml": {
            "window_seconds": 60.0,
            "contamination": 0.05,
        }
    }
    model_path = tmp_path / "model.joblib"
    with pytest.raises(ValueError, match="Insufficient training data"):
        train_model(
            pcap_paths=[],
            config=config,
            model_output_path=model_path,
        )


def test_train_and_infer_model_flow(tmp_path):
    # Train model using a very short window so multiple windows are extracted from benign.pcap
    model_path = tmp_path / "iforest_test.joblib"
    config = {
        "ml": {
            "enabled": True,
            "model_path": str(model_path),
            "window_seconds": 0.2,
            "contamination": 0.1,
            "top_k": 5,
        }
    }

    summary = train_model(
        pcap_paths=[Path("tests/synthetic/benign.pcap")],
        config=config,
        model_output_path=model_path,
    )

    assert summary["n_windows"] >= 2
    assert model_path.exists()
    assert len(summary["feature_names"]) == 8

    # Now test inference with AnomalyDetector
    detector = AnomalyDetector(config)

    # Feed an anomalous synthetic packet burst (port scan-like)
    for i in range(30):
        ev = PacketEvent(
            ts=100.0 + (i * 0.01),
            src_ip="192.168.99.99",
            dst_ip="10.0.0.1",
            src_mac=None,
            dst_mac=None,
            proto="TCP",
            src_port=10000 + i,
            dst_port=1000 + i,
            tcp_flags="S",
            length=40,
        )
        detector.process(ev)

    alerts = detector.finalize()
    assert len(alerts) > 0
    top_alert = alerts[0]
    assert top_alert.detector == "ml_anomaly"
    assert top_alert.src == "192.168.99.99"
    assert "anomaly_score" in top_alert.evidence
    assert "connections_per_minute" in top_alert.evidence
    assert len(top_alert.evidence["top_feature_contributors"]) == 3


def test_metrics_exporter(tmp_path):
    alerts = [
        Alert(
            id="a1",
            detector="port_scan",
            severity=Severity.HIGH,
            src="10.0.0.1",
            dst="10.0.0.2",
            start_ts=1.0,
            end_ts=2.0,
            score=0.95,
            summary="SYN scan",
            evidence={},
        ),
        Alert(
            id="a2",
            detector="cleartext_creds",
            severity=Severity.MEDIUM,
            src="10.0.0.1",
            dst="10.0.0.2",
            start_ts=1.5,
            end_ts=2.5,
            score=0.85,
            summary="Cleartext HTTP",
            evidence={},
        ),
    ]
    stats = CaptureStats(
        filepath="dummy.pcap",
        total_packets=150,
        valid_packets=148,
        malformed_packets=2,
        start_time=0.0,
        end_time=12.3456,
    )
    exporter = MetricsExporter(alerts, stats, DEFAULT_CONFIG)
    output = exporter.generate()

    assert "pcapsentinel_packets_total 148" in output
    assert "pcapsentinel_malformed_packets_total 2" in output
    assert "pcapsentinel_capture_duration_seconds 12.3456" in output
    assert 'pcapsentinel_alerts_total{detector="port_scan",severity="HIGH"} 1' in output
    assert 'pcapsentinel_alerts_total{detector="cleartext_creds",severity="MEDIUM"} 1' in output
    assert 'pcapsentinel_alerts_total{detector="arp_spoof",severity="HIGH"} 0' in output
    assert 'pcapsentinel_alert_score_max{detector="port_scan"} 0.95' in output

    metrics_file = tmp_path / "metrics.prom"
    saved = exporter.write_to_file(metrics_file)
    assert saved == metrics_file
    assert metrics_file.exists()


def test_cli_train_and_analyze_with_ml(tmp_path, capsys):
    model_file = str(tmp_path / "model.joblib")
    metrics_file = str(tmp_path / "metrics.prom")

    # 1. Test CLI train command
    exit_code = main([
        "train",
        "--baseline", "tests/synthetic/benign.pcap",
        "--output", model_file,
        "--window", "0.2",
    ])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Model training complete" in captured.out
    assert Path(model_file).exists()

    # 2. Test CLI analyze command with --ml, --model, and --metrics
    exit_code = main([
        "analyze",
        "tests/synthetic/syn_scan.pcap",
        "--ml",
        "--model", model_file,
        "--metrics", metrics_file,
        "--out-dir", str(tmp_path),
    ])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "ANALYSIS SUMMARY" in captured.out
    assert "Metrics  :" in captured.out
    assert Path(metrics_file).exists()


def test_evaluator_reports_ml_separately_from_rule_scores(tmp_path):
    """ML is benchmarked against the same labels without altering rule metrics."""
    model_path = tmp_path / "model.joblib"
    config = {"ml": {"model_path": str(model_path), "window_seconds": 0.2, "contamination": 0.1}}
    train_model([Path("tests/synthetic/benign.pcap")], config, model_path)

    report = Evaluator("data/labels.yaml").evaluate_all(overrides={"ml": {"enabled": True, **config["ml"]}})
    assert "ml_anomaly" in report.by_detector
    assert report.overall.tp == 6  # The deterministic comparison remains stable.
