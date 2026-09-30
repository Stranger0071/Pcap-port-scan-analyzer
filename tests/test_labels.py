"""Tests for labels.yaml ground-truth parser."""

from pathlib import Path
import pytest
from pcapsentinel.evaluation.labels import load_labels


def test_load_labels_valid():
    labels = load_labels("data/labels.yaml")
    assert len(labels) == 6

    captures = {l.capture for l in labels}
    assert "tests/synthetic/syn_scan.pcap" in captures
    assert "tests/synthetic/benign.pcap" in captures

    # Check splits
    tuning_labels = [l for l in labels if l.split == "tuning"]
    held_out_labels = [l for l in labels if l.split == "held_out"]
    assert len(tuning_labels) == 3
    assert len(held_out_labels) == 3

    # Benign capture expects zero alerts
    benign_label = next(l for l in labels if "benign.pcap" in l.capture)
    assert benign_label.expected == []
    assert benign_label.split == "held_out"

    # Check expected items in the syn_scan label
    syn_label = next(l for l in labels if "syn_scan.pcap" in l.capture)
    assert len(syn_label.expected) == 1
    assert syn_label.expected[0].detector == "port_scan"
    assert syn_label.expected[0].src == "192.168.56.10"
    assert syn_label.expected[0].scan_type == "syn"

    # cleartext_creds expects two alerts (HTTP + FTP)
    creds_label = next(l for l in labels if "cleartext_creds.pcap" in l.capture)
    assert len(creds_label.expected) == 2
    assert all(e.detector == "cleartext_creds" for e in creds_label.expected)


def test_load_labels_not_found():
    with pytest.raises(FileNotFoundError):
        load_labels("non_existent_labels.yaml")
