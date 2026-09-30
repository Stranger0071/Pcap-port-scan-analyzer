"""Integration tests for CLI and end-to-end capture analysis."""

import json
from pathlib import Path
from pcapsentinel.cli import main, run_analysis

SYN_PCAP = Path("tests/synthetic/syn_scan.pcap")
XMAS_PCAP = Path("tests/synthetic/xmas_scan.pcap")
CREDS_PCAP = Path("tests/synthetic/cleartext_creds.pcap")
BENIGN_PCAP = Path("tests/synthetic/benign.pcap")


def test_analyze_syn_scan(tmp_path: Path):
    result = run_analysis(SYN_PCAP, out_dir=tmp_path)
    assert result["stats"].valid_packets == 25
    assert len(result["alerts"]) >= 1

    alert = result["alerts"][0]
    assert alert.detector == "port_scan"
    assert alert.evidence["scan_type"] == "syn"
    assert alert.src == "192.168.56.10"

    assert Path(result["json_report"]).exists()
    assert Path(result["markdown_report"]).exists()


def test_analyze_xmas_scan(tmp_path: Path):
    result = run_analysis(XMAS_PCAP, out_dir=tmp_path)
    assert len(result["alerts"]) >= 1

    alert = result["alerts"][0]
    assert alert.detector == "port_scan"
    assert alert.evidence["scan_type"] == "xmas"
    assert alert.src == "192.168.56.15"


def test_analyze_cleartext_creds(tmp_path: Path):
    result = run_analysis(CREDS_PCAP, out_dir=tmp_path)
    assert len(result["alerts"]) >= 1

    # Check both HTTP and FTP detected and redacted
    protos = {a.evidence.get("protocol") for a in result["alerts"]}
    assert "HTTP" in protos
    assert "FTP" in protos

    # Verify secret is NEVER in reports
    with open(result["json_report"], "r", encoding="utf-8") as f:
        json_content = f.read()
    assert "supersecretpass" not in json_content
    assert "secretftp99" not in json_content
    assert "***REDACTED***" in json_content

    with open(result["markdown_report"], "r", encoding="utf-8") as f:
        md_content = f.read()
    assert "supersecretpass" not in md_content
    assert "secretftp99" not in md_content
    assert "***REDACTED***" in md_content


def test_analyze_benign_traffic(tmp_path: Path):
    result = run_analysis(BENIGN_PCAP, out_dir=tmp_path)
    assert result["stats"].valid_packets == 40
    # Zero alerts on normal web traffic
    assert len(result["alerts"]) == 0


def test_analyze_arp_spoof(tmp_path: Path):
    result = run_analysis("tests/synthetic/arp_spoof.pcap", out_dir=tmp_path)
    assert len(result["alerts"]) >= 1
    alert = result["alerts"][0]
    assert alert.detector == "arp_spoof"
    assert alert.src == "00:0c:29:ab:cd:ef"
    assert alert.evidence["victim_ip"] == "192.168.56.1"


def test_analyze_dns_tunnel(tmp_path: Path):
    result = run_analysis("tests/synthetic/dns_tunnel.pcap", out_dir=tmp_path)
    assert len(result["alerts"]) >= 1
    alert = result["alerts"][0]
    assert alert.detector == "dns_tunnel"
    assert alert.evidence["parent_domain"] == "exfil.org"


def test_cli_main_invocation(tmp_path: Path, capsys):
    exit_code = main(["analyze", str(SYN_PCAP), "--out-dir", str(tmp_path)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "ANALYSIS SUMMARY" in captured.out
    assert "Total Alerts Found" in captured.out
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()
