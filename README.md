# PcapSentinel — Network Traffic Threat Analyzer

**PcapSentinel** is a lightweight, explainable, and memory-bounded network traffic analysis tool. It processes offline packet capture files (`.pcap`, `.pcapng`), detects network-layer attacks and insecure practices, and generates detailed machine-readable (`report.json`) and human-readable (`report.md`) threat reports.

---

## Key Features

- **Streaming-First Architecture**: Built on a single-pass streaming reader (`StreamingPcapReader`). Never buffers entire pcap files into memory; handles large captures safely.
- **Malformed Packet Resilience**: Gracefully skips and tallies corrupt or incomplete frames without crashing.
- **Port Scan Detection**: Detects and classifies TCP scanning techniques using sliding time windows and TCP flag inspection:
  - **SYN Scan**: Half-open connection probes (`S`).
  - **FIN Scan**: Probes with FIN asserted (`F`).
  - **NULL Scan**: Flagless probes (`""`).
  - **Xmas Scan**: FIN, PSH, and URG flags asserted simultaneously (`FPU`).
  - **Dual-Window Analysis**: Catches rapid scans (`window_seconds: 10`) and slow/stealthy scans (`slow_window_seconds: 300`).
- **Fail-Safe Credential Redaction**: Identifies unencrypted authentication attempts (HTTP Basic Auth, FTP `USER`/`PASS`). **Passwords and secrets are redacted (`***REDACTED***`) immediately during raw packet ingestion** and never stored in memory, events, alerts, or reports.
- **Temporal Alert Aggregation**: Groups, deduplicates, and merges temporally overlapping findings with prioritized severity ranking (`HIGH`, `MEDIUM`, `LOW`).
- **Dual-Format Reporting**: Produces structured `report.json` for SIEM/data ingestion and formatted `report.md` with executive metrics, top offenders, and evidence blocks.

---

## Installation

### Prerequisites
- Python 3.11+
- Virtual environment tool (`venv` or `uv`)

### Setup
```bash
# Clone the repository
git clone https://github.com/Stranger0071/Pcap-port-scan-analyzer.git
cd Pcap-port-scan-analyzer

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Analyze a Capture File
```bash
python -m pcapsentinel analyze capture.pcap
```

### Advanced Options
```bash
python -m pcapsentinel analyze capture.pcap \
  --config configs/default.yaml \
  --out-dir ./reports \
  --min-ports 15 \
  --window 10.0
```

### CLI Options
| Argument | Description | Default |
|---|---|---|
| `capture` | Path to `.pcap` or `.pcapng` file | _Required_ |
| `-c`, `--config` | Path to custom YAML configuration | `configs/default.yaml` |
| `-o`, `--out-dir` | Directory to save reports | `.` |
| `--min-ports` | Override `port_scan.min_distinct_ports` | `20` |
| `--window` | Override `port_scan.window_seconds` | `10.0` |
| `--no-json` | Disable `report.json` generation | `False` |
| `--no-markdown` | Disable `report.md` generation | `False` |
| `--version` | Display PcapSentinel version | — |

---

## Sample Report Summary

When running an analysis, PcapSentinel outputs an interactive console summary:

```text
[+] Analyzing network capture: tests/synthetic/syn_scan.pcap

============================================================
                ANALYSIS SUMMARY
============================================================
  Processed Packets   : 25
  Malformed Packets   : 0
  Capture Duration    : 1.2s
  Total Alerts Found  : 1
  Severity Breakdown  : HIGH=0, MEDIUM=1, LOW=0
============================================================

Top Alerts Detected:
  - [MEDIUM] SYN port scan detected from 192.168.56.10: 25 distinct ports targeted across 1 host(s) in 1.2s (Score: 0.81)

Reports Generated:
  Markdown : ./report.md
  JSON     : ./report.json
```

---

## Running Tests

Run the complete automated test suite using `pytest`:

```bash
pytest -v
```

To regenerate the synthetic test capture fixtures:
```bash
python tests/synthetic/generate_synthetic_pcaps.py
```

---

## Project Structure

```text
.
├── configs/
│   └── default.yaml          # Default detection thresholds & TTL settings
├── pcapsentinel/
│   ├── __init__.py
│   ├── __main__.py           # Executable entry point
│   ├── cli.py                # Command-line interface and orchestrator
│   ├── config.py             # Config loader with deep-merging
│   ├── models.py             # Severity, PacketEvent, Alert models
│   ├── reader.py             # Streaming PcapReader with stats
│   ├── normalizer.py         # Packet normalizer & secret redactor
│   ├── engine.py             # Detection engine with TTL eviction
│   ├── aggregator.py         # Alert deduplication & temporal clustering
│   ├── detectors/
│   │   ├── base.py           # Detector ABC
│   │   ├── port_scan.py      # TCP port scan detector
│   │   └── cleartext_creds.py# Cleartext credential detector
│   └── reporters/
│       ├── json_reporter.py  # Structured JSON output
│       └── markdown_reporter.py # Human-readable Markdown output
├── tests/
│   ├── synthetic/            # Synthetic PCAP test captures
│   ├── test_models_and_config.py
│   ├── test_normalizer.py
│   ├── test_reader.py
│   ├── test_engine.py
│   ├── test_port_scan.py
│   ├── test_cleartext_creds.py
│   ├── test_aggregator.py
│   ├── test_reporters.py
│   └── test_cli.py
├── requirements.txt
└── README.md
```

---

## Security & Ethics

This tool is designed for educational purposes, defensive analysis, and authorized penetration testing. Attack traffic should only be generated in isolated lab environments against systems you own or have explicit authorization to assess.
