# PRD: PcapSentinel — Network Traffic Threat Analyzer

| Field | Value |
|---|---|
| Status | Draft v2 |
| Target timeline | Working MVP by tomorrow; full scope over ~3 weeks |
| Primary stack | Python 3.11+, Scapy, scikit-learn, pytest |

---

## MVP Scope: What Is Possible by Tomorrow

Assumes roughly 8-10 focused hours. The MVP is a working, demo-able CLI, not the full PRD. The rest of this document describes the full product; anything not listed under "In the MVP" is deferred.

### In the MVP

| # | Deliverable | Notes |
|---|---|---|
| 1 | CLI: `python -m pcapsentinel analyze capture.pcap` | Single command, path in, reports out |
| 2 | Streaming pcap reader + packet normalizer | Scapy `PcapReader`; skips malformed packets and counts them |
| 3 | **Port-scan detector** (SYN, FIN, NULL, Xmas classification) | Distinct-ports-per-source in a time window; the core demo |
| 4 | **Cleartext-credential detector** (HTTP Basic, FTP USER/PASS) | Passwords redacted at parse time; easy and high-signal |
| 5 | **ARP-spoofing detector** (IP maps to a second MAC) | About 30 lines; include if the first four are done by mid-afternoon |
| 6 | YAML config with default thresholds | Thresholds not hard-coded |
| 7 | Reports: `report.json` and `report.md` | Summary table plus per-alert evidence |
| 8 | Lab captures: one SYN scan, one FIN/NULL/Xmas scan, one cleartext login, one benign capture | Generated in an isolated VM lab against your own machines |
| 9 | 3-5 pytest unit tests on synthetic packets | Trigger and no-trigger case for the port-scan detector, plus one for credentials |
| 10 | README with run instructions and one sample report | Enough for a recruiter to clone and run |

### Deferred (after the MVP)

- DNS-tunneling detector (entropy scoring needs tuning, so do it on Day 2)
- ML anomaly detector (Isolation Forest)
- Full evaluation harness and labeled dataset (for the MVP, verify by eye against your known lab scans and write down what you saw)
- Slow-scan and evasion testing
- Held-out test set, CI, Grafana/metrics export, live capture

### Suggested Hour-by-Hour Plan

| Block | Hours | Work |
|---|---|---|
| Setup | 0.5 | Repo, virtualenv, install Scapy, folder structure |
| Lab captures | 1.5 | Start VMs (host-only network), run `nmap -sS`, `-sF`, `-sN`, `-sX`, do a plain HTTP Basic and FTP login, capture a benign session; save as pcaps |
| Reader and models | 1 | `PacketEvent` and `Alert` dataclasses, streaming reader, normalizer |
| Port-scan detector | 2 | Sliding window, flag classification, evidence fields, tuned against your captures |
| Cleartext detector | 1 | HTTP Basic and FTP parsing with redaction |
| Reports and CLI | 1.5 | JSON and Markdown output, argparse, YAML config |
| Tests and README | 1.5 | Unit tests, sample report, README |
| Buffer / ARP detector | 1 | Add ARP detection if on schedule, otherwise absorb overruns |

### MVP Definition of Done

- Running the tool on your SYN-scan pcap flags the attacker IP as a port scan with a scan type and port count.
- Running it on the benign pcap produces zero alerts (or documented false positives).
- The cleartext login capture yields an alert with the password masked in every output.
- `pytest` passes.
- A fresh clone can run the tool from the README instructions.

### If You Fall Behind, Cut in This Order

1. ARP detector
2. YAML config (use constants in one file)
3. Markdown report (keep JSON only)
4. FTP detection (keep HTTP Basic only)

Never cut the port-scan detector, the redaction of credentials, or the tests.

### Safety Reminder for Lab Work

Generate attack traffic only inside an isolated host-only VM network, against machines you own.

---

## 1. Overview

PcapSentinel is a command-line tool that reads packet capture (`.pcap` / `.pcapng`) files, detects common network attacks and insecure practices, and produces a readable report. It combines **rule-based detectors** (fast, explainable) with an optional **ML anomaly detector** (Isolation Forest) and is validated against **traffic generated in my own isolated VM lab**, so detection quality is measured against known ground truth.

## 2. Problem Statement

Wireshark and Nmap are the standard tools for inspecting and generating network traffic, but manual inspection doesn't scale and doesn't teach *how* detection works. I want a tool that automates the hunt for a few high-value threats and lets me measure, honestly, how well simple detection logic performs, including where it fails (e.g., slow scans).

## 3. Goals

1. Detect the following in offline pcaps:
   - TCP port scans: SYN, FIN, NULL, Xmas
   - ARP spoofing / poisoning
   - DNS tunneling indicators
   - Cleartext credentials (HTTP Basic auth, FTP login)
2. Output structured findings (JSON) and a human-readable report (Markdown).
3. Evaluate detectors against labeled lab captures and report precision, recall, and false-positive counts.
4. Add an optional ML anomaly detector and compare it to the rule-based approach.
5. (Stretch) Export alert counts as metrics for a Grafana dashboard.

## 4. Non-Goals

- Not a real-time IDS/IPS or live packet sniffer (offline analysis first; live mode is a stretch).
- No blocking, mitigation, or active response.
- No decryption of TLS traffic.
- Not a replacement for Suricata/Zeek; this is a learning and demonstration tool.
- Never intended for use on networks I don't own or have permission to test.

## 5. Target Users

| User | Need |
|---|---|
| Me (student/analyst) | Learn detection engineering; demonstrate skills to recruiters |
| Recruiter / interviewer | Quickly see a working repo, sample report, and evaluation results |
| Junior SOC analyst (hypothetical) | Triage a pcap and get a ranked list of suspicious sources |

## 6. Functional Requirements

### 6.1 Ingestion
- **FR-1:** Read `.pcap` and `.pcapng` files via streaming (must not load whole file into memory).
- **FR-2:** Skip malformed packets and count them in the report rather than crashing.

### 6.2 Detectors
- **FR-3 Port scan:** Flag a source IP that sends TCP probes to many distinct destination ports (or hosts) within a time window. Classify scan type by TCP flags (SYN / FIN / NULL / Xmas).
- **FR-4 ARP spoofing:** Flag an IP address that maps to more than one MAC address, and unsolicited (gratuitous) ARP replies that change an existing mapping.
- **FR-5 DNS tunneling:** Flag domains with unusually long or high-entropy subdomain labels, high query volume to a single parent domain, or abnormal TXT/NULL record usage.
- **FR-6 Cleartext credentials:** Detect HTTP `Authorization: Basic` headers and FTP `USER`/`PASS` commands. **Credentials must be redacted in all outputs.**
- **FR-7 ML anomaly (optional):** Compute per-source, per-window features and score them with an Isolation Forest; report top anomalous sources.

### 6.3 Configuration
- **FR-8:** All thresholds (window size, port count, entropy cutoff, etc.) are set in a YAML config file, with sensible defaults, and overridable by CLI flags.

### 6.4 Output
- **FR-9:** Each alert contains: alert ID, detector, severity, source/destination, time range, evidence summary, and a confidence or score.
- **FR-10:** Produce `report.json` and `report.md` (summary table, top offenders, per-alert evidence, capture stats).
- **FR-11 (stretch):** Emit counters in a format Grafana can chart (Graphite plaintext or Prometheus text).

### 6.5 Evaluation
- **FR-12:** A labeled-dataset format (YAML) that lists expected detections per capture (type, source, time window).
- **FR-13:** An `evaluate` command that compares alerts to labels and prints precision, recall, F1, and false positives per detector.

## 7. Non-Functional Requirements

| Area | Requirement |
|---|---|
| Performance | Process a 100 MB pcap in a reasonable time on a laptop (target: under a couple of minutes) using streaming and bounded memory |
| Explainability | Every alert must show the evidence that triggered it |
| Extensibility | Adding a detector = one new class implementing a common interface, no changes to the core |
| Reliability | Malformed input never crashes the run |
| Safety | No raw payloads or credentials stored; reports redact secrets |
| Testability | Unit tests per detector using small synthetic pcaps |
| Portability | Runs on Linux/macOS/Windows with `pip install -r requirements.txt` |

## 8. Lab Setup and Data (for evaluation)

Isolated host-only virtual network (e.g., Kali or Ubuntu attacker VM, a vulnerable target VM, a plain client VM). **No bridged/internet-facing interfaces during attacks.**

| Scenario | How to generate | Expected detector |
|---|---|---|
| SYN scan | `nmap -sS` at target | Port scan |
| FIN / NULL / Xmas | `nmap -sF`, `-sN`, `-sX` | Port scan (type-classified) |
| Slow scan (evasion) | `nmap -T1` | Port scan (expected weakness; document result) |
| ARP spoofing | `arpspoof` / `ettercap` in isolated lab | ARP spoofing |
| DNS tunneling | `dnscat2` or `iodine` in the lab | DNS tunneling |
| Cleartext creds | Login to a local HTTP Basic page and a local FTP server | Cleartext credentials |
| Benign baseline | Normal browsing, DNS, file transfers | No alerts (false-positive check) |

Public sample pcaps (e.g., from malware-traffic-analysis or Wireshark sample captures) may supplement testing. Check each source's terms before using or redistributing.

## 9. Success Metrics

- Each rule detector reaches a documented precision/recall on the lab dataset (I'll report the real numbers, whatever they are).
- Known-weakness cases (slow scans, encrypted DNS) are documented honestly in the README.
- At least one detector improvement is driven by evaluation results (e.g., a threshold change that reduced false positives).
- ML detector is compared against rules on the same data.
- Repo includes: README, sample report, config example, tests, and lab-setup guide.

## 10. Milestones

| When | Deliverable |
|---|---|
| Tomorrow (MVP) | CLI, pcap reader, port-scan and cleartext-credential detectors (ARP if time allows), JSON and Markdown reports, lab captures, unit tests, README |
| Days 2-7 | DNS-tunneling detector, remaining ARP work, evaluation harness with labeled captures, threshold tuning |
| Weeks 2-3 | ML anomaly detector and comparison with rules, slow-scan and evasion testing, held-out set, (stretch) Grafana export |

## 11. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Threshold tuning overfits to my lab traffic | Keep a separate held-out capture set; report results on both |
| Slow/distributed scans evade detection | Document as a known limitation; test explicitly |
| Legal/ethical concerns from generating attack traffic | Isolated host-only lab, my own machines only |
| Large pcaps exhaust memory | Streaming reader, TTL eviction of per-source state |
| Scope creep | Ship rule-based detectors and evaluation first; ML and Grafana are stretch |

## 12. Resume Positioning (fill in with real results)

- Built a Python tool that detects port scans, ARP spoofing, DNS tunneling, and cleartext credentials in pcaps, validated against traffic generated in a VM lab.
- Measured detector precision and recall on labeled captures, and documented evasion cases such as slow scans.
- Compared rule-based detection with an Isolation Forest anomaly model on per-source flow features.

Only include numbers after running the evaluation.

## 13. Open Questions

1. Scapy vs. dpkt/PyShark for parsing speed? (Decide after a quick benchmark on a large pcap.)
2. Include live-capture mode, or keep offline only?
3. Report format: Markdown only, or add a static HTML report?
