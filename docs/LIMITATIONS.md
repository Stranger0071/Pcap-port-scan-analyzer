# Detection Engineering Limitations & Known Boundaries

This document formally records the known weaknesses, evasion cases, and architectural boundaries
of each PcapSentinel detector, measured against the evaluation benchmark. Honest documentation
of these is a first-class deliverable alongside the detection code itself.

---

## 1. Port Scan Detector

### Known Weaknesses

| Scenario | Behavior | Notes |
|---|---|---|
| **Slow / low-and-slow scans** (`nmap -T0`, `-T1`) | **May evade detection** | If the attacker spreads probes to fewer than `slow_min_distinct_ports` within `slow_window_seconds`, neither window trips. The threshold gap between fast and slow windows creates a blind spot for extremely patient adversaries. |
| **Distributed / coordinated scans** | **Will evade detection** | If multiple source IPs collaborate to scan distinct port ranges, no single source crosses the threshold. PcapSentinel has no cross-source correlation engine. |
| **ICMP / UDP host sweeps** | **Not detected** | Only TCP flag-based probes are tracked. ICMP ping sweeps and UDP port scans are not classified. |
| **Half-open scan with RST noise** | **Potential FP reduction** | RST responses from the scanned host are not used to filter probes, meaning even unsuccessful probes to filtered ports still count toward the threshold (this is usually correct behavior but could inflate FP count in certain network topologies). |

### Threshold Guidance
- **Fast window** (`window_seconds`, `min_distinct_ports`): Tune against your fastest expected legitimate burst of connections (e.g. a load balancer health check to many backends). A safe starting value is 20 ports / 10 seconds.
- **Slow window** (`slow_window_seconds`, `slow_min_distinct_ports`): The window must be wide enough to catch T1 scans (~1 probe/sec) but narrow enough to avoid accumulating normal background traffic. Evaluate on both tuning and held-out sets before tightening.

---

## 2. ARP Spoofing Detector

### Known Weaknesses

| Scenario | Behavior | Notes |
|---|---|---|
| **Legitimate IP mobility** (DHCP renewal, VM live-migration, NIC bonding failover) | **False Positive risk** | When a machine legitimately changes its MAC (e.g. NIC replacement, bonding) a spurious alert fires. Mitigate with `arp_spoof.allowlist_macs`. |
| **VRRP / HSRP virtual gateway MACs** | **False Positive risk** | Virtual router redundancy protocols present multiple MACs for the same gateway IP by design. Add the VRRP virtual MAC to `allowlist_macs`. |
| **ARP-proxy environments** | **Potential FP** | Environments using ARP proxying (e.g. some cloud VPCs, tunnels) can legitimately produce multiple MACs per IP. |
| **Encrypted / tunneled ARP spoofing** | **Not detected** | Attacks encapsulated in VXLAN, GRE, or other tunnels are not inspected. |

### Threshold Guidance
- Populate `arp_spoof.allowlist_macs` from known VRRP/HSRP configurations before baseline evaluation.
- Review `all_known_macs` in alert evidence to distinguish deliberate poisoning (attacker's OUI differs from vendor prefix) from infrastructure changes.

---

## 3. DNS Tunneling Detector

### Known Weaknesses

| Scenario | Behavior | Notes |
|---|---|---|
| **Encrypted DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT)** | **Cannot detect** | Traffic is encrypted at application layer; DNS query content is invisible to packet inspection. |
| **Low-rate / slow exfiltration** | **May evade detection** | If fewer than `min_unique_subdomains` are queried within `window_seconds`, the volume condition doesn't trigger. An attacker using a slow exfiltration rate will only trip the single-query condition if each label is long enough. |
| **Base32-encoded payloads** | **Reduced entropy** | Base32 uses only 32 characters, producing lower Shannon entropy (~3.4 bits/char) than Base64. This can fall near or below the `min_entropy` threshold. Consider lowering the cutoff to 3.0 for production environments after evaluation. |
| **Legitimate CDN / telemetry hostnames** | **False Positive risk** | Services like Akamai, Cloudflare, and Microsoft telemetry produce high-entropy subdomains legitimately. Add to `dns_tunnel.domain_allowlist`. |
| **DNS-based load balancing** | **Potential FP** | High-frequency CDN CNAME chains can look like subdomain churn. Allowlist or raise `min_unique_subdomains`. |

### Threshold Guidance
- Start with `min_entropy: 3.5` and `max_label_length: 40`. After baseline evaluation against benign traffic, adjust `min_entropy` down toward 3.0 only if false negatives appear on Base32 captures.
- Build `domain_allowlist` from a benign traffic baseline: any domain triggering alerts in a known-clean capture should be allowlisted.

---

## 4. Cleartext Credentials Detector

### Known Weaknesses

| Scenario | Behavior | Notes |
|---|---|---|
| **TLS-encrypted sessions (HTTPS, FTPS, SFTP)** | **Cannot detect** | Session content is encrypted. Credentials transmitted over TLS are not inspected. |
| **Custom or non-standard authentication protocols** | **Not detected** | Only HTTP `Authorization: Basic` and FTP `USER`/`PASS` commands are parsed. Telnet, POP3, IMAP, SMTP AUTH PLAIN, and custom binary protocols are not covered in Phase 1–2. |
| **Partial / fragmented TCP segments** | **May miss detection** | If the HTTP auth header or FTP command spans multiple TCP segments, the payload reassembly heuristic may fail to match. Full TCP stream reassembly would require stateful session tracking. |
| **Proxied or header-forwarded credentials** | **Not detected** | `Proxy-Authorization: Basic` headers are not parsed. |

---

## 5. Benchmark Evaluation Results (Synthetic Dataset)

Results below are on the **synthetic fixture dataset** bundled with the repository. These are
not real-world measurements — their purpose is to verify detector correctness on known inputs.

```
========================================================================
                   PCAPSENTINEL BENCHMARK EVALUATION
========================================================================
Captures Evaluated: 6

DETECTOR PERFORMANCE:
Detector             TP     FP     FN     Precision   Recall     F1-Score
------------------------------------------------------------------------
arp_spoof            1      0      0      1.000       1.000      1.000
cleartext_creds      2      0      0      1.000       1.000      1.000
dns_tunnel           1      0      0      1.000       1.000      1.000
port_scan            2      0      0      1.000       1.000      1.000
------------------------------------------------------------------------

DATASET SPLIT PERFORMANCE:
Split                TP     FP     FN     Precision   Recall     F1-Score
------------------------------------------------------------------------
held_out             2      0      0      1.000       1.000      1.000
tuning               4      0      0      1.000       1.000      1.000
------------------------------------------------------------------------
OVERALL              6      0      0      1.000       1.000      1.000
========================================================================
```

> **Note**: Perfect synthetic scores reflect that the fixtures were purpose-built to trip detectors.
> Real-world lab captures (with noisy baselines, fragmentation, and legitimate high-entropy domains)
> will produce lower precision/recall. Document those numbers by running `evaluate` against your own
> VM-generated captures.

---

---

## 6. Comparative Analysis: Unsupervised ML vs. Deterministic Rule-Based Detectors

Phase 5 introduced an unsupervised `IsolationForest` estimator trained on windowed per-source flow features. Below is the comparative analysis between deterministic rules and unsupervised flow scoring:

| Dimension | Deterministic Rule-Based Detectors | ML Anomaly Detector (Isolation Forest) |
|---|---|---|
| **Explainability** | **High**: Alerts contain direct evidence (targeted port lists, entropy values, MAC binding histories). Clear causality. | **Moderate**: Alerts expose eight window features plus the three largest deviations from the trained baseline (e.g. `syn_to_synack_ratio`, `distinct_dst_ports`). |
| **False Positive Behavior** | **Predictable**: Zero alerts on benign baselines when allowlists (e.g. CDN domains, VRRP MACs) are populated. | **Probabilistic**: Sensitive to benign traffic shifts (bursty transfers, new services, backups) not represented in the training baseline. |
| **Novel / Stealth Attack Detection** | **Rigid**: Attacks engineered just below thresholds (e.g. low-and-slow scans under `slow_window_seconds`) evade detection. | **Flexible**: Novel multi-vector anomalies and non-standard scan flag/port distributions can be flagged if they deviate in feature space. |
| **Operational Overhead** | **Zero Setup**: Works out of the box with default YAML thresholds; no training phase required. | **Requires Baseline**: Requires curated, representative benign pcap captures (`python -m pcapsentinel train`) before inference. |
| **Memory & Performance** | **Streaming O(1)**: Bounded memory with TTL state eviction during single-pass packet ingestion. | **Windowed Buffering**: Buffers windowed state per source IP and evaluates tree estimators during stream finalization. |

### Practical Deployment Recommendation
Use rule-based detectors as the primary, authoritative alert source for high-confidence incident response. Deploy ML anomaly scoring in tandem (via `--ml`) as a secondary triage signal to highlight anomalous endpoints that warrant manual investigation or threshold fine-tuning.

---

## 7. Improvement Roadmap (Post Phase 5)

| Priority | Improvement | Phase |
|---|---|---|
| High | TCP stream reassembly for fragmented credential detection | Future |
| High | Cross-source scan correlation for distributed port scans | Future |
| Medium | ICMP sweep and UDP scan detection | Future |
| Medium | `Proxy-Authorization` and SMTP AUTH PLAIN credential parsing | Future |
| Low | DoH/DoT decryption with known key material (SSLKEYLOGFILE) | Stretch |
| Low | VXLAN / GRE decapsulation for tunneled threat detection | Stretch |
