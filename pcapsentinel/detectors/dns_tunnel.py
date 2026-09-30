"""DNS tunneling and data exfiltration detector using entropy and query volume analysis."""

import math
import uuid
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
from pcapsentinel.detectors.base import Detector
from pcapsentinel.models import Alert, PacketEvent, Severity


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())


def extract_parent_domain(qname: str) -> str:
    """Extract the registrable / parent domain (e.g. sub.foo.example.com -> example.com)."""
    parts = qname.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # Basic two-part root domain heuristic
    return ".".join(parts[-2:])


@dataclass
class DNSQueryRecord:
    ts: float
    qname: str
    max_label_len: int
    entropy: float
    qtype: int


class DNSTunnelDetector(Detector):
    """Detects DNS tunneling indicators: high label entropy, abnormal lengths, and high subdomain churn."""

    name = "dns_tunnel"

    def __init__(self, cfg: Dict[str, Any]):
        super().__init__(cfg)
        dns_cfg = cfg.get("dns_tunnel", {})
        self.max_label_length = int(dns_cfg.get("max_label_length", 40))
        self.min_entropy = float(dns_cfg.get("min_entropy", 3.5))
        self.min_unique_subdomains = int(dns_cfg.get("min_unique_subdomains", 30))
        self.window_seconds = float(dns_cfg.get("window_seconds", 60.0))
        self.domain_allowlist: Set[str] = {
            d.lower().strip(".") for d in dns_cfg.get("domain_allowlist", [])
        }

        # State: (src_ip, parent_domain) -> deque[DNSQueryRecord]
        self.queries: Dict[tuple[str, str], deque[DNSQueryRecord]] = defaultdict(deque)
        self.last_seen: Dict[tuple[str, str], float] = {}
        # Tracking to suppress duplicate alerts per (src_ip, parent_domain)
        self.last_alert_ts: Dict[tuple[str, str], float] = {}

    def _is_allowlisted(self, qname: str, parent_domain: str) -> bool:
        """Check if domain or parent domain matches configured allowlist."""
        qname_lower = qname.lower()
        if parent_domain in self.domain_allowlist:
            return True
        for allowed in self.domain_allowlist:
            if qname_lower == allowed or qname_lower.endswith("." + allowed):
                return True
        return False

    def process(self, ev: PacketEvent) -> List[Alert]:
        if "dns" not in ev.app or not ev.src_ip:
            return []

        dns_data = ev.app["dns"]
        # Only inspect queries (qr == 0)
        if dns_data.get("qr") != 0 or "qname" not in dns_data:
            return []

        qname = dns_data["qname"]
        qtype = dns_data.get("qtype", 1)  # 1 = A, 16 = TXT, 10 = NULL
        ts = ev.ts
        src = ev.src_ip
        dst = ev.dst_ip or "unknown"

        parent_domain = extract_parent_domain(qname)
        if not parent_domain or self._is_allowlisted(qname, parent_domain):
            return []

        # Calculate metrics for this query
        labels = qname.split(".")
        max_label_len = max((len(lbl) for lbl in labels), default=0)
        # Calculate entropy of the subdomain portion
        subdomain_part = ".".join(labels[:-2]) if len(labels) > 2 else labels[0]
        entropy = round(shannon_entropy(subdomain_part), 3)

        record = DNSQueryRecord(
            ts=ts,
            qname=qname,
            max_label_len=max_label_len,
            entropy=entropy,
            qtype=qtype,
        )

        state_key = (src, parent_domain)
        self.last_seen[state_key] = ts
        q_window = self.queries[state_key]
        q_window.append(record)

        # Evict records older than window_seconds
        cutoff = ts - self.window_seconds
        while q_window and q_window[0].ts < cutoff:
            q_window.popleft()

        # Evaluate triggering conditions
        alerts: List[Alert] = []
        unique_qnames = {r.qname for r in q_window}
        unique_count = len(unique_qnames)
        max_observed_entropy = max(r.entropy for r in q_window)
        max_observed_label = max(r.max_label_len for r in q_window)
        txt_null_count = sum(1 for r in q_window if r.qtype in (10, 16))

        # Condition A: Single query with exceptionally long label and high entropy
        single_query_trip = (max_label_len >= self.max_label_length and entropy >= self.min_entropy)

        # Condition B: High volume of unique subdomains under one parent domain with elevated entropy
        volume_trip = (unique_count >= self.min_unique_subdomains and max_observed_entropy >= 3.0)

        # Condition C: Abnormal TXT/NULL record query density
        record_type_trip = (unique_count >= 10 and txt_null_count >= 8 and max_observed_entropy >= 3.0)

        if single_query_trip or volume_trip or record_type_trip:
            last_alert = self.last_alert_ts.get(state_key)
            if last_alert is None or (ts - last_alert) > 30.0:
                self.last_alert_ts[state_key] = ts

                score = 0.80
                if single_query_trip and (volume_trip or record_type_trip):
                    score = 0.98
                elif single_query_trip:
                    score = min(0.95, 0.75 + (max_observed_label / 100.0) * 0.2)
                elif volume_trip:
                    score = min(0.95, 0.80 + (unique_count / 100.0) * 0.15)

                severity = Severity.HIGH if (score >= 0.90 or txt_null_count >= 10) else Severity.MEDIUM

                summary = (
                    f"DNS tunneling / exfiltration indicator detected for domain '{parent_domain}' "
                    f"from {src}: {unique_count} unique subdomains, max entropy {max_observed_entropy}"
                )

                evidence = {
                    "parent_domain": parent_domain,
                    "unique_subdomains_count": unique_count,
                    "max_entropy": max_observed_entropy,
                    "max_label_length": max_observed_label,
                    "txt_null_queries_count": txt_null_count,
                    "total_queries_in_window": len(q_window),
                    "sample_queries": list(unique_qnames)[:5],
                    "single_query_trip": single_query_trip,
                    "volume_trip": volume_trip,
                }

                alert = Alert(
                    id=f"DNS-{uuid.uuid4().hex[:8].upper()}",
                    detector=self.name,
                    severity=severity,
                    src=src,
                    dst=dst,
                    start_ts=q_window[0].ts,
                    end_ts=ts,
                    score=round(score, 4),
                    summary=summary,
                    evidence=evidence,
                )
                alerts.append(alert)

        return alerts

    def evict_idle(self, current_ts: float, ttl_seconds: float) -> None:
        """Evict tracked domains idle longer than ttl_seconds."""
        cutoff = current_ts - ttl_seconds
        idle_keys = [k for k, ts in self.last_seen.items() if ts < cutoff]
        for k in idle_keys:
            self.queries.pop(k, None)
            self.last_seen.pop(k, None)
            self.last_alert_ts.pop(k, None)
