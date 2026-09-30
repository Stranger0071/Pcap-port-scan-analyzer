"""Port scan detector with TCP flag classification and dual-window support."""

import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
from pcapsentinel.detectors.base import Detector
from pcapsentinel.models import Alert, PacketEvent, Severity


@dataclass
class Probe:
    ts: float
    dst_ip: str
    dst_port: int
    flags: str


class PortScanDetector(Detector):
    """Detects TCP port scans and classifies probe technique (SYN, FIN, NULL, Xmas)."""

    name = "port_scan"

    def __init__(self, cfg: Dict[str, Any]):
        super().__init__(cfg)
        ps_cfg = cfg.get("port_scan", {})
        self.min_distinct_ports = int(ps_cfg.get("min_distinct_ports", 20))
        self.window_seconds = float(ps_cfg.get("window_seconds", 10.0))
        self.slow_window_seconds = float(ps_cfg.get("slow_window_seconds", 300.0))
        self.slow_min_distinct_ports = int(ps_cfg.get("slow_min_distinct_ports", 40))

        # State per source IP: deque of Probes
        self.probes: Dict[str, deque[Probe]] = defaultdict(deque)
        self.last_seen: Dict[str, float] = {}
        # Tracking to suppress duplicate intermediate emissions for the same scan burst
        self.last_alert_info: Dict[str, Dict[str, Any]] = {}

    def _classify_scan(self, flags_list: List[str]) -> str:
        """Classify scan type based on the predominant TCP flags in the window."""
        total = len(flags_list)
        if total == 0:
            return "unknown"

        syn_count = sum(1 for f in flags_list if f == "S")
        null_count = sum(1 for f in flags_list if f == "")
        fin_count = sum(1 for f in flags_list if f == "F")
        xmas_count = sum(1 for f in flags_list if ("F" in f and "P" in f and "U" in f))

        if syn_count / total >= 0.6:
            return "syn"
        elif null_count / total >= 0.6:
            return "null"
        elif fin_count / total >= 0.6:
            return "fin"
        elif xmas_count / total >= 0.6:
            return "xmas"
        return "tcp_sweep"

    def process(self, ev: PacketEvent) -> List[Alert]:
        """Inspect TCP packets and trigger alerts when port threshold is exceeded."""
        if ev.proto != "TCP" or not ev.src_ip or ev.dst_port is None:
            return []

        # We care about scan probes (SYN, NULL, FIN, Xmas). Normal data/ACK traffic is ignored.
        flags = ev.tcp_flags if ev.tcp_flags is not None else ""
        is_probe = (
            flags == "S" or
            flags == "" or
            flags == "F" or
            ("F" in flags and "P" in flags and "U" in flags)
        )
        if not is_probe:
            return []

        src = ev.src_ip
        dst = ev.dst_ip or "unknown"
        ts = ev.ts
        self.last_seen[src] = ts

        # Record probe
        self.probes[src].append(Probe(ts=ts, dst_ip=dst, dst_port=ev.dst_port, flags=flags))

        # Prune probes outside the slow window
        slow_cutoff = ts - self.slow_window_seconds
        src_probes = self.probes[src]
        while src_probes and src_probes[0].ts < slow_cutoff:
            src_probes.popleft()

        # 1. Check fast window
        fast_cutoff = ts - self.window_seconds
        fast_probes = [p for p in src_probes if p.ts >= fast_cutoff]
        fast_ports = {p.dst_port for p in fast_probes}

        alerts: List[Alert] = []

        if len(fast_ports) >= self.min_distinct_ports:
            alert = self._generate_alert(
                src=src,
                probes=fast_probes,
                distinct_ports=fast_ports,
                window_name="fast",
                window_duration=self.window_seconds,
            )
            if alert:
                alerts.append(alert)
                return alerts

        # 2. Check slow window if fast window didn't trigger
        slow_ports = {p.dst_port for p in src_probes}
        if len(slow_ports) >= self.slow_min_distinct_ports:
            alert = self._generate_alert(
                src=src,
                probes=list(src_probes),
                distinct_ports=slow_ports,
                window_name="slow",
                window_duration=self.slow_window_seconds,
            )
            if alert:
                alerts.append(alert)

        return alerts

    def _generate_alert(
        self,
        src: str,
        probes: List[Probe],
        distinct_ports: Set[int],
        window_name: str,
        window_duration: float,
    ) -> Optional[Alert]:
        """Generate an alert if not recently alerted with identical port counts."""
        start_ts = probes[0].ts
        end_ts = probes[-1].ts
        port_count = len(distinct_ports)

        # Check suppression to avoid flood of duplicate alerts during a continuous scan
        last_info = self.last_alert_info.get(src)
        if last_info:
            time_since_last = end_ts - last_info["ts"]
            prev_ports = last_info["port_count"]
            # If within 2 seconds of last alert and port count hasn't grown substantially, suppress
            if time_since_last < 2.0 and port_count < prev_ports * 1.5:
                return None

        self.last_alert_info[src] = {"ts": end_ts, "port_count": port_count}

        flags_list = [p.flags for p in probes]
        scan_type = self._classify_scan(flags_list)
        if window_name == "slow":
            scan_type = f"slow_{scan_type}"

        duration = max(0.001, end_ts - start_ts)
        rate = round(len(probes) / duration, 2)
        sample_ports = sorted(list(distinct_ports))[:10]
        dst_hosts = list({p.dst_ip for p in probes})

        # Severity ranking
        severity = Severity.HIGH if port_count >= 100 else Severity.MEDIUM

        # Confidence score
        base_score = 0.8 if window_name == "fast" else 0.7
        score = min(0.99, base_score + (port_count / 500.0) * 0.2)

        summary = (
            f"{scan_type.upper()} port scan detected from {src}: "
            f"{port_count} distinct ports targeted across {len(dst_hosts)} host(s) "
            f"in {round(duration, 2)}s"
        )

        evidence = {
            "scan_type": scan_type,
            "distinct_ports_count": port_count,
            "total_probes": len(probes),
            "sample_ports": sample_ports,
            "probe_rate_per_sec": rate,
            "window_type": window_name,
            "target_hosts_count": len(dst_hosts),
            "sample_target_hosts": dst_hosts[:5],
        }

        alert_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"

        return Alert(
            id=alert_id,
            detector=self.name,
            severity=severity,
            src=src,
            dst=dst_hosts[0] if len(dst_hosts) == 1 else None,
            start_ts=start_ts,
            end_ts=end_ts,
            score=round(score, 4),
            summary=summary,
            evidence=evidence,
        )

    def evict_idle(self, current_ts: float, ttl_seconds: float) -> None:
        """Evict tracked sources idle longer than ttl_seconds."""
        cutoff = current_ts - ttl_seconds
        idle_sources = [src for src, ts in self.last_seen.items() if ts < cutoff]
        for src in idle_sources:
            self.probes.pop(src, None)
            self.last_seen.pop(src, None)
            self.last_alert_info.pop(src, None)
