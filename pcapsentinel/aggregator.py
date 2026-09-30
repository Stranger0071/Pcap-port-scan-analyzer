"""Alert aggregation, deduplication, and severity ranking."""

from typing import Any, Dict, List, Optional
from pcapsentinel.models import Alert, Severity


class AlertAggregator:
    """Merges and deduplicates raw alerts from detectors into a consolidated report-ready list."""

    def __init__(self, merge_gap_seconds: float = 30.0):
        self.merge_gap_seconds = merge_gap_seconds

    def _make_group_key(self, alert: Alert) -> tuple:
        """Construct group key for deduplication."""
        detector = alert.detector
        src = alert.src
        dst = alert.dst or ""

        # Secondary discriminator based on detector type
        sub_key = ""
        if detector == "port_scan":
            sub_key = alert.evidence.get("scan_type", "")
        elif detector == "cleartext_creds":
            sub_key = f"{alert.evidence.get('protocol', '')}:{alert.evidence.get('username', '')}"
        elif detector == "dns_tunnel":
            sub_key = alert.evidence.get("parent_domain", "")
        elif detector == "arp_spoof":
            sub_key = alert.evidence.get("victim_ip", "")

        return (detector, src, dst, sub_key)

    def aggregate(self, alerts: List[Alert]) -> List[Alert]:
        """Aggregate, merge temporally adjacent alerts, and sort by severity and score."""
        if not alerts:
            return []

        # Group alerts by signature
        groups: Dict[tuple, List[Alert]] = {}
        for alert in alerts:
            key = self._make_group_key(alert)
            if key not in groups:
                groups[key] = []
            groups[key].append(alert)

        merged_alerts: List[Alert] = []

        for key, alert_list in groups.items():
            # Sort within group by start_ts
            alert_list.sort(key=lambda a: a.start_ts)

            current_cluster: List[Alert] = [alert_list[0]]

            for alert in alert_list[1:]:
                prev = current_cluster[-1]
                # If alert overlaps or starts within merge_gap_seconds of the previous alert's end
                if alert.start_ts <= (prev.end_ts + self.merge_gap_seconds):
                    current_cluster.append(alert)
                else:
                    merged_alerts.append(self._merge_cluster(current_cluster))
                    current_cluster = [alert]

            if current_cluster:
                merged_alerts.append(self._merge_cluster(current_cluster))

        # Sort final alerts: Severity (HIGH -> LOW), Score (1.0 -> 0.0), Start Time (earliest first)
        merged_alerts.sort(
            key=lambda a: (a.severity.rank, a.score, -a.start_ts),
            reverse=True,
        )

        return merged_alerts

    def _merge_cluster(self, cluster: List[Alert]) -> Alert:
        """Merge a cluster of related alerts into a single cohesive Alert."""
        first = cluster[0]
        if len(cluster) == 1:
            return first

        # Compute merged time span
        start_ts = min(a.start_ts for a in cluster)
        end_ts = max(a.end_ts for a in cluster)

        # Compute highest severity
        max_severity = max((a.severity for a in cluster), key=lambda s: s.rank)

        # Compute max score
        max_score = max(a.score for a in cluster)

        # Merge evidence
        merged_evidence: Dict[str, Any] = dict(first.evidence)

        if first.detector == "port_scan":
            all_ports = set()
            total_probes = 0
            for a in cluster:
                ports = a.evidence.get("sample_ports", [])
                all_ports.update(ports)
                total_probes += a.evidence.get("total_probes", 0)

            merged_evidence["sample_ports"] = sorted(list(all_ports))[:15]
            # Use max reported distinct count or length of all collected sample ports
            reported_max = max(a.evidence.get("distinct_ports_count", 0) for a in cluster)
            merged_evidence["distinct_ports_count"] = max(reported_max, len(all_ports))
            merged_evidence["total_probes"] = total_probes
            duration = max(0.001, end_ts - start_ts)
            merged_evidence["probe_rate_per_sec"] = round(total_probes / duration, 2)
            summary = (
                f"{merged_evidence.get('scan_type', '').upper()} port scan detected from {first.src}: "
                f"{merged_evidence['distinct_ports_count']} distinct ports targeted in {round(duration, 2)}s"
            )
        else:
            summary = first.summary

        merged_evidence["merged_alerts_count"] = len(cluster)

        return Alert(
            id=first.id,
            detector=first.detector,
            severity=max_severity,
            src=first.src,
            dst=first.dst,
            start_ts=start_ts,
            end_ts=end_ts,
            score=max_score,
            summary=summary,
            evidence=merged_evidence,
        )
