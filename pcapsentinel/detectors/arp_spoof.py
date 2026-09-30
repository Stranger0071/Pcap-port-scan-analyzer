"""ARP spoofing and poisoning detector."""

import uuid
from typing import Any, Dict, List, Optional, Set
from pcapsentinel.detectors.base import Detector
from pcapsentinel.models import Alert, PacketEvent, Severity


class ARPSpoofDetector(Detector):
    """Detects ARP spoofing: multiple MACs claiming the same IP or abrupt gratuitous ARP overrides."""

    name = "arp_spoof"

    def __init__(self, cfg: Dict[str, Any]):
        super().__init__(cfg)
        arp_cfg = cfg.get("arp_spoof", {})
        self.allowlist_macs: Set[str] = {
            m.lower() for m in arp_cfg.get("allowlist_macs", [])
        }

        # State: ip -> {"current_mac": str, "macs": set[str], "last_ts": float}
        self.ip_mac_table: Dict[str, Dict[str, Any]] = {}
        # Track alerted pairs: (ip, mac) -> last_alert_ts to avoid alert storming
        self.alerted_bindings: Dict[tuple[str, str], float] = {}

    def process(self, ev: PacketEvent) -> List[Alert]:
        if ev.proto != "ARP" or "arp" not in ev.app:
            return []

        arp_data = ev.app["arp"]
        op = arp_data.get("op")
        hwsrc = arp_data.get("hwsrc")
        psrc = arp_data.get("psrc")
        is_gratuitous = arp_data.get("is_gratuitous", False)

        if not hwsrc or not psrc or psrc in ("0.0.0.0", "255.255.255.255"):
            return []

        # Ignore allowlisted MAC addresses
        if hwsrc.lower() in self.allowlist_macs:
            return []

        alerts: List[Alert] = []
        ts = ev.ts

        if psrc not in self.ip_mac_table:
            # First observation of this IP -> MAC mapping
            self.ip_mac_table[psrc] = {
                "current_mac": hwsrc,
                "macs": {hwsrc},
                "last_ts": ts,
            }
            return []

        entry = self.ip_mac_table[psrc]
        entry["last_ts"] = ts
        current_mac = entry["current_mac"]

        if hwsrc != current_mac:
            # Different MAC claimed for existing IP
            entry["macs"].add(hwsrc)
            entry["current_mac"] = hwsrc  # update latest binding

            dedup_key = (psrc, hwsrc)
            last_alert = self.alerted_bindings.get(dedup_key)

            if last_alert is None or (ts - last_alert) > 30.0:
                self.alerted_bindings[dedup_key] = ts

                change_type = "gratuitous_arp_override" if is_gratuitous else "mac_binding_conflict"
                summary = (
                    f"ARP spoofing detected: IP {psrc} was claimed by {hwsrc} "
                    f"(previously mapped to {current_mac})"
                )

                evidence = {
                    "victim_ip": psrc,
                    "original_mac": current_mac,
                    "spoofed_mac": hwsrc,
                    "all_known_macs": sorted(list(entry["macs"])),
                    "is_gratuitous": is_gratuitous,
                    "change_type": change_type,
                    "arp_opcode": op,
                }

                alert = Alert(
                    id=f"ARP-{uuid.uuid4().hex[:8].upper()}",
                    detector=self.name,
                    severity=Severity.HIGH,
                    src=hwsrc,  # attacker MAC
                    dst=psrc,   # targeted IP
                    start_ts=ts,
                    end_ts=ts,
                    score=0.95,
                    summary=summary,
                    evidence=evidence,
                )
                alerts.append(alert)

        return alerts

    def evict_idle(self, current_ts: float, ttl_seconds: float) -> None:
        """Evict tracked IP mappings idle longer than ttl_seconds."""
        cutoff = current_ts - ttl_seconds
        idle_ips = [ip for ip, data in self.ip_mac_table.items() if data["last_ts"] < cutoff]
        for ip in idle_ips:
            self.ip_mac_table.pop(ip, None)

        idle_dedup = [k for k, last_ts in self.alerted_bindings.items() if last_ts < cutoff]
        for k in idle_dedup:
            self.alerted_bindings.pop(k, None)
