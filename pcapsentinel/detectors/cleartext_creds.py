"""Cleartext credentials detector for HTTP Basic Auth and FTP login sessions."""

import uuid
from typing import Any, Dict, List, Optional
from pcapsentinel.detectors.base import Detector
from pcapsentinel.models import Alert, PacketEvent, Severity


class CleartextCredsDetector(Detector):
    """Detects transmission of unencrypted credentials (HTTP Basic, FTP USER/PASS) with strict redaction."""

    name = "cleartext_creds"

    def __init__(self, cfg: Dict[str, Any]):
        super().__init__(cfg)
        cred_cfg = cfg.get("cleartext_creds", {})
        self.enabled = cred_cfg.get("enabled", True)

        # Map (src_ip, dst_ip) -> {"username": str, "last_ts": float}
        self.ftp_sessions: Dict[tuple[str, str], Dict[str, Any]] = {}
        # Track seen credentials to avoid duplicate alerts: (proto, src, dst, username) -> last_alert_ts
        self.seen_alerts: Dict[tuple[str, str, str, str], float] = {}

    def process(self, ev: PacketEvent) -> List[Alert]:
        if not self.enabled or not ev.src_ip:
            return []

        alerts: List[Alert] = []
        src = ev.src_ip
        dst = ev.dst_ip or "unknown"
        ts = ev.ts

        # 1. HTTP Basic Auth
        if "http_auth" in ev.app:
            auth_info = ev.app["http_auth"]
            username = auth_info.get("username", "unknown")
            dedup_key = ("HTTP", src, dst, username)

            # Alert if not seen within last 60 seconds
            if dedup_key not in self.seen_alerts or (ts - self.seen_alerts[dedup_key]) > 60.0:
                self.seen_alerts[dedup_key] = ts
                alert_id = f"CRED-{uuid.uuid4().hex[:8].upper()}"
                alerts.append(
                    Alert(
                        id=alert_id,
                        detector=self.name,
                        severity=Severity.MEDIUM,
                        src=src,
                        dst=dst,
                        start_ts=ts,
                        end_ts=ts,
                        score=1.0,
                        summary=f"Cleartext HTTP Basic Authentication detected from {src} to {dst}",
                        evidence={
                            "protocol": "HTTP",
                            "auth_type": "Basic",
                            "username": username,
                            "password": "***REDACTED***",
                            "target_port": ev.dst_port or 80,
                        },
                    )
                )

        # 2. FTP Authentication
        if "ftp_cmd" in ev.app:
            ftp_cmd = ev.app["ftp_cmd"]
            cmd = ftp_cmd.get("cmd")
            arg = ftp_cmd.get("arg", "")
            session_key = (src, dst)

            if cmd == "USER":
                self.ftp_sessions[session_key] = {
                    "username": arg,
                    "last_ts": ts,
                }
            elif cmd == "PASS":
                session = self.ftp_sessions.get(session_key, {})
                username = session.get("username", "unknown")
                dedup_key = ("FTP", src, dst, username)

                if dedup_key not in self.seen_alerts or (ts - self.seen_alerts[dedup_key]) > 60.0:
                    self.seen_alerts[dedup_key] = ts
                    alert_id = f"CRED-{uuid.uuid4().hex[:8].upper()}"
                    alerts.append(
                        Alert(
                            id=alert_id,
                            detector=self.name,
                            severity=Severity.MEDIUM,
                            src=src,
                            dst=dst,
                            start_ts=ts,
                            end_ts=ts,
                            score=1.0,
                            summary=f"Cleartext FTP login credentials detected from {src} to {dst}",
                            evidence={
                                "protocol": "FTP",
                                "username": username,
                                "password": "***REDACTED***",
                                "target_port": ev.dst_port or 21,
                            },
                        )
                    )

        return alerts

    def evict_idle(self, current_ts: float, ttl_seconds: float) -> None:
        """Evict tracked sessions and alert dedup timestamps idle longer than ttl_seconds."""
        cutoff = current_ts - ttl_seconds
        idle_sessions = [k for k, v in self.ftp_sessions.items() if v["last_ts"] < cutoff]
        for k in idle_sessions:
            self.ftp_sessions.pop(k, None)

        idle_dedup = [k for k, last_ts in self.seen_alerts.items() if last_ts < cutoff]
        for k in idle_dedup:
            self.seen_alerts.pop(k, None)
