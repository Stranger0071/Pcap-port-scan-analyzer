"""Streaming extraction of fixed-window, per-endpoint flow features."""

from dataclasses import dataclass
from math import floor
from typing import ClassVar, Dict, List

from pcapsentinel.models import PacketEvent


@dataclass(frozen=True)
class FlowWindow:
    """The outbound activity of one endpoint during one fixed time window."""

    src_ip: str
    window_start: float
    window_end: float
    features: List[float]

    feature_names: ClassVar[List[str]] = [
        "connections_per_minute", "distinct_dst_ips", "distinct_dst_ports", "syn_count",
        "syn_to_synack_ratio", "bytes_sent_received_ratio", "mean_packet_length",
        "dns_queries_per_minute",
    ]


class FeatureExtractor:
    """Accumulate bounded per-IP state without retaining packets."""

    def __init__(self, window_seconds: float = 60.0):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        self.window_seconds = float(window_seconds)
        self._state: Dict[str, dict] = {}

    def _window_start(self, timestamp: float) -> float:
        return floor(timestamp / self.window_seconds) * self.window_seconds

    @staticmethod
    def _init_state(window_start: float) -> dict:
        return {"window_start": window_start, "connections": set(), "dst_ips": set(),
                "dst_ports": set(), "syn_count": 0, "synack_count": 0,
                "bytes_sent": 0, "bytes_received": 0, "sent_packets": 0,
                "dns_queries": 0}

    def _ensure_state(self, ip: str, timestamp: float, emitted: List[FlowWindow]) -> dict:
        window_start = self._window_start(timestamp)
        state = self._state.get(ip)
        if state is not None and state["window_start"] != window_start:
            if state["sent_packets"]:
                emitted.append(self._build_window(ip, state))
            state = self._init_state(window_start)
            self._state[ip] = state
        elif state is None:
            state = self._init_state(window_start)
            self._state[ip] = state
        return state

    def update(self, ev: PacketEvent) -> List[FlowWindow]:
        """Add one event and return any completed windows it closes."""
        emitted: List[FlowWindow] = []
        if ev.src_ip:
            self._accumulate_sent(self._ensure_state(ev.src_ip, ev.ts, emitted), ev)
        if ev.dst_ip and ev.dst_ip != ev.src_ip:
            self._accumulate_received(self._ensure_state(ev.dst_ip, ev.ts, emitted), ev)
        return emitted

    @staticmethod
    def _accumulate_sent(state: dict, ev: PacketEvent) -> None:
        state["sent_packets"] += 1
        state["bytes_sent"] += ev.length
        if ev.dst_ip:
            state["dst_ips"].add(ev.dst_ip)
        if ev.dst_port is not None:
            state["dst_ports"].add(ev.dst_port)
        state["connections"].add((ev.proto, ev.dst_ip, ev.src_port, ev.dst_port))
        if ev.proto == "TCP" and ev.tcp_flags and "S" in ev.tcp_flags and "A" not in ev.tcp_flags:
            state["syn_count"] += 1
        dns = ev.app.get("dns", {}) if ev.app else {}
        if ev.proto == "UDP" and ev.dst_port == 53 and dns.get("qname") and dns.get("qr") == 0:
            state["dns_queries"] += 1

    @staticmethod
    def _accumulate_received(state: dict, ev: PacketEvent) -> None:
        state["bytes_received"] += ev.length
        if ev.proto == "TCP" and ev.tcp_flags and "S" in ev.tcp_flags and "A" in ev.tcp_flags:
            state["synack_count"] += 1

    def finalize(self) -> List[FlowWindow]:
        windows = [self._build_window(ip, state) for ip, state in self._state.items() if state["sent_packets"]]
        self._state.clear()
        return windows

    def _build_window(self, src_ip: str, state: dict) -> FlowWindow:
        duration_minutes = self.window_seconds / 60.0
        features = [
            len(state["connections"]) / duration_minutes,
            len(state["dst_ips"]), len(state["dst_ports"]), state["syn_count"],
            state["syn_count"] / max(state["synack_count"], 1),
            state["bytes_sent"] / max(state["bytes_received"], 1),
            state["bytes_sent"] / state["sent_packets"],
            state["dns_queries"] / duration_minutes,
        ]
        return FlowWindow(src_ip, state["window_start"], state["window_start"] + self.window_seconds,
                          [round(float(value), 6) for value in features])
