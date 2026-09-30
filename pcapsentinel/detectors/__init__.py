"""Detector package exports."""

from pcapsentinel.detectors.base import Detector
from pcapsentinel.detectors.port_scan import PortScanDetector
from pcapsentinel.detectors.cleartext_creds import CleartextCredsDetector
from pcapsentinel.detectors.arp_spoof import ARPSpoofDetector
from pcapsentinel.detectors.dns_tunnel import DNSTunnelDetector

__all__ = [
    "Detector",
    "PortScanDetector",
    "CleartextCredsDetector",
    "ARPSpoofDetector",
    "DNSTunnelDetector",
]
