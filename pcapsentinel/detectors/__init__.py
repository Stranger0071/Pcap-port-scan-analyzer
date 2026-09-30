"""Detector package exports."""

from pcapsentinel.detectors.base import Detector
from pcapsentinel.detectors.port_scan import PortScanDetector
from pcapsentinel.detectors.cleartext_creds import CleartextCredsDetector

__all__ = ["Detector", "PortScanDetector", "CleartextCredsDetector"]
