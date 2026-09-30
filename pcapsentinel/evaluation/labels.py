"""Labels schema parser for ground-truth evaluation datasets."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import yaml


@dataclass
class ExpectedAlert:
    detector: str
    src: str
    scan_type: Optional[str] = None
    start: Optional[float] = None
    end: Optional[float] = None


@dataclass
class CaptureLabel:
    capture: str
    split: str = "tuning"  # "tuning" | "held_out"
    expected: List[ExpectedAlert] = field(default_factory=list)


def load_labels(yaml_path: str | Path) -> List[CaptureLabel]:
    """Parse a labels.yaml ground-truth configuration file."""
    path = Path(yaml_path)
    if not path.exists():
        raise FileNotFoundError(f"Labels file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []

    results: List[CaptureLabel] = []
    for item in data:
        capture = str(item.get("capture", ""))
        split = str(item.get("split", "tuning"))
        expected_raw = item.get("expected", []) or []

        expected_alerts: List[ExpectedAlert] = []
        for exp in expected_raw:
            expected_alerts.append(
                ExpectedAlert(
                    detector=str(exp.get("detector", "")),
                    src=str(exp.get("src", "")),
                    scan_type=exp.get("scan_type"),
                    start=float(exp["start"]) if "start" in exp else None,
                    end=float(exp["end"]) if "end" in exp else None,
                )
            )

        results.append(
            CaptureLabel(
                capture=capture,
                split=split,
                expected=expected_alerts,
            )
        )

    return results
