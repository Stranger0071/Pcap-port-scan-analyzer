"""IsolationForest model training on benign baseline captures."""

from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from pcapsentinel.ml.features import FeatureExtractor, FlowWindow
from pcapsentinel.normalizer import normalize_packet
from pcapsentinel.reader import StreamingPcapReader


def train_model(pcap_paths: List[Path], config: Dict[str, Any], model_output_path: Path) -> Dict[str, Any]:
    """Train and serialize an IsolationForest from representative benign PCAPs."""
    ml_cfg = config.get("ml", {})
    extractor = FeatureExtractor(window_seconds=float(ml_cfg.get("window_seconds", 60.0)))
    windows: List[FlowWindow] = []
    for pcap_path in pcap_paths:
        path = Path(pcap_path)
        if not path.is_file():
            raise FileNotFoundError(f"Baseline capture not found: {path}")
        for raw_pkt in StreamingPcapReader(path).read_packets():
            windows.extend(extractor.update(normalize_packet(raw_pkt)))
    windows.extend(extractor.finalize())

    if len(windows) < 2:
        raise ValueError(f"Insufficient training data: collected only {len(windows)} flow window(s). Provide longer or additional baseline captures.")

    features = np.asarray([window.features for window in windows], dtype=float)
    contamination = float(ml_cfg.get("contamination", 0.05))
    if not 0 < contamination <= 0.5:
        raise ValueError("ml.contamination must be greater than 0 and no more than 0.5")
    model = IsolationForest(contamination=contamination, n_estimators=100, random_state=42).fit(features)
    model_output_path = Path(model_output_path)
    model_output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": model,
        "feature_names": FlowWindow.feature_names,
        "feature_medians": np.median(features, axis=0).tolist(),
        "feature_scales": np.maximum(np.std(features, axis=0), 1e-6).tolist(),
        "n_windows_trained": len(windows),
        "window_seconds": extractor.window_seconds,
    }, model_output_path)
    return {"n_windows": len(windows), "model_path": str(model_output_path), "feature_names": FlowWindow.feature_names}
