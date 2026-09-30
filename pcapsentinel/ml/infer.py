"""IsolationForest-based anomaly detector for PcapSentinel."""

from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np

from pcapsentinel.detectors.base import Detector
from pcapsentinel.ml.features import FeatureExtractor, FlowWindow
from pcapsentinel.models import Alert, PacketEvent, Severity


class AnomalyDetector(Detector):
    """Flag only IsolationForest outliers and rank them by anomaly score."""

    name = "ml_anomaly"

    def __init__(self, cfg: Dict[str, Any]):
        super().__init__(cfg)
        ml_cfg = cfg.get("ml", {})
        self.model_path = Path(ml_cfg.get("model_path", "models/iforest.joblib"))
        self.top_k = max(1, int(ml_cfg.get("top_k", 10)))
        self._extractor = FeatureExtractor(float(ml_cfg.get("window_seconds", 60.0)))
        if not self.model_path.is_file():
            raise FileNotFoundError(f"ML model not found at '{self.model_path}'. Train one with `python -m pcapsentinel train --baseline <pcap> --output {self.model_path}`.")
        self._artifact = joblib.load(self.model_path)
        required = {"model", "feature_names", "feature_medians", "feature_scales"}
        if not isinstance(self._artifact, dict) or not required.issubset(self._artifact):
            raise ValueError("Invalid ML model artifact; retrain it with the current PcapSentinel version.")
        if self._artifact["feature_names"] != FlowWindow.feature_names:
            raise ValueError("ML model features do not match this PcapSentinel version; retrain the model.")
        self._scored_windows: List[Tuple[float, FlowWindow]] = []

    def _score_windows(self, windows: List[FlowWindow]) -> None:
        if not windows:
            return
        features = np.asarray([window.features for window in windows], dtype=float)
        predictions = self._artifact["model"].predict(features)
        scores = self._artifact["model"].decision_function(features)
        # ``predict`` classifies an exact decision boundary as inlier on some
        # scikit-learn versions. Treat a zero-or-negative decision score as an
        # outlier so a boundary case is not silently discarded.
        self._scored_windows.extend(
            (float(score), window)
            for score, window, prediction in zip(scores, windows, predictions)
            if prediction == -1 or score <= 0.0
        )

    def process(self, ev: PacketEvent) -> List[Alert]:
        self._score_windows(self._extractor.update(ev))
        return []

    def finalize(self) -> List[Alert]:
        self._score_windows(self._extractor.finalize())
        if not self._scored_windows:
            return []
        scores = [score for score, _ in self._scored_windows]
        low, high = min(scores), max(scores)
        spread = max(high - low, 1e-9)
        ranked = sorted(((1.0 - (score - low) / spread, score, window) for score, window in self._scored_windows), reverse=True, key=lambda item: item[0])
        return [self._to_alert(anomaly_score, raw_score, window) for anomaly_score, raw_score, window in ranked[:self.top_k]]

    def _to_alert(self, anomaly_score: float, raw_score: float, window: FlowWindow) -> Alert:
        values = np.asarray(window.features, dtype=float)
        medians = np.asarray(self._artifact["feature_medians"], dtype=float)
        scales = np.asarray(self._artifact["feature_scales"], dtype=float)
        deviations = np.abs((values - medians) / np.maximum(scales, 1e-6))
        contributors = [
            {"feature": FlowWindow.feature_names[index], "value": round(float(values[index]), 4),
             "baseline_median": round(float(medians[index]), 4), "deviation": round(float(deviations[index]), 3)}
            for index in np.argsort(deviations)[::-1][:3]
        ]
        evidence: Dict[str, Any] = {"anomaly_score": round(anomaly_score, 4), "raw_if_score": round(raw_score, 4),
                                    "window_seconds": self._extractor.window_seconds, "top_feature_contributors": contributors}
        evidence.update({name: round(value, 4) for name, value in zip(FlowWindow.feature_names, window.features)})
        severity = Severity.HIGH if anomaly_score >= 0.8 else Severity.MEDIUM if anomaly_score >= 0.6 else Severity.LOW
        return Alert(id=f"ml_{window.src_ip}_{int(window.window_start)}", detector=self.name, severity=severity,
                     src=window.src_ip, dst=None, start_ts=window.window_start, end_ts=window.window_end,
                     score=round(anomaly_score, 4),
                     summary=f"ML anomaly detected for {window.src_ip}: anomaly score {anomaly_score:.3f} in {self._extractor.window_seconds:g}s window",
                     evidence=evidence)

    def evict_idle(self, current_ts: float, ttl_seconds: float) -> None:
        """Windows are bounded by their fixed timestamp interval."""
