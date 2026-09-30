"""Configuration loading and validation for PcapSentinel."""

import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "window_seconds": 30,
    "state_ttl_seconds": 300,
    "max_tracked_sources": 50000,
    "port_scan": {
        "min_distinct_ports": 20,
        "window_seconds": 10,
        "slow_window_seconds": 300,
        "slow_min_distinct_ports": 40,
    },
    "arp_spoof": {
        "allowlist_macs": [],
    },
    "dns_tunnel": {
        "max_label_length": 40,
        "min_entropy": 3.5,
        "min_unique_subdomains": 30,
        "domain_allowlist": [],
    },
    "cleartext_creds": {
        "enabled": True,
    },
    "ml": {
        "enabled": False,
        "model_path": "models/iforest.joblib",
        "top_k": 10,
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge dictionary `override` into `base`."""
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(config_path: Optional[str | Path] = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Load configuration from a YAML file, merging on top of default configuration.

    Args:
        config_path: Optional path to custom YAML config file.
        overrides: Optional key-value dictionary to override values.

    Returns:
        Consolidated configuration dictionary.
    """
    config = dict(DEFAULT_CONFIG)

    # If config_path is provided, load and merge it
    if config_path:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        with open(path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
            config = _deep_merge(config, user_cfg)
    else:
        # Check standard location: configs/default.yaml
        standard_path = Path("configs/default.yaml")
        if standard_path.exists():
            with open(standard_path, "r", encoding="utf-8") as f:
                user_cfg = yaml.safe_load(f) or {}
                config = _deep_merge(config, user_cfg)

    if overrides:
        config = _deep_merge(config, overrides)

    return config
