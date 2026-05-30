"""
Centralised configuration loader for CloudHawk.

Priority (highest to lowest):
  1. Environment variables (AWS_DEFAULT_REGION, etc.)
  2. config/config.yaml
  3. Built-in defaults

Usage:
    from config import get_config
    cfg = get_config()
    region = cfg["aws"]["default_region"]
"""

import os
import copy
import logging
import yaml
from typing import Any, Dict

logger = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_FILE = os.path.join(_BASE_DIR, "config", "config.yaml")

_DEFAULTS: Dict[str, Any] = {
    "aws": {
        "default_region": "us-east-1",
        "max_events_per_service": 1000,
        "services": ["ec2", "s3", "iam", "cloudtrail", "guardduty"],
    },
    "azure": {
        "subscription_id": "",
        "max_events_per_service": 1000,
        "services": ["storage", "vm", "keyvault", "security_center", "activity_log"],
    },
    "gcp": {
        "project_id": "",
        "max_events_per_service": 1000,
        "services": ["iam", "storage", "compute", "logging"],
    },
    "detection": {
        "rule_engine": {"threads": 4, "chunk_size": 100},
        "anomaly": {"enabled": False, "contamination": 0.1},
    },
    "alerting": {
        "enabled": False,
        "channels": {
            "slack": {"enabled": False, "webhook_url": "", "channel": "#security-alerts"},
            "email": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from_email": "",
                "to_email": "",
            },
        },
    },
    "web": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": False,
    },
    "logging": {
        "level": "INFO",
        "file": "cloudhawk.log",
    },
}


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Recursively merge override into a copy of base."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_env_overrides(cfg: Dict) -> Dict:
    """Layer environment variables on top of file config."""
    overrides: Dict[str, Any] = {}

    # AWS
    if os.environ.get("AWS_DEFAULT_REGION"):
        overrides.setdefault("aws", {})["default_region"] = os.environ["AWS_DEFAULT_REGION"]

    # Azure
    if os.environ.get("AZURE_SUBSCRIPTION_ID"):
        overrides.setdefault("azure", {})["subscription_id"] = os.environ["AZURE_SUBSCRIPTION_ID"]

    # GCP
    if os.environ.get("GOOGLE_CLOUD_PROJECT"):
        overrides.setdefault("gcp", {})["project_id"] = os.environ["GOOGLE_CLOUD_PROJECT"]

    # Web
    if os.environ.get("CLOUDHAWK_PORT"):
        overrides.setdefault("web", {})["port"] = int(os.environ["CLOUDHAWK_PORT"])
    if os.environ.get("CLOUDHAWK_HOST"):
        overrides.setdefault("web", {})["host"] = os.environ["CLOUDHAWK_HOST"]
    if os.environ.get("FLASK_DEBUG"):
        overrides.setdefault("web", {})["debug"] = os.environ["FLASK_DEBUG"] == "1"

    # Alerting — Slack
    if os.environ.get("SLACK_WEBHOOK_URL"):
        overrides.setdefault("alerting", {}).setdefault("channels", {}).setdefault("slack", {})[
            "webhook_url"
        ] = os.environ["SLACK_WEBHOOK_URL"]

    return _deep_merge(cfg, overrides) if overrides else cfg


def _load_yaml(path: str) -> Dict:
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        logger.debug(f"Config file not found, using defaults: {path}")
        return {}
    except yaml.YAMLError as e:
        logger.error(f"YAML parse error in {path}: {e} — using defaults")
        return {}


# Module-level cache — call get_config() everywhere; reload() to force refresh.
_cache: Dict[str, Any] = {}


def get_config(config_file: str = _CONFIG_FILE) -> Dict[str, Any]:
    """Return merged config (cached after first call)."""
    global _cache
    if not _cache:
        _cache = reload(config_file)
    return _cache


def reload(config_file: str = _CONFIG_FILE) -> Dict[str, Any]:
    """Force re-read of config file and env vars. Updates cache."""
    global _cache
    file_cfg = _load_yaml(config_file)
    merged = _deep_merge(_DEFAULTS, file_cfg)
    _cache = _apply_env_overrides(merged)
    return _cache


def get(key_path: str, default: Any = None) -> Any:
    """
    Dot-notation key access with a safe default.
    Example: get("aws.default_region", "us-east-1")
    """
    cfg = get_config()
    keys = key_path.split(".")
    current: Any = cfg
    for k in keys:
        if isinstance(current, dict) and k in current:
            current = current[k]
        else:
            return default
    return current
