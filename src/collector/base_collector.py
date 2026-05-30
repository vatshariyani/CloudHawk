"""
Abstract base class for all CloudHawk cloud collectors.

Every collector (AWS, GCP, Azure) inherits from BaseCollector and must
implement collect_all() which returns a list of standardised security events.

Standardised event schema
-------------------------
{
    "timestamp":   str  ISO-8601 UTC with Z suffix
    "cloud":       str  "aws" | "gcp" | "azure"
    "source":      str  collector-specific tag  e.g. "GCP_AUDIT_LOG"
    "resource_id": str  cloud resource identifier
    "event_type":  str  e.g. "PUBLIC_BUCKET_ACCESS"
    "severity":    str  "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    "description": str  human-readable summary
    "raw_event":   Any  original API response (for forensics)
    ...             any extra cloud-specific fields added by the subclass
}
"""

import datetime
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseCollector(ABC):
    """Base class for cloud security collectors."""

    cloud: str = ""  # subclasses set this to "aws", "gcp", or "azure"

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__module__ + "." + self.__class__.__name__)

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def collect_all(self) -> List[Dict[str, Any]]:
        """Run all collectors and return the combined event list."""

    # ------------------------------------------------------------------
    # Shared event builder
    # ------------------------------------------------------------------

    def _event(
        self,
        source: str,
        resource_id: str,
        event_type: str,
        severity: str,
        description: str,
        raw: Any,
        **extra,
    ) -> Dict[str, Any]:
        """Build a standardised security event dict."""
        ev: Dict[str, Any] = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "cloud": self.cloud,
            "source": source,
            "resource_id": str(resource_id),
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "raw_event": raw,
        }
        ev.update(extra)
        return ev

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def utcnow_str() -> str:
        return datetime.datetime.utcnow().isoformat() + "Z"
