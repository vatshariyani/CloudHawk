"""
CloudHawk Azure Security Collector

Collects security-relevant events from Microsoft Azure:
  - Activity Log  (azure-mgmt-monitor) — the primary audit trail
  - Security Center alerts / recommendations
  - Storage Account posture (HTTPS-only, public blob access, encryption)

Credentials are resolved in this order:
  1. AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID  (service principal)
  2. azure.client_id / client_secret / tenant_id in the config dict
  3. DefaultAzureCredential (az login, managed identity, env vars, etc.)

AZURE_SUBSCRIPTION_ID env var can supply the subscription when it is not set
in config.

Never hardcode credentials here.
"""

import datetime
import logging
import os
from typing import Any, Dict, List, Optional

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.storage import StorageManagementClient


class AzureCollector:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        az_cfg = config.get("azure", {})

        self.subscription_id: str = (
            os.getenv("AZURE_SUBSCRIPTION_ID") or az_cfg.get("subscription_id", "")
        )
        if not self.subscription_id:
            raise ValueError(
                "Azure subscription_id is required (set azure.subscription_id in config "
                "or AZURE_SUBSCRIPTION_ID env var)"
            )

        self.max_events: int = az_cfg.get("max_events_per_service", 1000)
        self.hours_back: int = az_cfg.get("hours_back", 24)
        self.logger = logging.getLogger(__name__)

        self._credential = self._load_credentials(az_cfg)

        self._monitor_client: Optional[MonitorManagementClient] = None
        self._security_client: Optional[SecurityCenter] = None
        self._storage_client: Optional[StorageManagementClient] = None

    # ------------------------------------------------------------------
    # Credential helpers
    # ------------------------------------------------------------------

    def _load_credentials(self, az_cfg: Dict[str, Any]):
        client_id = os.getenv("AZURE_CLIENT_ID") or az_cfg.get("client_id", "")
        client_secret = os.getenv("AZURE_CLIENT_SECRET") or az_cfg.get("client_secret", "")
        tenant_id = os.getenv("AZURE_TENANT_ID") or az_cfg.get("tenant_id", "")

        if client_id and client_secret and tenant_id:
            self.logger.info("Azure: using service principal credentials")
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        self.logger.info("Azure: using DefaultAzureCredential")
        return DefaultAzureCredential()

    @property
    def monitor_client(self) -> MonitorManagementClient:
        if self._monitor_client is None:
            self._monitor_client = MonitorManagementClient(
                self._credential, self.subscription_id
            )
        return self._monitor_client

    @property
    def security_client(self) -> SecurityCenter:
        if self._security_client is None:
            self._security_client = SecurityCenter(
                self._credential, self.subscription_id
            )
        return self._security_client

    @property
    def storage_client(self) -> StorageManagementClient:
        if self._storage_client is None:
            self._storage_client = StorageManagementClient(
                self._credential, self.subscription_id
            )
        return self._storage_client

    # ------------------------------------------------------------------
    # Standardised event builder
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
        ev = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "cloud": "azure",
            "source": source,
            "resource_id": resource_id,
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "subscription_id": self.subscription_id,
            "raw_event": raw,
        }
        ev.update(extra)
        return ev

    # ------------------------------------------------------------------
    # Activity Log  (primary T08 method)
    # ------------------------------------------------------------------

    def collect_activity_logs(self) -> List[Dict[str, Any]]:
        """Collect Azure Activity Log entries for the past N hours."""
        events: List[Dict[str, Any]] = []
        start = datetime.datetime.utcnow() - datetime.timedelta(hours=self.hours_back)
        filter_str = f"eventTimestamp ge '{start.strftime('%Y-%m-%dT%H:%M:%SZ')}'"

        try:
            entries = self.monitor_client.activity_logs.list(
                filter=filter_str,
                select=(
                    "eventTimestamp,level,operationName,resourceId,"
                    "caller,status,subStatus,resourceGroupName,resourceType"
                ),
            )
            count = 0
            for entry in entries:
                if count >= self.max_events:
                    break
                events.append(self._parse_activity_entry(entry))
                count += 1
        except (HttpResponseError, ClientAuthenticationError) as exc:
            self.logger.error("Azure Activity Log collection failed: %s", exc)
            events.append(self._event(
                source="AZURE_COLLECTOR",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="HIGH",
                description=f"Activity Log collection failed: {exc}",
                raw={"error": str(exc)},
            ))
        except Exception as exc:
            self.logger.error("Azure Activity Log collection failed: %s", exc)
            events.append(self._event(
                source="AZURE_COLLECTOR",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="HIGH",
                description=f"Activity Log collection failed: {exc}",
                raw={"error": str(exc)},
            ))

        self.logger.info("Azure: collected %d activity log events", len(events))
        return events

    def _parse_activity_entry(self, entry) -> Dict[str, Any]:
        try:
            operation = ""
            if entry.operation_name:
                operation = (
                    entry.operation_name.value
                    if hasattr(entry.operation_name, "value")
                    else str(entry.operation_name)
                )

            status = ""
            if entry.status:
                status = (
                    entry.status.value
                    if hasattr(entry.status, "value")
                    else str(entry.status)
                )

            level = str(entry.level.value) if entry.level and hasattr(entry.level, "value") else str(getattr(entry, "level", "Informational"))
            severity = _map_azure_level(level)

            ts = entry.event_timestamp.isoformat() + "Z" if entry.event_timestamp else datetime.datetime.utcnow().isoformat() + "Z"

            resource_id = getattr(entry, "resource_id", "") or ""
            caller = getattr(entry, "caller", "") or ""

            return self._event(
                source="AZURE_ACTIVITY_LOG",
                resource_id=resource_id,
                event_type=operation or "ACTIVITY_EVENT",
                severity=severity,
                description=f"Azure activity: {operation} by {caller} — {status}",
                raw={
                    "operation": operation,
                    "status": status,
                    "level": level,
                    "caller": caller,
                    "resource_group": getattr(entry, "resource_group_name", ""),
                },
                operation_name=operation,
                caller=caller,
                status=status,
                azure_level=level,
                azure_timestamp=ts,
            )
        except Exception as exc:
            self.logger.warning("Failed to parse activity entry: %s", exc)
            return self._event(
                source="AZURE_ACTIVITY_LOG",
                resource_id="unknown",
                event_type="PARSE_ERROR",
                severity="LOW",
                description=f"Failed to parse activity log entry: {exc}",
                raw={"error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Security Center alerts
    # ------------------------------------------------------------------

    def collect_security_alerts(self) -> List[Dict[str, Any]]:
        """Collect Azure Security Center / Defender for Cloud alerts."""
        events: List[Dict[str, Any]] = []
        try:
            alerts = self.security_client.alerts.list()
            count = 0
            for alert in alerts:
                if count >= self.max_events:
                    break
                events.append(self._parse_security_alert(alert))
                count += 1
        except Exception as exc:
            self.logger.error("Azure Security Center collection failed: %s", exc)
            events.append(self._event(
                source="AZURE_COLLECTOR",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="HIGH",
                description=f"Security Center collection failed: {exc}",
                raw={"error": str(exc)},
            ))

        self.logger.info("Azure: collected %d Security Center alerts", len(events))
        return events

    def _parse_security_alert(self, alert) -> Dict[str, Any]:
        try:
            severity = _map_asc_severity(getattr(alert, "alert_severity", "Medium") or "Medium")
            alert_type = getattr(alert, "alert_type", "") or ""
            display_name = getattr(alert, "display_name", alert_type) or alert_type
            resource_id = getattr(alert, "compromised_entity", "") or alert.id or "N/A"
            ts = alert.start_date_time_utc.isoformat() + "Z" if getattr(alert, "start_date_time_utc", None) else datetime.datetime.utcnow().isoformat() + "Z"

            return self._event(
                source="AZURE_SECURITY_CENTER",
                resource_id=resource_id,
                event_type=alert_type or "SECURITY_ALERT",
                severity=severity,
                description=f"Azure Security Center alert: {display_name}",
                raw={"alert_type": alert_type, "severity": getattr(alert, "alert_severity", ""), "id": getattr(alert, "id", "")},
                alert_display_name=display_name,
                alert_severity=getattr(alert, "alert_severity", ""),
                azure_timestamp=ts,
            )
        except Exception as exc:
            self.logger.warning("Failed to parse security alert: %s", exc)
            return self._event(
                source="AZURE_SECURITY_CENTER",
                resource_id="unknown",
                event_type="PARSE_ERROR",
                severity="LOW",
                description=f"Failed to parse security alert: {exc}",
                raw={"error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Storage Account posture
    # ------------------------------------------------------------------

    def collect_storage_security(self) -> List[Dict[str, Any]]:
        """Check Storage Account security posture (HTTPS-only, public access, encryption)."""
        events: List[Dict[str, Any]] = []
        try:
            accounts = list(self.storage_client.storage_accounts.list())
        except Exception as exc:
            self.logger.error("Azure storage collection failed: %s", exc)
            events.append(self._event(
                source="AZURE_COLLECTOR",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="HIGH",
                description=f"Storage account collection failed: {exc}",
                raw={"error": str(exc)},
            ))
            return events

        for account in accounts:
            events.extend(self._check_storage_account(account))

        self.logger.info("Azure: collected %d storage security events", len(events))
        return events

    def _check_storage_account(self, account) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        name = account.name or "unknown"
        resource_id = account.id or name

        # HTTPS-only traffic
        if not getattr(account, "enable_https_traffic_only", True):
            events.append(self._event(
                source="AZURE_STORAGE",
                resource_id=resource_id,
                event_type="STORAGE_HTTP_ALLOWED",
                severity="HIGH",
                description=f"Storage account '{name}' allows non-HTTPS traffic",
                raw={"account": name, "https_only": False},
            ))

        # Public blob access
        if getattr(account, "allow_blob_public_access", False):
            events.append(self._event(
                source="AZURE_STORAGE",
                resource_id=resource_id,
                event_type="STORAGE_PUBLIC_BLOB_ACCESS",
                severity="CRITICAL",
                description=f"Storage account '{name}' allows public blob access",
                raw={"account": name, "public_access": True},
            ))

        # Encryption at rest (Microsoft-managed key is default; flag absent encryption)
        encryption = getattr(account, "encryption", None)
        if encryption is None:
            events.append(self._event(
                source="AZURE_STORAGE",
                resource_id=resource_id,
                event_type="STORAGE_NO_ENCRYPTION",
                severity="MEDIUM",
                description=f"Storage account '{name}' has no encryption configuration",
                raw={"account": name, "encryption": None},
            ))

        return events

    # ------------------------------------------------------------------
    # Top-level collect
    # ------------------------------------------------------------------

    def collect_all(self) -> List[Dict[str, Any]]:
        """Run all collectors and return combined event list."""
        events: List[Dict[str, Any]] = []
        events.extend(self.collect_activity_logs())
        events.extend(self.collect_security_alerts())
        events.extend(self.collect_storage_security())
        self.logger.info("Azure: total events collected: %d", len(events))
        return events


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_LEVEL_MAP = {
    "critical": "CRITICAL",
    "error": "HIGH",
    "warning": "MEDIUM",
    "informational": "INFO",
    "verbose": "INFO",
}

_ASC_SEVERITY_MAP = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _map_azure_level(level: str) -> str:
    return _LEVEL_MAP.get(level.lower(), "INFO")


def _map_asc_severity(severity: str) -> str:
    return _ASC_SEVERITY_MAP.get(severity.lower(), "MEDIUM")
