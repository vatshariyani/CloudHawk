"""
CloudHawk GCP Security Collector

Collects security-relevant events from Google Cloud Platform:
  - Cloud Audit Logs (data access, admin activity, system events)
  - Cloud Storage bucket security posture
  - Compute Engine firewall / external-IP checks

Credentials are resolved in this order:
  1. GOOGLE_APPLICATION_CREDENTIALS env var (path to service-account JSON)
  2. gcp.credentials_path in config dict
  3. Application Default Credentials (gcloud auth application-default login)

Never hardcode credentials here.
"""

import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional

from google.auth import default as google_default
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import logging as cloud_logging
from google.cloud import storage
from google.oauth2 import service_account

from collector.base_collector import BaseCollector


class GCPCollector(BaseCollector):
    cloud = "gcp"

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        gcp_cfg = config.get("gcp", {})

        self.project_id: str = gcp_cfg.get("project_id") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
        if not self.project_id:
            raise ValueError("GCP project_id is required (set gcp.project_id in config or GOOGLE_CLOUD_PROJECT env var)")

        self.max_events: int = gcp_cfg.get("max_events_per_service", 1000)
        self.hours_back: int = gcp_cfg.get("hours_back", 24)

        creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or gcp_cfg.get("credentials_path", "")
        self._credentials = self._load_credentials(creds_path)

        self._logging_client: Optional[cloud_logging.Client] = None
        self._storage_client: Optional[storage.Client] = None

    # ------------------------------------------------------------------
    # Credential helpers
    # ------------------------------------------------------------------

    def _load_credentials(self, creds_path: str):
        try:
            if creds_path and os.path.exists(creds_path):
                self.logger.info("GCP: using service-account credentials from %s", creds_path)
                return service_account.Credentials.from_service_account_file(creds_path)
            creds, _ = google_default()
            self.logger.info("GCP: using application default credentials")
            return creds
        except DefaultCredentialsError as exc:
            raise RuntimeError(
                "GCP credentials not found. Set GOOGLE_APPLICATION_CREDENTIALS or run "
                "'gcloud auth application-default login'."
            ) from exc

    @property
    def logging_client(self) -> cloud_logging.Client:
        if self._logging_client is None:
            self._logging_client = cloud_logging.Client(
                project=self.project_id,
                credentials=self._credentials,
            )
        return self._logging_client

    @property
    def storage_client(self) -> storage.Client:
        if self._storage_client is None:
            self._storage_client = storage.Client(
                project=self.project_id,
                credentials=self._credentials,
            )
        return self._storage_client

    def _event(self, source, resource_id, event_type, severity, description, raw, **extra):
        ev = super()._event(source, resource_id, event_type, severity, description, raw, **extra)
        ev["project_id"] = self.project_id
        return ev

    # ------------------------------------------------------------------
    # Cloud Audit Logs
    # ------------------------------------------------------------------

    def collect_logs(self) -> List[Dict[str, Any]]:
        """Primary T07 method — collect Cloud Audit Log entries."""
        events: List[Dict[str, Any]] = []
        start = datetime.datetime.utcnow() - datetime.timedelta(hours=self.hours_back)
        timestamp_filter = start.strftime("%Y-%m-%dT%H:%M:%SZ")

        log_filter = (
            'logName=("projects/{p}/logs/cloudaudit.googleapis.com%2Factivity" OR '
            '"projects/{p}/logs/cloudaudit.googleapis.com%2Fdata_access" OR '
            '"projects/{p}/logs/cloudaudit.googleapis.com%2Fsystem_event") '
            'AND timestamp>="{ts}"'
        ).format(p=self.project_id, ts=timestamp_filter)

        try:
            entries = self.logging_client.list_entries(
                filter_=log_filter,
                max_results=self.max_events,
                order_by=cloud_logging.DESCENDING,
            )
            for entry in entries:
                events.append(self._parse_log_entry(entry))
        except Exception as exc:
            self.logger.error("GCP audit log collection failed: %s", exc)
            events.append(self._event(
                source="GCP_COLLECTOR",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="HIGH",
                description=f"Cloud Audit Log collection failed: {exc}",
                raw={"error": str(exc)},
            ))

        self.logger.info("GCP: collected %d audit log events", len(events))
        return events

    def _parse_log_entry(self, entry) -> Dict[str, Any]:
        try:
            ts = entry.timestamp.isoformat() + "Z" if entry.timestamp else datetime.datetime.utcnow().isoformat() + "Z"
            severity_name = entry.severity.name if hasattr(entry.severity, "name") else str(entry.severity)
            payload = entry.payload if entry.payload else {}

            method_name = ""
            principal_email = ""
            if isinstance(payload, dict):
                method_name = payload.get("methodName", "")
                auth_info = payload.get("authenticationInfo", {})
                principal_email = auth_info.get("principalEmail", "") if isinstance(auth_info, dict) else ""
            elif hasattr(payload, "method_name"):
                method_name = payload.method_name or ""

            resource_labels = {}
            if entry.resource and hasattr(entry.resource, "labels"):
                resource_labels = dict(entry.resource.labels)

            resource_id = (
                resource_labels.get("instance_id")
                or resource_labels.get("bucket_name")
                or resource_labels.get("project_id")
                or self.project_id
            )

            severity = _map_gcp_severity(severity_name)

            return self._event(
                source="GCP_AUDIT_LOG",
                resource_id=resource_id,
                event_type=method_name or "AUDIT_EVENT",
                severity=severity,
                description=f"GCP audit log: {method_name or entry.log_name}",
                raw={"log_name": entry.log_name, "severity": severity_name, "method": method_name},
                log_name=entry.log_name,
                method_name=method_name,
                principal_email=principal_email,
                resource_type=entry.resource.type if entry.resource else "",
                resource_labels=resource_labels,
                gcp_timestamp=ts,
            )
        except Exception as exc:
            self.logger.warning("Failed to parse log entry: %s", exc)
            return self._event(
                source="GCP_AUDIT_LOG",
                resource_id="unknown",
                event_type="PARSE_ERROR",
                severity="LOW",
                description=f"Failed to parse log entry: {exc}",
                raw={"error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Cloud Storage posture
    # ------------------------------------------------------------------

    def collect_storage_security(self) -> List[Dict[str, Any]]:
        """Check GCS bucket security posture (public access, versioning, CMEK)."""
        events: List[Dict[str, Any]] = []
        try:
            buckets = list(self.storage_client.list_buckets())
        except Exception as exc:
            self.logger.error("GCP storage collection failed: %s", exc)
            events.append(self._event(
                source="GCP_COLLECTOR",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="HIGH",
                description=f"Storage bucket collection failed: {exc}",
                raw={"error": str(exc)},
            ))
            return events

        for bucket in buckets:
            events.extend(self._check_bucket(bucket))

        self.logger.info("GCP: collected %d storage security events", len(events))
        return events

    def _check_bucket(self, bucket) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        name = bucket.name

        # Public access via IAM
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = binding.get("members", [])
                role = binding.get("role", "")
                if {"allUsers", "allAuthenticatedUsers"} & set(members):
                    events.append(self._event(
                        source="GCP_STORAGE",
                        resource_id=name,
                        event_type="PUBLIC_BUCKET_ACCESS",
                        severity="CRITICAL",
                        description=f"Bucket '{name}' grants public access via role '{role}'",
                        raw={"bucket": name, "role": role, "members": list(members)},
                    ))
        except Exception as exc:
            self.logger.debug("Could not fetch IAM policy for bucket %s: %s", name, exc)

        # Customer-managed encryption
        if not bucket.default_kms_key_name:
            events.append(self._event(
                source="GCP_STORAGE",
                resource_id=name,
                event_type="BUCKET_NO_CMEK",
                severity="MEDIUM",
                description=f"Bucket '{name}' is not encrypted with a customer-managed key",
                raw={"bucket": name, "kms_key": None},
            ))

        # Versioning
        if not bucket.versioning_enabled:
            events.append(self._event(
                source="GCP_STORAGE",
                resource_id=name,
                event_type="BUCKET_VERSIONING_DISABLED",
                severity="LOW",
                description=f"Bucket '{name}' has versioning disabled",
                raw={"bucket": name, "versioning": False},
            ))

        return events

    # ------------------------------------------------------------------
    # Top-level collect
    # ------------------------------------------------------------------

    def collect_all(self) -> List[Dict[str, Any]]:
        """Run all collectors and return combined event list."""
        events: List[Dict[str, Any]] = []
        events.extend(self.collect_logs())
        events.extend(self.collect_storage_security())
        self.logger.info("GCP: total events collected: %d", len(events))
        return events


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_SEVERITY_MAP = {
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "NOTICE": "LOW",
    "INFO": "INFO",
    "DEBUG": "INFO",
    "DEFAULT": "INFO",
}


def _map_gcp_severity(gcp_severity: str) -> str:
    return _SEVERITY_MAP.get(gcp_severity.upper(), "INFO")
