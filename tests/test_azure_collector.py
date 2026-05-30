"""
Tests for AzureCollector. Azure SDK packages are mocked at the sys.modules
level so these run without Azure credentials or the SDK installed.
"""

import sys
import os
import types
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ---------------------------------------------------------------------------
# Stub out azure.* packages before the collector module is imported
# ---------------------------------------------------------------------------
def _stub_azure_modules():
    def _mod(name):
        return types.ModuleType(name)

    azure = _mod("azure")
    azure.core = _mod("azure.core")
    azure.core.exceptions = _mod("azure.core.exceptions")
    azure.core.exceptions.ClientAuthenticationError = type("ClientAuthenticationError", (Exception,), {})
    azure.core.exceptions.HttpResponseError = type("HttpResponseError", (Exception,), {})

    azure.identity = _mod("azure.identity")
    azure.identity.DefaultAzureCredential = MagicMock
    azure.identity.ClientSecretCredential = MagicMock

    azure.mgmt = _mod("azure.mgmt")

    azure.mgmt.monitor = _mod("azure.mgmt.monitor")
    azure.mgmt.monitor.MonitorManagementClient = MagicMock

    azure.mgmt.security = _mod("azure.mgmt.security")
    azure.mgmt.security.SecurityCenter = MagicMock

    azure.mgmt.storage = _mod("azure.mgmt.storage")
    azure.mgmt.storage.StorageManagementClient = MagicMock

    for name, mod in [
        ("azure", azure),
        ("azure.core", azure.core),
        ("azure.core.exceptions", azure.core.exceptions),
        ("azure.identity", azure.identity),
        ("azure.mgmt", azure.mgmt),
        ("azure.mgmt.monitor", azure.mgmt.monitor),
        ("azure.mgmt.security", azure.mgmt.security),
        ("azure.mgmt.storage", azure.mgmt.storage),
    ]:
        sys.modules[name] = mod


_stub_azure_modules()

from collector.azure_collector import AzureCollector, _map_azure_level, _map_asc_severity  # noqa: E402

CONFIG = {
    "azure": {
        "subscription_id": "sub-1234",
        "max_events_per_service": 10,
        "hours_back": 1,
    }
}


def _make_collector():
    return AzureCollector(CONFIG)


class TestAzureCollectorInit(unittest.TestCase):
    def test_subscription_id_set(self):
        c = _make_collector()
        self.assertEqual(c.subscription_id, "sub-1234")

    def test_max_events_set(self):
        c = _make_collector()
        self.assertEqual(c.max_events, 10)

    def test_missing_subscription_raises(self):
        with self.assertRaises((ValueError, RuntimeError)):
            AzureCollector({"azure": {}})


class TestCollectActivityLogs(unittest.TestCase):
    def test_returns_list(self):
        c = _make_collector()
        mock_monitor = MagicMock()
        mock_monitor.activity_logs.list.return_value = []
        c._monitor_client = mock_monitor
        self.assertIsInstance(c.collect_activity_logs(), list)

    def test_api_error_yields_error_event(self):
        c = _make_collector()
        mock_monitor = MagicMock()
        mock_monitor.activity_logs.list.side_effect = Exception("network error")
        c._monitor_client = mock_monitor
        events = c.collect_activity_logs()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "COLLECTION_ERROR")
        self.assertEqual(events[0]["source"], "AZURE_COLLECTOR")

    def test_event_schema(self):
        c = _make_collector()
        ev = c._event("SRC", "res-1", "TEST_TYPE", "HIGH", "desc", {})
        for field in ("timestamp", "cloud", "source", "resource_id", "event_type",
                      "severity", "description", "subscription_id", "raw_event"):
            self.assertIn(field, ev)
        self.assertEqual(ev["cloud"], "azure")
        self.assertEqual(ev["subscription_id"], "sub-1234")


class TestCollectSecurityAlerts(unittest.TestCase):
    def test_api_error_yields_error_event(self):
        c = _make_collector()
        mock_sec = MagicMock()
        mock_sec.alerts.list.side_effect = Exception("auth error")
        c._security_client = mock_sec
        events = c.collect_security_alerts()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "COLLECTION_ERROR")

    def test_alert_parsed(self):
        c = _make_collector()
        mock_sec = MagicMock()
        alert = MagicMock()
        alert.alert_type = "VM_SUSPICIOUS_PROCESS"
        alert.alert_severity = "High"
        alert.display_name = "Suspicious process on VM"
        alert.compromised_entity = "/subscriptions/sub-1234/vms/vm1"
        alert.id = "alert-001"
        alert.start_date_time_utc = None
        mock_sec.alerts.list.return_value = [alert]
        c._security_client = mock_sec
        events = c.collect_security_alerts()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "AZURE_SECURITY_CENTER")
        self.assertEqual(events[0]["severity"], "HIGH")


class TestCollectStorageSecurity(unittest.TestCase):
    def test_api_error_yields_error_event(self):
        c = _make_collector()
        mock_storage = MagicMock()
        mock_storage.storage_accounts.list.side_effect = Exception("forbidden")
        c._storage_client = mock_storage
        events = c.collect_storage_security()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "COLLECTION_ERROR")

    def test_public_access_detected(self):
        c = _make_collector()
        mock_storage = MagicMock()
        account = MagicMock()
        account.name = "mystorage"
        account.id = "/subscriptions/sub-1234/storageAccounts/mystorage"
        account.enable_https_traffic_only = True
        account.allow_blob_public_access = True
        account.encryption = MagicMock()
        mock_storage.storage_accounts.list.return_value = [account]
        c._storage_client = mock_storage
        events = c.collect_storage_security()
        types_ = {e["event_type"] for e in events}
        self.assertIn("STORAGE_PUBLIC_BLOB_ACCESS", types_)

    def test_http_allowed_detected(self):
        c = _make_collector()
        mock_storage = MagicMock()
        account = MagicMock()
        account.name = "mystorage"
        account.id = "/subscriptions/sub-1234/storageAccounts/mystorage"
        account.enable_https_traffic_only = False
        account.allow_blob_public_access = False
        account.encryption = MagicMock()
        mock_storage.storage_accounts.list.return_value = [account]
        c._storage_client = mock_storage
        events = c.collect_storage_security()
        types_ = {e["event_type"] for e in events}
        self.assertIn("STORAGE_HTTP_ALLOWED", types_)


class TestHelpers(unittest.TestCase):
    def test_level_map(self):
        self.assertEqual(_map_azure_level("Critical"), "CRITICAL")
        self.assertEqual(_map_azure_level("Error"), "HIGH")
        self.assertEqual(_map_azure_level("Warning"), "MEDIUM")
        self.assertEqual(_map_azure_level("Informational"), "INFO")
        self.assertEqual(_map_azure_level("Unknown"), "INFO")

    def test_asc_severity_map(self):
        self.assertEqual(_map_asc_severity("High"), "HIGH")
        self.assertEqual(_map_asc_severity("Medium"), "MEDIUM")
        self.assertEqual(_map_asc_severity("Low"), "LOW")
        self.assertEqual(_map_asc_severity("Unknown"), "MEDIUM")


if __name__ == "__main__":
    unittest.main()
