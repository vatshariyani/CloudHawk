"""
Tests for GCPCollector. google-cloud packages are mocked at the sys.modules
level so these run without GCP credentials or the SDK installed.
"""

import sys
import os
import types
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ---------------------------------------------------------------------------
# Stub out google.* packages before the collector module is imported
# ---------------------------------------------------------------------------
def _stub_google_modules():
    google = types.ModuleType("google")
    google.auth = types.ModuleType("google.auth")
    google.auth.exceptions = types.ModuleType("google.auth.exceptions")
    google.auth.exceptions.DefaultCredentialsError = Exception
    google.auth.default = MagicMock(return_value=(MagicMock(), "stub-project"))

    google.oauth2 = types.ModuleType("google.oauth2")
    google.oauth2.service_account = types.ModuleType("google.oauth2.service_account")
    google.oauth2.service_account.Credentials = MagicMock()

    cloud = types.ModuleType("google.cloud")

    # google.cloud.logging stub
    cl = types.ModuleType("google.cloud.logging")
    cl.Client = MagicMock()
    cl.DESCENDING = "DESCENDING"
    cloud.logging = cl

    # google.cloud.storage stub
    cs = types.ModuleType("google.cloud.storage")
    cs.Client = MagicMock()
    cloud.storage = cs

    google.cloud = cloud

    for name in [
        "google",
        "google.auth",
        "google.auth.exceptions",
        "google.oauth2",
        "google.oauth2.service_account",
        "google.cloud",
        "google.cloud.logging",
        "google.cloud.storage",
    ]:
        sys.modules.setdefault(name, eval(name.replace("google.", "google.", 1)))

    # simpler: just set them all directly
    sys.modules["google"] = google
    sys.modules["google.auth"] = google.auth
    sys.modules["google.auth.exceptions"] = google.auth.exceptions
    sys.modules["google.oauth2"] = google.oauth2
    sys.modules["google.oauth2.service_account"] = google.oauth2.service_account
    sys.modules["google.cloud"] = cloud
    sys.modules["google.cloud.logging"] = cl
    sys.modules["google.cloud.storage"] = cs


_stub_google_modules()

from collector.gcp_collector import GCPCollector, _map_gcp_severity  # noqa: E402

# ---------------------------------------------------------------------------
CONFIG = {
    "gcp": {
        "project_id": "test-project",
        "max_events_per_service": 10,
        "hours_back": 1,
    }
}


def _make_collector():
    sys.modules["google.auth"].default = MagicMock(return_value=(MagicMock(), "test-project"))
    return GCPCollector(CONFIG)


class TestGCPCollectorInit(unittest.TestCase):
    def test_project_id_set(self):
        c = _make_collector()
        self.assertEqual(c.project_id, "test-project")

    def test_max_events_set(self):
        c = _make_collector()
        self.assertEqual(c.max_events, 10)

    def test_missing_project_id_raises(self):
        with self.assertRaises((ValueError, RuntimeError)):
            GCPCollector({"gcp": {}})


class TestCollectLogs(unittest.TestCase):
    def test_returns_list(self):
        c = _make_collector()
        mock_client = MagicMock()
        mock_client.list_entries.return_value = []
        c._logging_client = mock_client
        self.assertIsInstance(c.collect_logs(), list)

    def test_api_error_yields_error_event(self):
        c = _make_collector()
        mock_client = MagicMock()
        mock_client.list_entries.side_effect = Exception("network error")
        c._logging_client = mock_client
        events = c.collect_logs()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "COLLECTION_ERROR")
        self.assertEqual(events[0]["source"], "GCP_COLLECTOR")

    def test_event_has_required_fields(self):
        c = _make_collector()
        ev = c._event("SRC", "res-1", "TEST_TYPE", "HIGH", "desc", {})
        for field in ("timestamp", "cloud", "source", "resource_id", "event_type",
                      "severity", "description", "project_id", "raw_event"):
            self.assertIn(field, ev)
        self.assertEqual(ev["cloud"], "gcp")
        self.assertEqual(ev["project_id"], "test-project")


class TestCollectStorageSecurity(unittest.TestCase):
    def test_api_error_yields_error_event(self):
        c = _make_collector()
        mock_storage = MagicMock()
        mock_storage.list_buckets.side_effect = Exception("auth error")
        c._storage_client = mock_storage
        events = c.collect_storage_security()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "COLLECTION_ERROR")

    def test_public_bucket_detected(self):
        c = _make_collector()
        mock_storage = MagicMock()
        bucket = MagicMock()
        bucket.name = "my-bucket"
        bucket.default_kms_key_name = "projects/p/key"
        bucket.versioning_enabled = True
        policy = MagicMock()
        policy.bindings = [{"role": "roles/storage.objectViewer", "members": {"allUsers"}}]
        bucket.get_iam_policy.return_value = policy
        mock_storage.list_buckets.return_value = [bucket]
        c._storage_client = mock_storage
        events = c.collect_storage_security()
        types_ = {e["event_type"] for e in events}
        self.assertIn("PUBLIC_BUCKET_ACCESS", types_)


class TestMapSeverity(unittest.TestCase):
    def test_known(self):
        self.assertEqual(_map_gcp_severity("CRITICAL"), "CRITICAL")
        self.assertEqual(_map_gcp_severity("ERROR"), "HIGH")
        self.assertEqual(_map_gcp_severity("WARNING"), "MEDIUM")
        self.assertEqual(_map_gcp_severity("INFO"), "INFO")

    def test_unknown_defaults_info(self):
        self.assertEqual(_map_gcp_severity("WHATEVER"), "INFO")


if __name__ == "__main__":
    unittest.main()
