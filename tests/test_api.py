"""
Tests for the /api/v1/ blueprint.

Flask test client is used — no real cloud calls, no real JWT library needed
in CI (PyJWT must be installed for auth.py to import).
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Stub google/azure so collector imports don't fail
import types

def _stub(name):
    m = types.ModuleType(name)
    sys.modules.setdefault(name, m)
    return m

for _n in ["google", "google.auth", "google.auth.exceptions",
           "google.oauth2", "google.oauth2.service_account",
           "google.cloud", "google.cloud.logging", "google.cloud.storage",
           "azure", "azure.core", "azure.core.exceptions",
           "azure.identity", "azure.mgmt", "azure.mgmt.monitor",
           "azure.mgmt.security", "azure.mgmt.storage",
           "boto3", "botocore", "botocore.exceptions"]:
    _stub(_n)

from unittest.mock import MagicMock
sys.modules["google.auth"].default = MagicMock(return_value=(MagicMock(), "p"))
sys.modules["google.auth.exceptions"].DefaultCredentialsError = Exception
sys.modules["azure.core.exceptions"].ClientAuthenticationError = type("CAE", (Exception,), {})
sys.modules["azure.core.exceptions"].HttpResponseError = type("HRE", (Exception,), {})
sys.modules["azure.identity"].DefaultAzureCredential = MagicMock
sys.modules["azure.identity"].ClientSecretCredential = MagicMock
sys.modules["azure.mgmt.monitor"].MonitorManagementClient = MagicMock
sys.modules["azure.mgmt.security"].SecurityCenter = MagicMock
sys.modules["azure.mgmt.storage"].StorageManagementClient = MagicMock
sys.modules["botocore.exceptions"].ClientError = Exception
sys.modules["botocore.exceptions"].NoCredentialsError = Exception


import flask  # noqa: E402
from web.app import app  # noqa: E402


def _client():
    app.config["TESTING"] = True
    return app.test_client()


def _get_token(client, permissions=None):
    resp = client.post(
        "/api/v1/auth/token",
        json={"user_id": "test-user", "permissions": permissions or ["read", "write", "admin"]},
    )
    return resp.get_json()["token"]


class TestHealth(unittest.TestCase):
    def test_health_returns_200(self):
        c = _client()
        r = c.get("/api/v1/health")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("version", data)


class TestAuth(unittest.TestCase):
    def test_token_issued(self):
        c = _client()
        r = c.post("/api/v1/auth/token", json={"user_id": "alice", "permissions": ["read"]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("token", data)
        self.assertEqual(data["expires_in"], 86400)

    def test_token_missing_user_id_returns_400(self):
        c = _client()
        r = c.post("/api/v1/auth/token", json={})
        self.assertEqual(r.status_code, 400)

    def test_unauthenticated_alerts_returns_401(self):
        c = _client()
        r = c.get("/api/v1/alerts")
        self.assertEqual(r.status_code, 401)

    def test_bearer_token_grants_access(self):
        c = _client()
        token = _get_token(c)
        r = c.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
        self.assertNotEqual(r.status_code, 401)

    def test_api_key_grants_access(self):
        from api.auth import auth_manager
        key = auth_manager.generate_api_key("test", ["read"])
        c = _client()
        r = c.get("/api/v1/alerts", headers={"X-API-Key": key})
        self.assertNotEqual(r.status_code, 401)

    def test_insufficient_permission_returns_403(self):
        from api.auth import auth_manager
        key = auth_manager.generate_api_key("read-only", ["read"])
        c = _client()
        r = c.post("/api/v1/rules", json={}, headers={"X-API-Key": key})
        self.assertEqual(r.status_code, 403)


class TestAlerts(unittest.TestCase):
    def _auth_headers(self, c):
        return {"Authorization": f"Bearer {_get_token(c)}"}

    def test_alerts_returns_list(self):
        c = _client()
        r = c.get("/api/v1/alerts", headers=self._auth_headers(c))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("alerts", data)
        self.assertIn("total", data)
        self.assertIn("has_more", data)

    def test_pagination_params(self):
        c = _client()
        r = c.get("/api/v1/alerts?limit=5&offset=0", headers=self._auth_headers(c))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["limit"], 5)
        self.assertEqual(data["offset"], 0)

    def test_invalid_limit_falls_back_to_default(self):
        c = _client()
        r = c.get("/api/v1/alerts?limit=abc", headers=self._auth_headers(c))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["limit"], 100)

    def test_alert_not_found_returns_404(self):
        c = _client()
        r = c.get("/api/v1/alerts/nonexistent-id", headers=self._auth_headers(c))
        self.assertEqual(r.status_code, 404)


class TestRules(unittest.TestCase):
    def _auth_headers(self, c):
        return {"Authorization": f"Bearer {_get_token(c)}"}

    def test_rules_returns_200(self):
        c = _client()
        r = c.get("/api/v1/rules", headers=self._auth_headers(c))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("rules", data)
        self.assertGreater(data["total"], 0)

    def test_rules_filter_by_severity(self):
        c = _client()
        r = c.get("/api/v1/rules?severity=CRITICAL", headers=self._auth_headers(c))
        self.assertEqual(r.status_code, 200)
        rules = r.get_json()["rules"]
        for rule in rules:
            self.assertEqual(rule["severity"], "CRITICAL")


class TestScans(unittest.TestCase):
    def _auth_headers(self, c):
        return {"Authorization": f"Bearer {_get_token(c)}"}

    def test_list_scans(self):
        c = _client()
        r = c.get("/api/v1/scans", headers=self._auth_headers(c))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("scans", data)

    def test_scan_not_found_returns_404(self):
        c = _client()
        r = c.get("/api/v1/scans/no-such-scan", headers=self._auth_headers(c))
        self.assertEqual(r.status_code, 404)

    def test_create_scan_invalid_provider_returns_400(self):
        c = _client()
        r = c.post(
            "/api/v1/scans",
            json={"cloud_provider": "FAKE"},
            headers=self._auth_headers(c),
        )
        self.assertEqual(r.status_code, 400)


class TestStats(unittest.TestCase):
    def test_stats(self):
        c = _client()
        token = _get_token(c)
        r = c.get("/api/v1/stats", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("total_alerts", data)
        self.assertIn("total_scans", data)
        self.assertIn("api_version", data)


class TestOpenAPI(unittest.TestCase):
    def test_spec_returns_200(self):
        c = _client()
        r = c.get("/api/docs/openapi.json")
        self.assertEqual(r.status_code, 200)
        spec = r.get_json()
        self.assertEqual(spec["openapi"], "3.0.3")
        self.assertIn("/alerts", spec["paths"])
        self.assertIn("/scans", spec["paths"])
        self.assertIn("/rules", spec["paths"])

    def test_swagger_ui_returns_200(self):
        c = _client()
        r = c.get("/api/docs/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"swagger", r.data.lower())


if __name__ == "__main__":
    unittest.main()
