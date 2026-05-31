"""
T27: Shared pytest fixtures and cloud-SDK stubs.

boto3 / google-cloud / azure are stubbed at the sys.modules level *at import
time* — before any test module imports a collector — so the whole suite runs
without the cloud SDKs installed and without real credentials.

Fixtures provided:
  sample_alerts     — a small list of alert dicts (alerts.json shape)
  sample_events     — a small list of standardised security events
  rules_file        — a tmp YAML rules file (path str)
  alerts_file       — a tmp alerts.json file (path str)
  aws_collector     — an AWSCollector with all boto3 clients mocked
  flask_client      — Flask test client for the web app
"""

import os
import sys
import types
import json
from unittest.mock import MagicMock

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)


# ---------------------------------------------------------------------------
# Cloud-SDK stubs (executed at import time, before collectors are imported)
# ---------------------------------------------------------------------------
def _module(name):
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m


def _install_cloud_stubs():
    # ---- boto3 / botocore ----
    boto3 = _module("boto3")
    boto3.client = MagicMock(name="boto3.client")
    boto3.Session = MagicMock(name="boto3.Session")
    _module("botocore")
    botocore_exc = _module("botocore.exceptions")
    botocore_exc.ClientError = type("ClientError", (Exception,), {})
    botocore_exc.NoCredentialsError = type("NoCredentialsError", (Exception,), {})

    # ---- google.* ----
    google = _module("google")
    g_auth = _module("google.auth")
    g_auth.default = MagicMock(return_value=(MagicMock(), "stub-project"))
    g_auth_exc = _module("google.auth.exceptions")
    g_auth_exc.DefaultCredentialsError = type("DefaultCredentialsError", (Exception,), {})
    g_auth.exceptions = g_auth_exc
    google.auth = g_auth

    g_oauth2 = _module("google.oauth2")
    g_sa = _module("google.oauth2.service_account")
    g_sa.Credentials = MagicMock(name="Credentials")
    g_oauth2.service_account = g_sa
    google.oauth2 = g_oauth2

    g_cloud = _module("google.cloud")
    g_logging = _module("google.cloud.logging")
    g_logging.Client = MagicMock(name="logging.Client")
    g_logging.DESCENDING = "DESCENDING"
    g_storage = _module("google.cloud.storage")
    g_storage.Client = MagicMock(name="storage.Client")
    g_cloud.logging = g_logging
    g_cloud.storage = g_storage
    google.cloud = g_cloud

    # ---- azure.* ----
    azure = _module("azure")
    az_core = _module("azure.core")
    az_core_exc = _module("azure.core.exceptions")
    az_core_exc.ClientAuthenticationError = type("ClientAuthenticationError", (Exception,), {})
    az_core_exc.HttpResponseError = type("HttpResponseError", (Exception,), {})
    az_core.exceptions = az_core_exc
    azure.core = az_core

    az_identity = _module("azure.identity")
    az_identity.DefaultAzureCredential = MagicMock(name="DefaultAzureCredential")
    az_identity.ClientSecretCredential = MagicMock(name="ClientSecretCredential")
    azure.identity = az_identity

    az_mgmt = _module("azure.mgmt")
    az_monitor = _module("azure.mgmt.monitor")
    az_monitor.MonitorManagementClient = MagicMock(name="MonitorManagementClient")
    az_security = _module("azure.mgmt.security")
    az_security.SecurityCenter = MagicMock(name="SecurityCenter")
    az_storage = _module("azure.mgmt.storage")
    az_storage.StorageManagementClient = MagicMock(name="StorageManagementClient")
    az_mgmt.monitor = az_monitor
    az_mgmt.security = az_security
    az_mgmt.storage = az_storage
    azure.mgmt = az_mgmt


_install_cloud_stubs()


# ---------------------------------------------------------------------------
# Data fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_alerts():
    """Alerts in alerts.json shape (rule_id, severity, status, log_excerpt…)."""
    return [
        {
            "timestamp": "2025-10-02T10:00:00+00:00",
            "rule_id": "EC2-SG-001",
            "title": "SSH open to world",
            "description": "Security group allows SSH from anywhere",
            "severity": "CRITICAL",
            "remediation": "Restrict SSH access",
            "service": "EC2",
            "status": "OPEN",
            "log_excerpt": {"source": "AWS_EC2_SG", "resource_id": "sg-001"},
        },
        {
            "timestamp": "2025-10-02T10:05:00+00:00",
            "rule_id": "EC2-SG-001",
            "title": "SSH open to world",
            "description": "Security group allows SSH from anywhere",
            "severity": "HIGH",
            "remediation": "Restrict SSH access",
            "service": "EC2",
            "status": "OPEN",
            "log_excerpt": {"source": "AWS_EC2_SG", "resource_id": "sg-001"},
        },
        {
            "timestamp": "2025-10-02T09:00:00+00:00",
            "rule_id": "IAM-USER-001",
            "title": "User without MFA",
            "description": "IAM user has no MFA device",
            "severity": "MEDIUM",
            "remediation": "Enable MFA",
            "service": "IAM",
            "status": "OPEN",
            "log_excerpt": {"source": "AWS_IAM", "resource_id": "user/alice"},
        },
    ]


@pytest.fixture
def sample_events():
    """Standardised security events (collector output / rule-engine input)."""
    return [
        {
            "timestamp": "2025-10-02T10:00:00Z",
            "source": "AWS_EC2_SG",
            "resource_id": "sg-001",
            "event_type": "SECURITY_GROUP_RULE",
            "severity": "CRITICAL",
            "description": "tcp from 0.0.0.0/0 on 22",
            "sg": {"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"},
        },
        {
            "timestamp": "2025-10-02T10:01:00Z",
            "source": "AWS_S3",
            "resource_id": "my-bucket",
            "event_type": "BUCKET_ACL",
            "severity": "HIGH",
            "description": "bucket is public",
            "public": True,
        },
    ]


@pytest.fixture
def rules_file(tmp_path):
    """A tmp YAML rules file matching security_rules.yaml shape."""
    rules = {
        "rules": [
            {
                "id": "EC2-SG-001",
                "title": "SSH open to world",
                "description": "SG allows SSH from anywhere",
                "service": "EC2",
                "owasp": "A05:2021 Security Misconfiguration",
                "condition": 'source == "AWS_EC2_SG" and sg.cidr == "0.0.0.0/0" and sg.from_port == 22',
                "severity": "CRITICAL",
                "remediation": "Restrict SSH",
            },
            {
                "id": "S3-PUB-001",
                "title": "Public S3 bucket",
                "description": "bucket is public",
                "service": "S3",
                "owasp": "A01:2021 Broken Access Control",
                "condition": 'source == "AWS_S3" and public == "True"',
                "severity": "HIGH",
                "remediation": "Disable public access",
            },
        ]
    }
    p = tmp_path / "rules.yaml"
    p.write_text(yaml.safe_dump(rules))
    return str(p)


@pytest.fixture
def alerts_file(tmp_path, sample_alerts):
    p = tmp_path / "alerts.json"
    p.write_text(json.dumps({"timestamp": "2025-10-02T10:00:00+00:00",
                             "total_alerts": len(sample_alerts),
                             "alerts": sample_alerts}))
    return str(p)


# ---------------------------------------------------------------------------
# Collector / app fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def aws_collector():
    """AWSCollector with all boto3 clients mocked (no real AWS calls)."""
    from collector.aws_collector import AWSCollector
    return AWSCollector(region="us-east-1", max_events=10)


@pytest.fixture
def flask_client():
    from web.app import app
    app.config["TESTING"] = True
    return app.test_client()
