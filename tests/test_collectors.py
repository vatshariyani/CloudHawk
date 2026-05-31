"""
T29: Tests for the collectors. boto3/google/azure are stubbed in conftest.py,
so these run without the SDKs installed or any real credentials.

Covers:
  - BaseCollector event-schema contract
  - AWSCollector construction + event builder + save (no dedicated test before)
  - Cross-collector consistency (every collector inherits BaseCollector)
"""

import json
import os

import pytest

from collector.base_collector import BaseCollector
from collector.aws_collector import AWSCollector


# ---------------------------------------------------------------------------
# BaseCollector contract
# ---------------------------------------------------------------------------
class _Dummy(BaseCollector):
    cloud = "test"

    def collect_all(self):
        return [self._event("SRC", "res-1", "TYPE", "HIGH", "desc", {"k": "v"})]


class TestBaseCollector:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BaseCollector()

    def test_event_has_standard_schema(self):
        ev = _Dummy()._event("SRC", "res-1", "TYPE", "HIGH", "desc", {"k": "v"})
        for field in ("timestamp", "cloud", "source", "resource_id",
                      "event_type", "severity", "description", "raw_event"):
            assert field in ev
        assert ev["cloud"] == "test"
        assert ev["resource_id"] == "res-1"

    def test_event_extra_fields_merged(self):
        ev = _Dummy()._event("S", "r", "T", "LOW", "d", {}, region="us-east-1")
        assert ev["region"] == "us-east-1"

    def test_utcnow_str_has_z_suffix(self):
        assert _Dummy.utcnow_str().endswith("Z")

    def test_collect_all_returns_events(self):
        events = _Dummy().collect_all()
        assert len(events) == 1
        assert events[0]["event_type"] == "TYPE"


# ---------------------------------------------------------------------------
# AWSCollector
# ---------------------------------------------------------------------------
class TestAWSCollector:
    def test_construction_sets_region_and_max(self, aws_collector):
        assert aws_collector.region == "us-east-1"
        assert aws_collector.max_events == 10

    def test_is_base_collector(self, aws_collector):
        assert isinstance(aws_collector, BaseCollector)
        assert aws_collector.cloud == "aws"

    def test_clients_created(self, aws_collector):
        # boto3.client is mocked → all service handles exist
        for svc in ("ec2", "s3", "iam", "cloudtrail", "guardduty"):
            assert getattr(aws_collector, svc) is not None

    def test_create_security_event_schema(self, aws_collector):
        ev = aws_collector._create_security_event(
            "AWS_S3", "bucket-1", "BUCKET_ACL", "HIGH", "public bucket", {"raw": 1}
        )
        assert ev["source"] == "AWS_S3"
        assert ev["resource_id"] == "bucket-1"
        assert ev["severity"] == "HIGH"
        assert ev["event_type"] == "BUCKET_ACL"

    def test_save_security_events_writes_file(self, aws_collector, tmp_path):
        events = [{"source": "AWS_S3", "severity": "HIGH"}]
        out = aws_collector.save_security_events(events, output_dir=str(tmp_path))
        assert os.path.exists(out)
        with open(out) as fh:
            data = json.load(fh)
        # accept either a bare list or a wrapped {"events": [...]} shape
        if isinstance(data, dict):
            data = data.get("events", data.get("security_events", []))
        assert len(data) == 1


# ---------------------------------------------------------------------------
# Cross-collector consistency
# ---------------------------------------------------------------------------
class TestCollectorConsistency:
    def test_all_collectors_inherit_base(self):
        from collector.gcp_collector import GCPCollector
        from collector.azure_collector import AzureCollector
        assert issubclass(GCPCollector, BaseCollector)
        assert issubclass(AzureCollector, BaseCollector)
        assert issubclass(AWSCollector, BaseCollector)

    def test_cloud_tags_distinct(self):
        from collector.gcp_collector import GCPCollector
        from collector.azure_collector import AzureCollector
        assert AWSCollector.cloud == "aws"
        assert GCPCollector.cloud == "gcp"
        assert AzureCollector.cloud == "azure"
