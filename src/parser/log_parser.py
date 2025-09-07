"""
CloudHawk Log Parser
--------------------
Normalizes raw logs from collectors (AWS, GCP, Azure) into a common JSON schema.

Schema:
{
    "timestamp": str,        # UTC timestamp
    "source": str,           # AWS_EC2, AWS_S3, AWS_IAM, AWS_CLOUDTRAIL, etc.
    "resource_id": str,      # Instance ID, Bucket name, User, etc.
    "event_type": str,       # Type of event (SECURITY_GROUP, S3_POLICY, IAM_ROLE, CLOUDTRAIL_EVENT, etc.)
    "severity": str,         # LOW / MEDIUM / HIGH / CRITICAL
    "description": str,      # Human-readable summary
    "raw_event": dict        # Original raw log for reference
}
"""

import datetime
import json


class LogParser:
    def __init__(self):
        pass

    # ------------------ Normalizers ------------------ #

    def normalize_ec2(self, ec2_data):
        """Normalize EC2 & Security Group data"""
        events = []
        for sg in ec2_data.get("security_groups", []):
            for rule in sg.get("IpPermissions", []):
                cidrs = [ip["CidrIp"] for ip in rule.get("IpRanges", []) if "CidrIp" in ip]
                for cidr in cidrs:
                    severity = "LOW"
                    if rule.get("FromPort") in [22, 3389] and cidr == "0.0.0.0/0":
                        severity = "HIGH"

                    events.append({
                        "timestamp": datetime.datetime.utcnow().isoformat(),
                        "source": "AWS_EC2",
                        "resource_id": sg.get("GroupId"),
                        "event_type": "SECURITY_GROUP",
                        "severity": severity,
                        "description": f"Security group {sg.get('GroupName')} allows {rule.get('IpProtocol')} "
                                       f"from {cidr} on ports {rule.get('FromPort')}-{rule.get('ToPort')}",
                        "raw_event": sg
                    })
        return events

    def normalize_s3(self, s3_data):
        """Normalize S3 bucket policies"""
        events = []
        for bucket in s3_data:
            severity = "LOW"
            desc = f"S3 bucket {bucket['name']} configuration collected."

            if bucket.get("acl") != "N/A":
                for grant in bucket["acl"].get("Grants", []):
                    if "AllUsers" in str(grant) or "AuthenticatedUsers" in str(grant):
                        severity = "HIGH"
                        desc = f"S3 bucket {bucket['name']} is publicly accessible!"

            if bucket.get("encryption") == "Not enabled":
                severity = "MEDIUM"
                desc = f"S3 bucket {bucket['name']} has no encryption enabled."

            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_S3",
                "resource_id": bucket["name"],
                "event_type": "S3_POLICY",
                "severity": severity,
                "description": desc,
                "raw_event": bucket
            })
        return events

    def normalize_iam(self, iam_data):
        """Normalize IAM user/role data"""
        events = []
        for user in iam_data.get("users", []):
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_IAM",
                "resource_id": user.get("UserName"),
                "event_type": "IAM_USER",
                "severity": "LOW",
                "description": f"IAM user {user.get('UserName')} detected.",
                "raw_event": user
            })
        for role in iam_data.get("roles", []):
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_IAM",
                "resource_id": role.get("RoleName"),
                "event_type": "IAM_ROLE",
                "severity": "LOW",
                "description": f"IAM role {role.get('RoleName')} detected.",
                "raw_event": role
            })
        return events

    def normalize_cloudtrail(self, cloudtrail_data):
        """Normalize CloudTrail logs"""
        events = []
        for event in cloudtrail_data:
            events.append({
                "timestamp": event.get("eventTime", datetime.datetime.utcnow().isoformat()),
                "source": "AWS_CLOUDTRAIL",
                "resource_id": event.get("userIdentity", {}).get("arn", "unknown"),
                "event_type": event.get("eventName", "CloudTrailEvent"),
                "severity": "LOW",
                "description": f"CloudTrail event {event.get('eventName')} by {event.get('userIdentity', {}).get('arn', 'unknown')}",
                "raw_event": event
            })
        return events

    # ------------------ Integration ------------------ #

    def parse_all(self, collector):
        """
        Runs all AWS collectors and normalizes output into events.
        """
        events = []

        # EC2
        try:
            ec2_raw = collector.collect_ec2()
            events.extend(self.normalize_ec2(ec2_raw))
        except Exception as e:
            print(f"⚠️ EC2 parse failed: {e}")

        # S3
        try:
            s3_raw = collector.collect_s3()
            events.extend(self.normalize_s3(s3_raw))
        except Exception as e:
            print(f"⚠️ S3 parse failed: {e}")

        # IAM
        try:
            iam_raw = collector.collect_iam()
            events.extend(self.normalize_iam(iam_raw))
        except Exception as e:
            print(f"⚠️ IAM parse failed: {e}")

        # CloudTrail
        try:
            cloudtrail_raw = collector.collect_cloudtrail()
            events.extend(self.normalize_cloudtrail(cloudtrail_raw))
        except Exception as e:
            print(f"⚠️ CloudTrail parse failed: {e}")

        return events


if __name__ == "__main__":
    # Demo integration
    from collector.aws_collector import AWSCollector

    collector = AWSCollector(region="us-east-1")
    parser = LogParser()

    parsed_events = parser.parse_all(collector)

    print(json.dumps(parsed_events, indent=2))
