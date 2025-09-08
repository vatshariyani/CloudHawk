"""
CloudHawk AWS Collector
Collects metadata and logs from AWS services:
- EC2 Instances & Security Groups
- S3 Buckets & Policies
- IAM Users & Roles
- CloudTrail Events

- EKS Audit Logs
- Application Logs (CloudWatch)
- AWS Config Changes
- CloudTrail Events
- S3 Access Logs
- VPC Flow Logs
- CloudWatch Logs
- GuardDuty Findings
- Inspector Findings
- System Logs (via SSM)
- ALB/ELB Access Logs
- WAF Logs

Requires AWS credentials (from `aws configure` or IAM role).
"""

import boto3
import json
import datetime
import os

class AWSCollector:
    def __init__(self, region="us-east-1"):
        self.ec2 = boto3.client("ec2", region_name=region)
        self.s3 = boto3.client("s3", region_name=region)
        self.iam = boto3.client("iam", region_name=region)
        self.cloudtrail = boto3.client("cloudtrail", region_name=region)
        self.logs = boto3.client("logs", region_name=region) #cloudwatch logs
        self.ssm = boto3.client("ssm", region_name=region) #system logs
        self.config = boto3.client("config", region_name=region)      # AWS Config
        self.guardduty = boto3.client("guardduty", region_name=region)
        self.inspector = boto3.client("inspector2", region_name=region)  # Inspector v2
        self.elb = boto3.client("elbv2", region_name=region)          # ALB/NLB Logs
        self.waf = boto3.client("wafv2", region_name=region)          # WAF Logs
        self.eks = boto3.client("eks", region_name=region) 

    def collect_ec2(self):
        """Fetch all EC2 instances & security groups"""
        events = []
        try:
            sgs = self.ec2.describe_security_groups()
            for sg in sgs.get("SecurityGroups", []):
                for rule in sg.get("IpPermissions", []):
                    cidrs = [ip.get("CidrIp") for ip in rule.get("IpRanges", []) if "CidrIp" in ip]
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
                            "raw_event": sg,
                            # Add rule-compatible fields
                            "sg": {
                                "name": sg.get("GroupName"),
                                "id": sg.get("GroupId"),
                                "rules": f"{rule.get('IpProtocol')}/{rule.get('FromPort')}-{rule.get('ToPort')},{cidr}"
                            }
                        })
        except Exception as e:
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_EC2",
                "resource_id": "N/A",
                "event_type": "ERROR",
                "severity": "CRITICAL",
                "description": f"⚠️ EC2 collection failed: {e}",
                "raw_event": {}
            })
        return events

    def collect_s3(self):
        """Fetch S3 buckets and their policies/ACLs, parsed into CloudHawk schema"""
        events = []
        try:
            buckets = self.s3.list_buckets()
            for b in buckets.get("Buckets", []):
                bucket_name = b["Name"]

                # Base bucket info
                bucket_info = {"name": bucket_name}
                severity = "LOW"
                desc = f"S3 bucket {bucket_name} configuration collected."

                # --- ACL check ---
                try:
                    acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                    bucket_info["acl"] = acl
                    for grant in acl.get("Grants", []):
                        if "AllUsers" in str(grant) or "AuthenticatedUsers" in str(grant):
                            severity = "HIGH"
                            desc = f"S3 bucket {bucket_name} is publicly accessible!"
                except Exception:
                    bucket_info["acl"] = "N/A"

                # --- Bucket policy ---
                try:
                    policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                    bucket_info["policy"] = json.loads(policy["Policy"])
                except Exception:
                    bucket_info["policy"] = "N/A"

                # --- Encryption check ---
                try:
                    enc = self.s3.get_bucket_encryption(Bucket=bucket_name)
                    bucket_info["encryption"] = enc
                except Exception:
                    bucket_info["encryption"] = "Not enabled"
                    if severity != "HIGH":  # don’t downgrade if already public
                        severity = "MEDIUM"
                        desc = f"S3 bucket {bucket_name} has no encryption enabled."

                # --- Append normalized event with rule-compatible structure ---
                events.append({
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "source": "AWS_S3",
                    "resource_id": bucket_name,
                    "event_type": "S3_POLICY",
                    "severity": severity,
                    "description": desc,
                    "raw_event": {
                        "name": bucket_name,
                        "acl": bucket_info.get("acl"),
                        "policy": bucket_info.get("policy"),
                        "encryption": bucket_info.get("encryption")
                    },
                    # Add rule-compatible fields
                    "bucket": {
                        "name": bucket_name,
                        "acl": bucket_info.get("acl"),
                        "policy": bucket_info.get("policy"),
                        "encryption": bucket_info.get("encryption"),
                        "publicAccessBlock": bucket_info.get("publicAccessBlock", True),
                        "logging": bucket_info.get("logging", False),
                        "versioning": bucket_info.get("versioning", False)
                    }
                })

        except Exception as e:
            print(f"⚠️ S3 collection failed: {e}")
        return events
        
    def collect_iam(self):
        """Fetch and normalize IAM users and roles"""
        events = []
        try:
            users = self.iam.list_users()
            roles = self.iam.list_roles()

            for user in users.get("Users", []):
                events.append({
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "source": "AWS_IAM",
                    "resource_id": user.get("UserName"),
                    "event_type": "IAM_USER",
                    "severity": "LOW",
                    "description": f"IAM user {user.get('UserName')} detected.",
                    "raw_event": user,
                    # Add rule-compatible fields
                    "user": {
                        "name": user.get("UserName"),
                        "lastActiveDays": 0,  # Would need additional API call to get this
                        "activeKeys": 0,  # Would need additional API call to get this
                        "previousCountries": []  # Would need additional logic to track this
                    }
                })

            for role in roles.get("Roles", []):
                events.append({
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "source": "AWS_IAM",
                    "resource_id": role.get("RoleName"),
                    "event_type": "IAM_ROLE",
                    "severity": "LOW",
                    "description": f"IAM role {role.get('RoleName')} detected.",
                    "raw_event": role,
                    # Add rule-compatible fields
                    "role": {
                        "name": role.get("RoleName"),
                        "trustPolicy": role.get("AssumeRolePolicyDocument", {})
                    }
                })

        except Exception as e:
            print(f"⚠️ IAM collection failed: {e}")
        return events
        
    def collect_cloudtrail(self, max_events=100):
        """Fetch and normalize CloudTrail events with severity rules"""
        events = []
        try:
            response = self.cloudtrail.lookup_events(MaxResults=max_events)
            for e in response.get("Events", []):
                try:
                    event = json.loads(e["CloudTrailEvent"])
                except Exception:
                    event = e  # fallback if parsing fails

                event_name = event.get("eventName", "CloudTrailEvent")
                user = event.get("userIdentity", {}).get("arn", "unknown")

                # 🔹 Default severity
                severity = "LOW"

                # 🔹 Escalate severity based on event type
                high_risk_events = [
                    "DeleteBucket", "DeleteUser", "DeleteRole", "DeletePolicy",
                    "StopLogging", "ConsoleLogin", "TerminateInstances",
                    "PutBucketPolicy", "CreateAccessKey", "AttachUserPolicy"
                ]
                medium_risk_events = [
                    "UpdateLoginProfile", "CreateUser", "CreateRole", "StartInstances",
                    "AuthorizeSecurityGroupIngress", "PutBucketAcl"
                ]

                if event_name in high_risk_events:
                    severity = "HIGH"
                elif event_name in medium_risk_events:
                    severity = "MEDIUM"

                events.append({
                    "timestamp": event.get("eventTime", datetime.datetime.utcnow().isoformat()),
                    "source": "AWS_CLOUDTRAIL",
                    "resource_id": user,
                    "event_type": event_name,
                    "severity": severity,
                    "description": f"CloudTrail event {event_name} by {user}",
                    "raw_event": event,
                    # Add rule-compatible fields
                    "event": {
                        "action": event_name,
                        "user": user,
                        "mfa": event.get("userIdentity", {}).get("mfaAuthenticated", False),
                        "authType": event.get("userIdentity", {}).get("type", "unknown"),
                        "errorCode": event.get("errorCode"),
                        "region": event.get("awsRegion"),
                        "sourceIPAddress": event.get("sourceIPAddress")
                    }
                })

        except Exception as e:
            print(f"⚠️ CloudTrail collection failed: {e}")
        return events

    
    def collect_cloudwatch_logs(self, max_log_groups=5, max_events=10):
        """Fetch and normalize CloudWatch log events"""
        events = []
        try:
            log_groups = self.logs.describe_log_groups(limit=max_log_groups)
            for group in log_groups.get("logGroups", []):
                group_name = group["logGroupName"]
                try:
                    streams = self.logs.describe_log_streams(
                        logGroupName=group_name,
                        orderBy="LastEventTime",
                        descending=True,
                        limit=1
                    )
                    if streams.get("logStreams"):
                        stream_name = streams["logStreams"][0]["logStreamName"]
                        log_events = self.logs.get_log_events(
                            logGroupName=group_name,
                            logStreamName=stream_name,
                            limit=max_events
                        )
                        for e in log_events.get("events", []):
                            events.append({
                                "timestamp": e.get("timestamp"),
                                "source": "AWS_CLOUDWATCH",
                                "resource_id": group_name,
                                "event_type": "LogEvent",
                                "severity": "LOW",
                                "description": f"Log event in {group_name}",
                                "raw_event": e
                            })
                except Exception as e:
                    events.append({
                        "timestamp": datetime.datetime.utcnow().isoformat(),
                        "source": "AWS_CLOUDWATCH",
                        "resource_id": group_name,
                        "event_type": "ERROR",
                        "severity": "MEDIUM",
                        "description": f"Failed to fetch logs: {e}",
                        "raw_event": {}
                    })
        except Exception as e:
            print(f"⚠️ CloudWatch Logs collection failed: {e}")
        return events


    def collect_ssm_logs(self, max_results=10):
        """Fetch and normalize SSM command/session logs"""
        events = []
        try:
            commands = self.ssm.list_command_invocations(MaxResults=max_results, Details=True)
            for c in commands.get("CommandInvocations", []):
                events.append({
                    "timestamp": c.get("RequestedDateTime"),
                    "source": "AWS_SSM",
                    "resource_id": c.get("InstanceId", "unknown"),
                    "event_type": "CommandInvocation",
                    "severity": "MEDIUM" if c.get("Status") != "Success" else "LOW",
                    "description": f"SSM command executed: {c.get('CommandId')}",
                    "raw_event": c
                })

            sessions = self.ssm.describe_sessions(State="History", MaxResults=max_results)
            for s in sessions.get("Sessions", []):
                events.append({
                    "timestamp": s.get("StartDate"),
                    "source": "AWS_SSM",
                    "resource_id": s.get("SessionId", "unknown"),
                    "event_type": "Session",
                    "severity": "LOW",
                    "description": f"SSM session by {s.get('Owner')} on {s.get('Target')}",
                    "raw_event": s
                })
        except Exception as e:
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_SSM",
                "resource_id": "N/A",
                "event_type": "ERROR",
                "severity": "HIGH",
                "description": f"SSM logs collection failed: {e}",
                "raw_event": {}
            })
        return events


    def collect_config_changes(self, max_results=20):
        """Normalize AWS Config changes"""
        events = []
        try:
            response = self.config.get_resource_config_history(
                resourceType="AWS::EC2::Instance", limit=max_results
            )
            for item in response.get("configurationItems", []):
                events.append({
                    "timestamp": item.get("configurationItemCaptureTime"),
                    "source": "AWS_CONFIG",
                    "resource_id": item.get("resourceId"),
                    "event_type": "ConfigChange",
                    "severity": "MEDIUM" if item.get("configurationItemStatus") != "OK" else "LOW",
                    "description": f"Config change detected for {item.get('resourceName')}",
                    "raw_event": item
                })
        except Exception as e:
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_CONFIG",
                "resource_id": "N/A",
                "event_type": "ERROR",
                "severity": "HIGH",
                "description": f"Config collection failed: {e}",
                "raw_event": {}
            })
        return events


    def collect_guardduty(self):
        """Normalize GuardDuty findings"""
        events = []
        try:
            detectors = self.guardduty.list_detectors().get("detectorIds", [])
            for d in detectors:
                f = self.guardduty.list_findings(DetectorId=d)
                if f.get("FindingIds"):
                    details = self.guardduty.get_findings(DetectorId=d, FindingIds=f["FindingIds"])
                    for finding in details.get("Findings", []):
                        events.append({
                            "timestamp": finding.get("UpdatedAt"),
                            "source": "AWS_GUARDDUTY",
                            "resource_id": finding.get("Resource", {}).get("InstanceDetails", {}).get("InstanceId", "unknown"),
                            "event_type": finding.get("Type"),
                            "severity": finding.get("Severity"),
                            "description": finding.get("Title", "GuardDuty finding"),
                            "raw_event": finding
                        })
        except Exception as e:
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_GUARDDUTY",
                "resource_id": "N/A",
                "event_type": "ERROR",
                "severity": "HIGH",
                "description": f"GuardDuty collection failed: {e}",
                "raw_event": {}
            })
        return events


    def collect_inspector(self, max_results=20):
        """Normalize Inspector findings"""
        events = []
        try:
            response = self.inspector.list_findings(maxResults=max_results)
            if response.get("findings"):
                for finding in response["findings"]:
                    events.append({
                        "timestamp": finding.get("firstObservedAt"),
                        "source": "AWS_INSPECTOR",
                        "resource_id": finding.get("resourceId", "unknown"),
                        "event_type": finding.get("type", "InspectorFinding"),
                        "severity": finding.get("severity", "MEDIUM"),
                        "description": finding.get("title", "Inspector finding"),
                        "raw_event": finding
                    })
        except Exception as e:
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_INSPECTOR",
                "resource_id": "N/A",
                "event_type": "ERROR",
                "severity": "HIGH",
                "description": f"Inspector collection failed: {e}",
                "raw_event": {}
            })
        return events


    def collect_vpc_flow_logs(self, log_group="/aws/vpc/flow", max_events=20):
        """Normalize VPC Flow log entries"""
        events = []
        try:
            streams = self.logs.describe_log_streams(
                logGroupName=log_group, orderBy="LastEventTime", descending=True, limit=1
            )
            if streams.get("logStreams"):
                stream_name = streams["logStreams"][0]["logStreamName"]
                log_events = self.logs.get_log_events(
                    logGroupName=log_group, logStreamName=stream_name, limit=max_events
                )
                for e in log_events.get("events", []):
                    events.append({
                        "timestamp": e.get("timestamp"),
                        "source": "AWS_VPC_FLOW",
                        "resource_id": log_group,
                        "event_type": "FlowLog",
                        "severity": "LOW",
                        "description": f"VPC flow log event in {log_group}",
                        "raw_event": e
                    })
        except Exception as e:
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_VPC_FLOW",
                "resource_id": "N/A",
                "event_type": "ERROR",
                "severity": "HIGH",
                "description": f"VPC Flow Logs failed: {e}",
                "raw_event": {}
            })
        return events


    def collect_s3_access_logs(self, bucket_name, max_keys=5):
        """Normalize S3 access logs (raw object keys)"""
        events = []
        try:
            response = self.s3.list_objects_v2(Bucket=bucket_name, MaxKeys=max_keys)
            for obj in response.get("Contents", []):
                events.append({
                    "timestamp": obj.get("LastModified"),
                    "source": "AWS_S3_ACCESS",
                    "resource_id": bucket_name,
                    "event_type": "AccessLog",
                    "severity": "LOW",
                    "description": f"S3 access log object: {obj['Key']}",
                    "raw_event": obj
                })
        except Exception as e:
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_S3_ACCESS",
                "resource_id": bucket_name,
                "event_type": "ERROR",
                "severity": "HIGH",
                "description": f"S3 Access Logs failed: {e}",
                "raw_event": {}
            })
        return events

    def collect_alb_logs(self, bucket_name, max_keys=5):
        """ALB/ELB access logs are stored in S3"""
        return self.collect_s3_access_logs(bucket_name, max_keys)

    def collect_waf_logs(self, log_group="/aws/waf/logs", max_events=20):
        """Normalize WAF log events"""
        events = []
        try:
            streams = self.logs.describe_log_streams(
                logGroupName=log_group, orderBy="LastEventTime", descending=True, limit=1
            )
            if streams.get("logStreams"):
                stream_name = streams["logStreams"][0]["logStreamName"]
                log_events = self.logs.get_log_events(
                    logGroupName=log_group, logStreamName=stream_name, limit=max_events
                )
                for e in log_events.get("events", []):
                    events.append({
                        "timestamp": e.get("timestamp"),
                        "source": "AWS_WAF",
                        "resource_id": log_group,
                        "event_type": "WAFLog",
                        "severity": "MEDIUM",
                        "description": f"WAF log event in {log_group}",
                        "raw_event": e
                    })
        except Exception as e:
            events.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source": "AWS_WAF",
                "resource_id": "N/A",
                "event_type": "ERROR",
                "severity": "HIGH",
                "description": f"WAF Logs failed: {e}",
                "raw_event": {}
            })
        return events

    def collect_eks_audit_logs(self, cluster_name, log_group="/aws/eks/cluster/audit", max_events=10):
        """EKS audit logs"""
        logs = self.collect_cloudwatch_logs(max_log_groups=1, max_events=max_events)
        for e in logs:
            e["source"] = "AWS_EKS_AUDIT"
            e["resource_id"] = cluster_name
            e["description"] = f"EKS audit log for cluster {cluster_name}"
        return logs

    def collect_app_logs(self, log_group, max_events=10):
        """Application logs in CloudWatch"""
        logs = self.collect_cloudwatch_logs(max_log_groups=1, max_events=max_events)
        for e in logs:
            e["source"] = "AWS_APP_LOGS"
            e["resource_id"] = log_group
            e["description"] = f"Application log from {log_group}"
        return logs

if __name__ == "__main__":
    collector = AWSCollector(region="us-east-1")
    
    print("\n=== EC2 Data ===")
    ec2_events = collector.collect_ec2()
#    print(json.dumps(ec2_events, indent=2, default=str))
    
    print("\n=== S3 Data ===")
    s3_events = collector.collect_s3()
#    print(json.dumps(s3_events, indent=2, default=str))
    
    print("\n=== IAM Data ===")
    iam_events = collector.collect_iam()
#    print(json.dumps(iam_events, indent=2, default=str))
    
    print("\n=== CloudTrail Logs ===")
    cloudtrail_events = collector.collect_cloudtrail()
#    print(json.dumps(cloudtrail_events, indent=2, default=str))
    
    print("\n=== CloudWatch Logs ===")
    cloudwatch_logs = collector.collect_cloudwatch_logs()
#    print(json.dumps(cloudwatch_logs, indent=2, default=str))
    
    print("\n=== SSM Logs ===")
    ssm_logs = collector.collect_ssm_logs()
#    print(json.dumps(ssm_logs, indent=2, default=str))
    
    print("\n=== AWS Config ===")
    config_changes = collector.collect_config_changes()
#    print(json.dumps(config_changes, indent=2, default=str))

    print("\n=== GuardDuty Findings ===")
    guardduty_findings = collector.collect_guardduty()
#    print(json.dumps(guardduty_findings, indent=2, default=str))

    print("\n=== Inspector Findings ===")
    inspector_findings = collector.collect_inspector()
#    print(json.dumps(inspector_findings, indent=2, default=str))

    print("\n=== VPC Flow Logs ===")
    vpc_flow = collector.collect_vpc_flow_logs()
#    print(json.dumps(vpc_flow, indent=2, default=str))

    print("\n=== S3 Access Logs (replace with your bucket name) ===")
    s3_access = collector.collect_s3_access_logs("my-s3-logs-bucket")
#    print(json.dumps(s3_access, indent=2, default=str))

    print("\n=== ALB/ELB Logs (replace with your bucket name) ===")
    alb_logs = collector.collect_alb_logs("my-elb-logs-bucket")
#    print(json.dumps(alb_logs, indent=2, default=str))

    print("\n=== WAF Logs ===")
    waf_logs = collector.collect_waf_logs()
#    print(json.dumps(waf_logs, indent=2, default=str))
    
    print("\n=== EKS Audit Logs (replace with your cluster name & log group) ===")
    eks_audit_logs = collector.collect_eks_audit_logs("my-eks-cluster")
#    print(json.dumps(eks_audit_logs, indent=2, default=str))

    print("\n=== Application Logs (replace with your app log group) ===")
    app_logs = collector.collect_app_logs("/my/app/logs")
#    print(json.dumps(app_logs, indent=2, default=str))
    
    # Categorize
    misconfig_events = ec2_events + s3_events + config_changes
    iam_misuse_events = iam_events
    activity_events = cloudtrail_events + cloudwatch_logs + ssm_logs + app_logs + eks_audit_logs
    threat_detection = guardduty_findings + inspector_findings + waf_logs
    traffic_logs = vpc_flow + s3_access + alb_logs
    All_Logs = misconfig_events + iam_misuse_events + activity_events + threat_detection + traffic_logs
    
    
    # Write to files
    def save_logs(filename, events):
        # Ensure logs directory exists
        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        with open(os.path.join(logs_dir, filename), "w") as f:
            json.dump(events, f, indent=2, default=str)

    save_logs("misconfigurations.json", misconfig_events)
    save_logs("iam_misuse.json", iam_misuse_events)
    save_logs("activity_logs.json", activity_events)
    save_logs("threat_detection.json", threat_detection)
    save_logs("traffic_logs.json", traffic_logs)
    save_logs("All_Logs.json", All_Logs)

    print("✅ Logs saved in logs/ folder")
