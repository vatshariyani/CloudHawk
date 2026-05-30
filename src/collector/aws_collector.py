"""
CloudHawk AWS Security Collector
Collects and parses security-relevant data from AWS services:
- IAM Users, Roles, Policies (privilege escalation detection)
- S3 Buckets & Policies (data exposure detection)
- EC2 Security Groups (network security)
- CloudTrail Events (audit trail analysis)
- GuardDuty Findings (threat detection)

Credentials are read from environment variables or the default boto3 credential
chain (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN, ~/.aws,
or an attached IAM role). Never hardcode credentials here.
"""

import boto3
import json
import datetime
import os
import logging
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError

from collector.base_collector import BaseCollector


class AWSCollector(BaseCollector):
    cloud = "aws"

    def __init__(self, region: str = "us-east-1", max_events: int = 1000):
        super().__init__()
        self.region = region
        self.max_events = max_events

        try:
            self.ec2 = boto3.client("ec2", region_name=region)
            self.s3 = boto3.client("s3", region_name=region)
            self.iam = boto3.client("iam", region_name=region)
            self.cloudtrail = boto3.client("cloudtrail", region_name=region)
            self.guardduty = boto3.client("guardduty", region_name=region)
            self._test_credentials()
        except NoCredentialsError:
            raise Exception(
                "AWS credentials not found. Set AWS_ACCESS_KEY_ID / "
                "AWS_SECRET_ACCESS_KEY environment variables or configure "
                "an IAM role."
            )
        except Exception as e:
            raise Exception(f"Failed to initialize AWS clients: {e}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _test_credentials(self) -> None:
        """Verify credentials work with a cheap read-only call."""
        try:
            self.iam.list_users(MaxItems=1)
            self.logger.info("AWS credentials validated successfully")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDenied":
                self.logger.warning("AWS credentials have limited permissions")
            else:
                raise Exception(f"AWS credential test failed: {e}")

    def _create_security_event(
        self,
        source: str,
        resource_id: str,
        event_type: str,
        severity: str,
        description: str,
        raw_event: Dict,
        additional_fields: Optional[Dict] = None,
    ) -> Dict:
        event = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source": source,
            "resource_id": resource_id,
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "raw_event": raw_event,
            "region": self.region,
        }
        if additional_fields:
            event.update(additional_fields)
        return event

    # ------------------------------------------------------------------
    # EC2
    # ------------------------------------------------------------------

    def collect_ec2_security(self) -> List[Dict]:
        events: List[Dict] = []
        try:
            # B1 fix: paginate security groups
            paginator = self.ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    events.extend(self._analyze_security_group(sg))

            # B2 fix: paginate instances
            paginator = self.ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        events.extend(self._analyze_ec2_instance(instance))

        except ClientError as e:
            events.append(
                self._create_security_event(
                    source="AWS_EC2",
                    resource_id="N/A",
                    event_type="COLLECTION_ERROR",
                    severity="CRITICAL",
                    description=f"EC2 security collection failed: {e}",
                    raw_event={"error": str(e)},
                )
            )
            self.logger.error(f"EC2 collection failed: {e}")
        return events

    def _analyze_security_group(self, sg: Dict) -> List[Dict]:
        events: List[Dict] = []
        sg_id = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unknown")

        for rule in sg.get("IpPermissions", []):
            protocol = rule.get("IpProtocol", "tcp")
            # B4 fix: FromPort/ToPort absent for protocol "-1"
            from_port: Optional[int] = rule.get("FromPort")
            to_port: Optional[int] = rule.get("ToPort")

            # IPv4
            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                severity = self._analyze_sg_rule_severity(protocol, from_port, to_port, cidr)
                events.append(
                    self._create_security_event(
                        source="AWS_EC2_SG",
                        resource_id=sg_id,
                        event_type="SECURITY_GROUP_RULE",
                        severity=severity,
                        description=(
                            f"Security group '{sg_name}' allows {protocol} "
                            f"from {cidr} on ports "
                            f"{from_port if from_port is not None else 'ALL'}-"
                            f"{to_port if to_port is not None else 'ALL'}"
                        ),
                        raw_event=sg,
                        additional_fields={
                            "sg": {
                                "name": sg_name,
                                "id": sg_id,
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                            }
                        },
                    )
                )

            # B13 fix: check IPv6 ranges too
            for ip_range in rule.get("Ipv6Ranges", []):
                cidr6 = ip_range.get("CidrIpv6", "")
                severity = self._analyze_sg_rule_severity(protocol, from_port, to_port, cidr6, ipv6=True)
                events.append(
                    self._create_security_event(
                        source="AWS_EC2_SG",
                        resource_id=sg_id,
                        event_type="SECURITY_GROUP_RULE_IPV6",
                        severity=severity,
                        description=(
                            f"Security group '{sg_name}' allows {protocol} "
                            f"from {cidr6} (IPv6) on ports "
                            f"{from_port if from_port is not None else 'ALL'}-"
                            f"{to_port if to_port is not None else 'ALL'}"
                        ),
                        raw_event=sg,
                        additional_fields={
                            "sg": {
                                "name": sg_name,
                                "id": sg_id,
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr6,
                            }
                        },
                    )
                )
        return events

    def _analyze_sg_rule_severity(
        self,
        protocol: str,
        from_port: Optional[int],
        to_port: Optional[int],
        cidr: str,
        ipv6: bool = False,
    ) -> str:
        open_world = cidr in ("0.0.0.0/0", "::/0")
        if not open_world:
            return "LOW"

        # B3 fix: removed dead duplicate cidr checks; single pass, early returns
        if protocol == "-1":  # all traffic
            return "CRITICAL"
        if from_port is None or to_port is None:
            return "HIGH"
        if from_port == 0 and to_port == 65535:
            return "CRITICAL"
        if from_port <= 22 <= to_port:  # SSH
            return "CRITICAL"
        if from_port <= 3389 <= to_port:  # RDP
            return "CRITICAL"
        if from_port in (3306, 5432, 1433, 1521) or (
            from_port <= 3306 <= to_port
            or from_port <= 5432 <= to_port
            or from_port <= 1433 <= to_port
        ):  # DB ports
            return "HIGH"
        if from_port in (21, 23, 25, 53):
            return "MEDIUM"
        return "HIGH"  # any other port open to world

    def _analyze_ec2_instance(self, instance: Dict) -> List[Dict]:
        events: List[Dict] = []
        instance_id = instance.get("InstanceId", "unknown")
        instance_meta = {
            "id": instance_id,
            "state": instance.get("State", {}).get("Name"),
            "instance_type": instance.get("InstanceType"),
        }

        if instance.get("PublicIpAddress"):
            events.append(
                self._create_security_event(
                    source="AWS_EC2_INSTANCE",
                    resource_id=instance_id,
                    event_type="PUBLIC_IP",
                    severity="MEDIUM",
                    description=f"EC2 instance {instance_id} has public IP {instance['PublicIpAddress']}",
                    raw_event=instance,
                    additional_fields={"instance": {**instance_meta, "public_ip": instance["PublicIpAddress"]}},
                )
            )

        if not instance.get("IamInstanceProfile"):
            events.append(
                self._create_security_event(
                    source="AWS_EC2_INSTANCE",
                    resource_id=instance_id,
                    event_type="NO_IAM_ROLE",
                    severity="MEDIUM",
                    description=f"EC2 instance {instance_id} has no IAM role attached",
                    raw_event=instance,
                    additional_fields={"instance": instance_meta},
                )
            )
        return events

    # ------------------------------------------------------------------
    # S3
    # ------------------------------------------------------------------

    def collect_s3_security(self) -> List[Dict]:
        events: List[Dict] = []
        try:
            buckets_response = self.s3.list_buckets()
            for bucket in buckets_response.get("Buckets", []):
                events.extend(self._analyze_s3_bucket(bucket["Name"]))
        except ClientError as e:
            events.append(
                self._create_security_event(
                    source="AWS_S3",
                    resource_id="N/A",
                    event_type="COLLECTION_ERROR",
                    severity="CRITICAL",
                    description=f"S3 security collection failed: {e}",
                    raw_event={"error": str(e)},
                )
            )
            self.logger.error(f"S3 collection failed: {e}")
        return events

    def _analyze_s3_bucket(self, bucket_name: str) -> List[Dict]:
        events: List[Dict] = []
        bucket_info: Dict = {"name": bucket_name}
        _skip_codes = {"NoSuchBucket", "AccessDenied", "AllAccessDisabled"}

        # ACL
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            bucket_info["acl"] = acl
            public_uris = {
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            }
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in public_uris:
                    events.append(
                        self._create_security_event(
                            source="AWS_S3_ACL",
                            resource_id=bucket_name,
                            event_type="PUBLIC_ACCESS",
                            severity="CRITICAL",
                            description=f"S3 bucket '{bucket_name}' has public ACL access",
                            raw_event=acl,
                            additional_fields={"bucket": {"name": bucket_name, "grantee": grantee}},
                        )
                    )
        except ClientError as e:
            # B10 fix: skip all expected non-error codes, not just NoSuchBucket
            if e.response["Error"]["Code"] not in _skip_codes:
                self.logger.error(f"Unexpected ACL error for {bucket_name}: {e}")

        # Bucket policy
        try:
            policy_resp = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy_resp["Policy"])
            bucket_info["policy"] = policy_doc
            events.extend(self._analyze_bucket_policy(bucket_name, policy_doc))
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in {"NoSuchBucketPolicy"} | _skip_codes:
                self.logger.error(f"Unexpected policy error for {bucket_name}: {e}")

        # Encryption
        try:
            self.s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                events.append(
                    self._create_security_event(
                        source="AWS_S3_ENCRYPTION",
                        resource_id=bucket_name,
                        event_type="NO_ENCRYPTION",
                        severity="HIGH",
                        description=f"S3 bucket '{bucket_name}' has no server-side encryption enabled",
                        raw_event=bucket_info,
                        additional_fields={"bucket": {"name": bucket_name, "encryption": None}},
                    )
                )
            elif code not in _skip_codes:
                self.logger.error(f"Unexpected encryption error for {bucket_name}: {e}")

        # Public access block
        try:
            pab_resp = self.s3.get_public_access_block(Bucket=bucket_name)
            pab = pab_resp.get("PublicAccessBlockConfiguration", {})
            if not all([
                pab.get("BlockPublicAcls", False),
                pab.get("IgnorePublicAcls", False),
                pab.get("BlockPublicPolicy", False),
                pab.get("RestrictPublicBuckets", False),
            ]):
                events.append(
                    self._create_security_event(
                        source="AWS_S3_PAB",
                        resource_id=bucket_name,
                        event_type="WEAK_PUBLIC_ACCESS_BLOCK",
                        severity="HIGH",
                        description=f"S3 bucket '{bucket_name}' has incomplete public access block settings",
                        raw_event=pab_resp,
                        additional_fields={"bucket": {"name": bucket_name, "public_access_block": pab}},
                    )
                )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                events.append(
                    self._create_security_event(
                        source="AWS_S3_PAB",
                        resource_id=bucket_name,
                        event_type="NO_PUBLIC_ACCESS_BLOCK",
                        severity="CRITICAL",
                        description=f"S3 bucket '{bucket_name}' has no public access block configuration",
                        raw_event=bucket_info,
                        additional_fields={"bucket": {"name": bucket_name, "public_access_block": None}},
                    )
                )
            elif code not in _skip_codes:
                self.logger.error(f"Unexpected PAB error for {bucket_name}: {e}")

        return events

    def _analyze_bucket_policy(self, bucket_name: str, policy_doc: Dict) -> List[Dict]:
        events: List[Dict] = []
        dangerous_actions = {"s3:DeleteBucket", "s3:PutBucketPolicy", "s3:PutBucketAcl"}

        for statement in policy_doc.get("Statement", []):
            principal = statement.get("Principal", {})
            is_public = principal == "*" or (
                isinstance(principal, dict) and "*" in principal.get("AWS", [])
            )
            if is_public:
                events.append(
                    self._create_security_event(
                        source="AWS_S3_POLICY",
                        resource_id=bucket_name,
                        event_type="OVERLY_PERMISSIVE_POLICY",
                        severity="CRITICAL",
                        description=f"S3 bucket '{bucket_name}' policy allows access to all principals (*)",
                        raw_event=policy_doc,
                        additional_fields={"bucket": {"name": bucket_name, "statement": statement}},
                    )
                )

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action in dangerous_actions and is_public:
                    events.append(
                        self._create_security_event(
                            source="AWS_S3_POLICY",
                            resource_id=bucket_name,
                            event_type="DANGEROUS_POLICY_ACTION",
                            severity="CRITICAL",
                            description=f"S3 bucket '{bucket_name}' allows '{action}' to all principals",
                            raw_event=policy_doc,
                            additional_fields={
                                "bucket": {"name": bucket_name, "dangerous_action": action}
                            },
                        )
                    )
        return events

    # ------------------------------------------------------------------
    # IAM
    # ------------------------------------------------------------------

    def collect_iam_security(self) -> List[Dict]:
        events: List[Dict] = []
        try:
            events.extend(self._analyze_iam_users())
            events.extend(self._analyze_iam_roles())
            events.extend(self._analyze_iam_password_policy())
        except ClientError as e:
            events.append(
                self._create_security_event(
                    source="AWS_IAM",
                    resource_id="N/A",
                    event_type="COLLECTION_ERROR",
                    severity="CRITICAL",
                    description=f"IAM security collection failed: {e}",
                    raw_event={"error": str(e)},
                )
            )
            self.logger.error(f"IAM collection failed: {e}")
        return events

    def _analyze_iam_users(self) -> List[Dict]:
        events: List[Dict] = []
        try:
            # B5 fix: paginate users
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    events.extend(self._analyze_iam_user(user["UserName"], user))
        except ClientError as e:
            self.logger.error(f"Error listing IAM users: {e}")
        return events

    def _analyze_iam_user(self, username: str, user_data: Dict) -> List[Dict]:
        events: List[Dict] = []
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        # Access keys
        try:
            keys = self.iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            if len(keys) > 1:
                events.append(
                    self._create_security_event(
                        source="AWS_IAM_USER",
                        resource_id=username,
                        event_type="MULTIPLE_ACCESS_KEYS",
                        severity="MEDIUM",
                        description=f"IAM user '{username}' has {len(keys)} access keys (max recommended: 1)",
                        raw_event=user_data,
                        additional_fields={"user": {"name": username, "active_keys": len(keys)}},
                    )
                )
            for key in keys:
                if key.get("Status") == "Active":
                    create_date = key.get("CreateDate")
                    if create_date:
                        # B11 fix: use explicit UTC instead of source tzinfo
                        days_old = (now_utc - create_date.replace(tzinfo=datetime.timezone.utc)
                                    if create_date.tzinfo is None
                                    else now_utc - create_date).days
                        if days_old > 90:
                            events.append(
                                self._create_security_event(
                                    source="AWS_IAM_USER",
                                    resource_id=username,
                                    event_type="OLD_ACCESS_KEY",
                                    severity="HIGH",
                                    description=f"IAM user '{username}' has access key {days_old} days old (>90)",
                                    raw_event=user_data,
                                    additional_fields={
                                        "user": {
                                            "name": username,
                                            "key_age_days": days_old,
                                            "key_id": key.get("AccessKeyId"),
                                        }
                                    },
                                )
                            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.logger.error(f"Error checking access keys for {username}: {e}")

        # MFA
        try:
            mfa_devices = self.iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            if not mfa_devices:
                events.append(
                    self._create_security_event(
                        source="AWS_IAM_USER",
                        resource_id=username,
                        event_type="NO_MFA",
                        severity="HIGH",
                        description=f"IAM user '{username}' has no MFA device configured",
                        raw_event=user_data,
                        additional_fields={"user": {"name": username, "mfa_enabled": False}},
                    )
                )
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.logger.error(f"Error checking MFA for {username}: {e}")

        # Inline policies
        try:
            inline = self.iam.list_user_policies(UserName=username).get("PolicyNames", [])
            if inline:
                events.append(
                    self._create_security_event(
                        source="AWS_IAM_USER",
                        resource_id=username,
                        event_type="INLINE_POLICIES",
                        severity="MEDIUM",
                        description=f"IAM user '{username}' has {len(inline)} inline policies (use managed policies instead)",
                        raw_event=user_data,
                        additional_fields={"user": {"name": username, "inline_policies": inline}},
                    )
                )
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.logger.error(f"Error checking inline policies for {username}: {e}")

        return events

    def _analyze_iam_roles(self) -> List[Dict]:
        events: List[Dict] = []
        try:
            # B6 fix: paginate roles
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    events.extend(self._analyze_iam_role(role["RoleName"], role))
        except ClientError as e:
            self.logger.error(f"Error listing IAM roles: {e}")
        return events

    def _analyze_iam_role(self, role_name: str, role_data: Dict) -> List[Dict]:
        events: List[Dict] = []
        trust_policy = role_data.get("AssumeRolePolicyDocument", {})
        if trust_policy:
            events.extend(self._analyze_trust_policy(role_name, trust_policy))

        try:
            attached = self.iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            )
            for policy in attached:
                arn = policy.get("PolicyArn", "")
                if "AdministratorAccess" in arn:
                    events.append(
                        self._create_security_event(
                            source="AWS_IAM_ROLE",
                            resource_id=role_name,
                            event_type="ADMIN_ACCESS",
                            severity="CRITICAL",
                            description=f"IAM role '{role_name}' has AdministratorAccess attached",
                            raw_event=role_data,
                            additional_fields={"role": {"name": role_name, "policy_arn": arn}},
                        )
                    )
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.logger.error(f"Error checking attached policies for {role_name}: {e}")
        return events

    def _analyze_trust_policy(self, role_name: str, trust_policy: Dict) -> List[Dict]:
        events: List[Dict] = []
        for statement in trust_policy.get("Statement", []):
            principal = statement.get("Principal", {})
            aws_principals = []
            if isinstance(principal, dict):
                raw = principal.get("AWS", [])
                aws_principals = [raw] if isinstance(raw, str) else raw
            elif principal == "*":
                aws_principals = ["*"]

            for p in aws_principals:
                if p == "*":
                    events.append(
                        self._create_security_event(
                            source="AWS_IAM_ROLE",
                            resource_id=role_name,
                            event_type="OVERLY_PERMISSIVE_TRUST",
                            severity="CRITICAL",
                            description=f"IAM role '{role_name}' trust policy allows any AWS principal (*)",
                            raw_event=trust_policy,
                            additional_fields={"role": {"name": role_name, "statement": statement}},
                        )
                    )
        return events

    def _analyze_iam_password_policy(self) -> List[Dict]:
        """B9 fix: use get_account_password_policy(), not get_account_summary()."""
        events: List[Dict] = []
        try:
            policy = self.iam.get_account_password_policy().get("PasswordPolicy", {})
            if policy.get("MinimumPasswordLength", 0) < 8:
                events.append(
                    self._create_security_event(
                        source="AWS_IAM_ACCOUNT",
                        resource_id="ACCOUNT",
                        event_type="WEAK_PASSWORD_POLICY",
                        severity="HIGH",
                        description=(
                            f"Account password policy minimum length is "
                            f"{policy.get('MinimumPasswordLength', 0)} (recommended ≥14)"
                        ),
                        raw_event=policy,
                        additional_fields={"account": {"password_policy": policy}},
                    )
                )
            if not policy.get("RequireMFAForConsoleLogin", False):
                events.append(
                    self._create_security_event(
                        source="AWS_IAM_ACCOUNT",
                        resource_id="ACCOUNT",
                        event_type="MFA_NOT_REQUIRED",
                        severity="HIGH",
                        description="Account password policy does not require MFA for console login",
                        raw_event=policy,
                        additional_fields={"account": {"password_policy": policy}},
                    )
                )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchEntity":
                events.append(
                    self._create_security_event(
                        source="AWS_IAM_ACCOUNT",
                        resource_id="ACCOUNT",
                        event_type="NO_PASSWORD_POLICY",
                        severity="CRITICAL",
                        description="Account has no IAM password policy configured",
                        raw_event={},
                    )
                )
            elif code != "AccessDenied":
                self.logger.error(f"Error getting account password policy: {e}")
        return events

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------

    def collect_cloudtrail_security(self) -> List[Dict]:
        events: List[Dict] = []
        try:
            end = datetime.datetime.utcnow()
            start = end - datetime.timedelta(hours=24)
            collected = 0

            # B7 fix: paginate via NextToken
            kwargs: Dict[str, Any] = {
                "MaxResults": min(self.max_events, 50),
                "StartTime": start,
                "EndTime": end,
            }
            while collected < self.max_events:
                response = self.cloudtrail.lookup_events(**kwargs)
                for raw in response.get("Events", []):
                    try:
                        ct_event = json.loads(raw.get("CloudTrailEvent", "{}"))
                        security_event = self._analyze_cloudtrail_event(ct_event)
                        if security_event:
                            events.append(security_event)
                            collected += 1
                    except json.JSONDecodeError:
                        continue
                next_token = response.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token

        except ClientError as e:
            events.append(
                self._create_security_event(
                    source="AWS_CLOUDTRAIL",
                    resource_id="N/A",
                    event_type="COLLECTION_ERROR",
                    severity="CRITICAL",
                    description=f"CloudTrail collection failed: {e}",
                    raw_event={"error": str(e)},
                )
            )
            self.logger.error(f"CloudTrail collection failed: {e}")
        return events

    def _analyze_cloudtrail_event(self, event: Dict) -> Optional[Dict]:
        event_name = event.get("eventName", "")
        user_identity = event.get("userIdentity", {})
        user_type = user_identity.get("type", "")
        user_arn = user_identity.get("arn", "")

        high_risk = {
            "DeleteBucket", "DeleteUser", "DeleteRole", "DeletePolicy",
            "StopLogging", "TerminateInstances", "PutBucketPolicy",
            "CreateAccessKey", "AttachUserPolicy", "AssumeRole",
            "CreateRole", "PutUserPolicy",
        }
        critical_actions = {"DeleteBucket", "DeleteUser", "DeleteRole", "StopLogging"}

        extra = {
            "event": {
                "action": event_name,
                "user": user_arn,
                "user_type": user_type,
                "source_ip": event.get("sourceIPAddress"),
                "region": event.get("awsRegion"),
            }
        }

        if user_type == "Root":
            return self._create_security_event(
                source="AWS_CLOUDTRAIL",
                resource_id=user_arn,
                event_type="ROOT_ACCOUNT_USAGE",
                severity="CRITICAL",
                description=f"Root account used for action: {event_name}",
                raw_event=event,
                additional_fields=extra,
            )

        if event_name in high_risk:
            severity = "CRITICAL" if event_name in critical_actions else "HIGH"
            return self._create_security_event(
                source="AWS_CLOUDTRAIL",
                resource_id=user_arn,
                event_type="HIGH_RISK_ACTION",
                severity=severity,
                description=f"High-risk action: {event_name} by {user_arn}",
                raw_event=event,
                additional_fields=extra,
            )

        # B8 fix: mfaAuthenticated is a string "true"/"false", not a bool
        mfa_raw = user_identity.get("mfaAuthenticated", "false")
        mfa_used = str(mfa_raw).lower() == "true"
        if event_name == "ConsoleLogin" and not mfa_used:
            return self._create_security_event(
                source="AWS_CLOUDTRAIL",
                resource_id=user_arn,
                event_type="CONSOLE_LOGIN_NO_MFA",
                severity="HIGH",
                description=f"Console login without MFA by {user_arn}",
                raw_event=event,
                additional_fields={**extra, "event": {**extra["event"], "mfa": False}},
            )

        return None

    # ------------------------------------------------------------------
    # GuardDuty
    # ------------------------------------------------------------------

    def collect_guardduty_security(self) -> List[Dict]:
        events: List[Dict] = []
        try:
            detector_ids = self.guardduty.list_detectors().get("DetectorIds", [])
            for detector_id in detector_ids:
                finding_ids = self.guardduty.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        "Criterion": {
                            "service.archived": {"Eq": ["false"]}
                        }
                    },
                    MaxResults=min(self.max_events, 50),
                ).get("FindingIds", [])

                if not finding_ids:
                    continue

                findings = self.guardduty.get_findings(
                    DetectorId=detector_id, FindingIds=finding_ids
                ).get("Findings", [])

                for finding in findings:
                    events.append(self._analyze_guardduty_finding(finding))

        except ClientError as e:
            # BadRequestException = GuardDuty not enabled in this region
            if e.response["Error"]["Code"] != "BadRequestException":
                events.append(
                    self._create_security_event(
                        source="AWS_GUARDDUTY",
                        resource_id="N/A",
                        event_type="COLLECTION_ERROR",
                        severity="CRITICAL",
                        description=f"GuardDuty collection failed: {e}",
                        raw_event={"error": str(e)},
                    )
                )
                self.logger.error(f"GuardDuty collection failed: {e}")
        return events

    def _analyze_guardduty_finding(self, finding: Dict) -> Dict:
        score = finding.get("Severity", 0)
        if score >= 8.0:
            severity = "CRITICAL"
        elif score >= 6.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return self._create_security_event(
            source="AWS_GUARDDUTY",
            resource_id=finding.get("Id", "unknown"),
            event_type="THREAT_DETECTION",
            severity=severity,
            description=f"GuardDuty: {finding.get('Title', 'finding')}",
            raw_event=finding,
            additional_fields={
                "guardduty": {
                    "finding_type": finding.get("Type", ""),
                    "severity_score": score,
                    "title": finding.get("Title", ""),
                    "description": finding.get("Description", ""),
                    "region": finding.get("Region", ""),
                    "account_id": finding.get("AccountId", ""),
                }
            },
        )

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def collect_all_security_data(self) -> List[Dict]:
        all_events: List[Dict] = []
        collectors = [
            ("EC2", self.collect_ec2_security),
            ("S3", self.collect_s3_security),
            ("IAM", self.collect_iam_security),
            ("CloudTrail", self.collect_cloudtrail_security),
            ("GuardDuty", self.collect_guardduty_security),
        ]
        for name, fn in collectors:
            self.logger.info(f"Collecting {name} security data...")
            result = fn()
            all_events.extend(result)
            self.logger.info(f"Collected {len(result)} {name} events")
        self.logger.info(f"Total events collected: {len(all_events)}")
        return all_events

    def collect_all(self) -> List[Dict]:
        """Satisfy BaseCollector interface — delegates to collect_all_security_data."""
        return self.collect_all_security_data()

    def save_security_events(self, events: List[Dict], output_dir: str = "logs") -> str:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"aws_security_events_{timestamp}.json")
        with open(filepath, "w") as f:
            json.dump(events, f, indent=2, default=str)
        self.logger.info(f"Security events saved to: {filepath}")
        return filepath


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    collector = AWSCollector(region="us-east-1")
    events = collector.collect_all_security_data()
    output_file = collector.save_security_events(events)

    severity_counts: Dict[str, int] = {}
    for e in events:
        sev = e.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\nTotal events: {len(events)}")
    for sev, count in sorted(severity_counts.items()):
        print(f"  {sev}: {count}")
    print(f"\nSaved to: {output_file}")
