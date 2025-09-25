"""
CloudHawk AWS Security Collector
Collects and parses security-relevant data from AWS services:
- IAM Users, Roles, Policies (privilege escalation detection)
- S3 Buckets & Policies (data exposure detection)
- EC2 Security Groups (network security)
- CloudTrail Events (audit trail analysis)
- GuardDuty Findings (threat detection)
- VPC Flow Logs (network anomalies)
- CloudWatch Logs (application security)
- AWS Config (configuration drift)

Requires AWS credentials (from `aws configure` or IAM role).
"""

import boto3
import json
import datetime
import os
import logging
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError

class AWSCollector:
    def __init__(self, region="us-east-1", max_events: int = 1000):
        """
        Initialize AWS Security Collector
        
        Args:
            region: AWS region to collect from
            max_events: Maximum number of events to collect per service
        """
        self.region = region
        self.max_events = max_events
        self.logger = logging.getLogger(__name__)
        
        try:
            # Initialize AWS clients
            self.ec2 = boto3.client("ec2", region_name=region)
            self.s3 = boto3.client("s3", region_name=region)
            self.iam = boto3.client("iam", region_name=region)
            self.cloudtrail = boto3.client("cloudtrail", region_name=region)
            self.logs = boto3.client("logs", region_name=region)
            self.guardduty = boto3.client("guardduty", region_name=region)
            self.inspector = boto3.client("inspector2", region_name=region)
            self.config = boto3.client("config", region_name=region)
            self.kms = boto3.client("kms", region_name=region)
            
            # Test credentials
            self._test_credentials()
            
        except NoCredentialsError:
            raise Exception("AWS credentials not found. Please configure AWS CLI or set environment variables.")
        except Exception as e:
            raise Exception(f"Failed to initialize AWS clients: {e}")
    
    def _test_credentials(self):
        """Test AWS credentials by making a simple API call"""
        try:
            self.iam.list_users(MaxItems=1)
            self.logger.info("AWS credentials validated successfully")
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self.logger.warning("AWS credentials have limited permissions")
            else:
                raise Exception(f"AWS credential test failed: {e}")
    
    def _create_security_event(self, source: str, resource_id: str, event_type: str, 
                             severity: str, description: str, raw_event: Dict, 
                             additional_fields: Dict = None) -> Dict:
        """Create standardized security event"""
        event = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source": source,
            "resource_id": resource_id,
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "raw_event": raw_event,
            "region": self.region
        }
        
        if additional_fields:
            event.update(additional_fields)
            
        return event 

    def collect_ec2_security(self) -> List[Dict]:
        """Collect EC2 security groups and instances for security analysis"""
        events = []
        
        try:
            # Collect Security Groups
            sgs_response = self.ec2.describe_security_groups()
            for sg in sgs_response.get("SecurityGroups", []):
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")
                
                # Analyze each security group rule
                for rule in sg.get("IpPermissions", []):
                    protocol = rule.get("IpProtocol", "tcp")
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    
                    # Check for dangerous open rules
                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "0.0.0.0/0")
                        
                        # Determine severity based on rule
                        severity = self._analyze_security_group_rule(protocol, from_port, to_port, cidr)
                        
                        # Create security event
                        event = self._create_security_event(
                            source="AWS_EC2_SG",
                            resource_id=sg_id,
                            event_type="SECURITY_GROUP_RULE",
                            severity=severity,
                            description=f"Security group '{sg_name}' allows {protocol} from {cidr} on ports {from_port}-{to_port}",
                            raw_event=sg,
                            additional_fields={
                                "sg": {
                                    "name": sg_name,
                                    "id": sg_id,
                                    "protocol": protocol,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "cidr": cidr,
                                    "rule_string": f"{protocol}/{from_port}-{to_port},{cidr}"
                                }
                            }
                        )
                        events.append(event)
            
            # Collect EC2 Instances
            instances_response = self.ec2.describe_instances()
            for reservation in instances_response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId")
                    
                    # Check for security issues
                    security_issues = self._analyze_ec2_instance(instance)
                    for issue in security_issues:
                        events.append(issue)
                        
        except ClientError as e:
            error_event = self._create_security_event(
                source="AWS_EC2",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"EC2 security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"EC2 collection failed: {e}")
            
        return events
    
    def _analyze_security_group_rule(self, protocol: str, from_port: int, to_port: int, cidr: str) -> str:
        """Analyze security group rule and return severity"""
        # Critical: SSH/RDP open to world
        if cidr == "0.0.0.0/0":
            if from_port == 22 or (from_port <= 22 <= to_port):  # SSH
                return "CRITICAL"
            if from_port == 3389 or (from_port <= 3389 <= to_port):  # RDP
                return "CRITICAL"
            if protocol == "-1":  # All protocols
                return "CRITICAL"
            if from_port == 0 and to_port == 65535:  # All ports
                return "CRITICAL"
            return "HIGH"
        
        # High: Database ports open to world
        if cidr == "0.0.0.0/0" and from_port in [3306, 5432, 1433, 1521]:
            return "HIGH"
            
        # Medium: Other potentially risky ports
        if cidr == "0.0.0.0/0" and from_port in [21, 23, 25, 53, 80, 443, 993, 995]:
            return "MEDIUM"
            
        return "LOW"
    
    def _analyze_ec2_instance(self, instance: Dict) -> List[Dict]:
        """Analyze EC2 instance for security issues"""
        events = []
        instance_id = instance.get("InstanceId")
        
        # Check for public IP
        if instance.get("PublicIpAddress"):
            event = self._create_security_event(
                source="AWS_EC2_INSTANCE",
                resource_id=instance_id,
                event_type="PUBLIC_IP",
                severity="MEDIUM",
                description=f"EC2 instance {instance_id} has public IP {instance.get('PublicIpAddress')}",
                raw_event=instance,
                additional_fields={
                    "instance": {
                        "id": instance_id,
                        "public_ip": instance.get("PublicIpAddress"),
                        "state": instance.get("State", {}).get("Name"),
                        "instance_type": instance.get("InstanceType")
                    }
                }
            )
            events.append(event)
        
        # Check for IAM role
        iam_instance_profile = instance.get("IamInstanceProfile")
        if not iam_instance_profile:
            event = self._create_security_event(
                source="AWS_EC2_INSTANCE",
                resource_id=instance_id,
                event_type="NO_IAM_ROLE",
                severity="MEDIUM",
                description=f"EC2 instance {instance_id} has no IAM role attached",
                raw_event=instance,
                additional_fields={
                    "instance": {
                        "id": instance_id,
                        "state": instance.get("State", {}).get("Name"),
                        "instance_type": instance.get("InstanceType")
                    }
                }
            )
            events.append(event)
            
        return events

    def collect_s3_security(self) -> List[Dict]:
        """Collect S3 buckets and analyze for security issues"""
        events = []
        
        try:
            buckets_response = self.s3.list_buckets()
            for bucket in buckets_response.get("Buckets", []):
                bucket_name = bucket["Name"]
                bucket_events = self._analyze_s3_bucket(bucket_name)
                events.extend(bucket_events)
                
        except ClientError as e:
            error_event = self._create_security_event(
                source="AWS_S3",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"S3 security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"S3 collection failed: {e}")
            
        return events
    
    def _analyze_s3_bucket(self, bucket_name: str) -> List[Dict]:
        """Analyze individual S3 bucket for security issues"""
        events = []
        bucket_info = {"name": bucket_name}
        
        try:
            # Check bucket ACL
            try:
                acl_response = self.s3.get_bucket_acl(Bucket=bucket_name)
                bucket_info["acl"] = acl_response
                
                # Check for public access
                for grant in acl_response.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in ["http://acs.amazonaws.com/groups/global/AllUsers", 
                                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"]:
                        event = self._create_security_event(
                            source="AWS_S3_ACL",
                            resource_id=bucket_name,
                            event_type="PUBLIC_ACCESS",
                            severity="CRITICAL",
                            description=f"S3 bucket '{bucket_name}' has public ACL access",
                            raw_event=acl_response,
                            additional_fields={
                                "bucket": {
                                    "name": bucket_name,
                                    "acl": acl_response,
                                    "public_access": True,
                                    "grantee": grantee
                                }
                            }
                        )
                        events.append(event)
                        
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucket':
                    bucket_info["acl"] = f"Error: {e}"
            
            # Check bucket policy
            try:
                policy_response = self.s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy_response["Policy"])
                bucket_info["policy"] = policy_doc
                
                # Analyze policy for security issues
                policy_issues = self._analyze_bucket_policy(bucket_name, policy_doc)
                events.extend(policy_issues)
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    bucket_info["policy"] = f"Error: {e}"
                else:
                    bucket_info["policy"] = None
            
            # Check encryption
            try:
                encryption_response = self.s3.get_bucket_encryption(Bucket=bucket_name)
                bucket_info["encryption"] = encryption_response
            except ClientError as e:
                if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                    bucket_info["encryption"] = f"Error: {e}"
                else:
                    bucket_info["encryption"] = None
                    # No encryption is a security issue
                    event = self._create_security_event(
                        source="AWS_S3_ENCRYPTION",
                        resource_id=bucket_name,
                        event_type="NO_ENCRYPTION",
                        severity="HIGH",
                        description=f"S3 bucket '{bucket_name}' has no encryption enabled",
                        raw_event=bucket_info,
                        additional_fields={
                            "bucket": {
                                "name": bucket_name,
                                "encryption": None
                            }
                        }
                    )
                    events.append(event)
            
            # Check public access block
            try:
                pab_response = self.s3.get_public_access_block(Bucket=bucket_name)
                bucket_info["public_access_block"] = pab_response.get("PublicAccessBlockConfiguration", {})
                
                pab_config = bucket_info["public_access_block"]
                if not all([
                    pab_config.get("BlockPublicAcls", False),
                    pab_config.get("IgnorePublicAcls", False),
                    pab_config.get("BlockPublicPolicy", False),
                    pab_config.get("RestrictPublicBuckets", False)
                ]):
                    event = self._create_security_event(
                        source="AWS_S3_PAB",
                        resource_id=bucket_name,
                        event_type="WEAK_PUBLIC_ACCESS_BLOCK",
                        severity="HIGH",
                        description=f"S3 bucket '{bucket_name}' has weak public access block settings",
                        raw_event=pab_response,
                        additional_fields={
                            "bucket": {
                                "name": bucket_name,
                                "public_access_block": pab_config
                            }
                        }
                    )
                    events.append(event)
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                    bucket_info["public_access_block"] = f"Error: {e}"
                else:
                    bucket_info["public_access_block"] = None
                    # No public access block is a security issue
                    event = self._create_security_event(
                        source="AWS_S3_PAB",
                        resource_id=bucket_name,
                        event_type="NO_PUBLIC_ACCESS_BLOCK",
                        severity="CRITICAL",
                        description=f"S3 bucket '{bucket_name}' has no public access block configuration",
                        raw_event=bucket_info,
                        additional_fields={
                            "bucket": {
                                "name": bucket_name,
                                "public_access_block": None
                            }
                        }
                    )
                    events.append(event)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing bucket {bucket_name}: {e}")
            
        return events
    
    def _analyze_bucket_policy(self, bucket_name: str, policy_doc: Dict) -> List[Dict]:
        """Analyze S3 bucket policy for security issues"""
        events = []
        
        try:
            statements = policy_doc.get("Statement", [])
            for statement in statements:
                # Check for overly permissive principals
                principal = statement.get("Principal", {})
                if principal == "*" or (isinstance(principal, dict) and "*" in principal.get("AWS", [])):
                    event = self._create_security_event(
                        source="AWS_S3_POLICY",
                        resource_id=bucket_name,
                        event_type="OVERLY_PERMISSIVE_POLICY",
                        severity="CRITICAL",
                        description=f"S3 bucket '{bucket_name}' has policy allowing access to all principals (*)",
                        raw_event=policy_doc,
                        additional_fields={
                            "bucket": {
                                "name": bucket_name,
                                "policy": policy_doc,
                                "statement": statement
                            }
                        }
                    )
                    events.append(event)
                
                # Check for dangerous actions
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                    
                dangerous_actions = ["s3:DeleteBucket", "s3:PutBucketPolicy", "s3:PutBucketAcl"]
                for action in actions:
                    if action in dangerous_actions and principal == "*":
                        event = self._create_security_event(
                            source="AWS_S3_POLICY",
                            resource_id=bucket_name,
                            event_type="DANGEROUS_POLICY_ACTION",
                            severity="CRITICAL",
                            description=f"S3 bucket '{bucket_name}' allows dangerous action '{action}' to all principals",
                            raw_event=policy_doc,
                            additional_fields={
                                "bucket": {
                                    "name": bucket_name,
                                    "policy": policy_doc,
                                    "statement": statement,
                                    "dangerous_action": action
                                }
                            }
                        )
                        events.append(event)
                        
        except Exception as e:
            self.logger.error(f"Error analyzing bucket policy for {bucket_name}: {e}")
            
        return events
        
    def collect_iam_security(self) -> List[Dict]:
        """Collect IAM users, roles, and policies for security analysis"""
        events = []
        
        try:
            # Collect IAM Users
            users_events = self._analyze_iam_users()
            events.extend(users_events)
            
            # Collect IAM Roles
            roles_events = self._analyze_iam_roles()
            events.extend(roles_events)
            
            # Collect IAM Policies
            policies_events = self._analyze_iam_policies()
            events.extend(policies_events)
            
        except ClientError as e:
            error_event = self._create_security_event(
                source="AWS_IAM",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"IAM security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"IAM collection failed: {e}")
            
        return events
    
    def _analyze_iam_users(self) -> List[Dict]:
        """Analyze IAM users for security issues"""
        events = []
        
        try:
            users_response = self.iam.list_users()
            for user in users_response.get("Users", []):
                username = user.get("UserName")
                user_events = self._analyze_iam_user(username, user)
                events.extend(user_events)
                
        except ClientError as e:
            self.logger.error(f"Error analyzing IAM users: {e}")
            
        return events
    
    def _analyze_iam_user(self, username: str, user_data: Dict) -> List[Dict]:
        """Analyze individual IAM user for security issues"""
        events = []
        
        try:
            # Check for access keys
            try:
                keys_response = self.iam.list_access_keys(UserName=username)
                access_keys = keys_response.get("AccessKeyMetadata", [])
                
                if len(access_keys) > 1:
                    event = self._create_security_event(
                        source="AWS_IAM_USER",
                        resource_id=username,
                        event_type="MULTIPLE_ACCESS_KEYS",
                        severity="MEDIUM",
                        description=f"IAM user '{username}' has {len(access_keys)} access keys (should have max 1)",
                        raw_event=user_data,
                        additional_fields={
                            "user": {
                                "name": username,
                                "active_keys": len(access_keys),
                                "keys": access_keys
                            }
                        }
                    )
                    events.append(event)
                
                # Check for old access keys
                for key in access_keys:
                    if key.get("Status") == "Active":
                        create_date = key.get("CreateDate")
                        if create_date:
                            days_old = (datetime.datetime.now(create_date.tzinfo) - create_date).days
                            if days_old > 90:
                                event = self._create_security_event(
                                    source="AWS_IAM_USER",
                                    resource_id=username,
                                    event_type="OLD_ACCESS_KEY",
                                    severity="HIGH",
                                    description=f"IAM user '{username}' has access key older than 90 days ({days_old} days)",
                                    raw_event=user_data,
                                    additional_fields={
                                        "user": {
                                            "name": username,
                                            "key_age_days": days_old,
                                            "key_id": key.get("AccessKeyId")
                                        }
                                    }
                                )
                                events.append(event)
                                
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    self.logger.error(f"Error checking access keys for {username}: {e}")
            
            # Check for MFA
            try:
                mfa_response = self.iam.list_mfa_devices(UserName=username)
                mfa_devices = mfa_response.get("MFADevices", [])
                
                if not mfa_devices:
                    event = self._create_security_event(
                        source="AWS_IAM_USER",
                        resource_id=username,
                        event_type="NO_MFA",
                        severity="HIGH",
                        description=f"IAM user '{username}' has no MFA device configured",
                        raw_event=user_data,
                        additional_fields={
                            "user": {
                                "name": username,
                                "mfa_enabled": False
                            }
                        }
                    )
                    events.append(event)
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    self.logger.error(f"Error checking MFA for {username}: {e}")
            
            # Check for inline policies
            try:
                inline_policies_response = self.iam.list_user_policies(UserName=username)
                inline_policies = inline_policies_response.get("PolicyNames", [])
                
                if inline_policies:
                    event = self._create_security_event(
                        source="AWS_IAM_USER",
                        resource_id=username,
                        event_type="INLINE_POLICIES",
                        severity="MEDIUM",
                        description=f"IAM user '{username}' has {len(inline_policies)} inline policies",
                        raw_event=user_data,
                        additional_fields={
                            "user": {
                                "name": username,
                                "inline_policies": inline_policies
                            }
                        }
                    )
                    events.append(event)
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    self.logger.error(f"Error checking inline policies for {username}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing IAM user {username}: {e}")
            
        return events
    
    def _analyze_iam_roles(self) -> List[Dict]:
        """Analyze IAM roles for security issues"""
        events = []
        
        try:
            roles_response = self.iam.list_roles()
            for role in roles_response.get("Roles", []):
                role_name = role.get("RoleName")
                role_events = self._analyze_iam_role(role_name, role)
                events.extend(role_events)
                
        except ClientError as e:
            self.logger.error(f"Error analyzing IAM roles: {e}")
            
        return events
    
    def _analyze_iam_role(self, role_name: str, role_data: Dict) -> List[Dict]:
        """Analyze individual IAM role for security issues"""
        events = []
        
        try:
            # Check trust policy
            trust_policy = role_data.get("AssumeRolePolicyDocument", {})
            if trust_policy:
                trust_issues = self._analyze_trust_policy(role_name, trust_policy)
                events.extend(trust_issues)
            
            # Check for overly permissive policies
            try:
                attached_policies_response = self.iam.list_attached_role_policies(RoleName=role_name)
                attached_policies = attached_policies_response.get("AttachedPolicies", [])
                
                for policy in attached_policies:
                    policy_arn = policy.get("PolicyArn", "")
                    if "AdministratorAccess" in policy_arn:
                        event = self._create_security_event(
                            source="AWS_IAM_ROLE",
                            resource_id=role_name,
                            event_type="ADMIN_ACCESS",
                            severity="CRITICAL",
                            description=f"IAM role '{role_name}' has AdministratorAccess policy attached",
                            raw_event=role_data,
                            additional_fields={
                                "role": {
                                    "name": role_name,
                                    "admin_access": True,
                                    "policy_arn": policy_arn
                                }
                            }
                        )
                        events.append(event)
                        
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    self.logger.error(f"Error checking attached policies for {role_name}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing IAM role {role_name}: {e}")
            
        return events
    
    def _analyze_trust_policy(self, role_name: str, trust_policy: Dict) -> List[Dict]:
        """Analyze IAM role trust policy for security issues"""
        events = []
        
        try:
            statements = trust_policy.get("Statement", [])
            for statement in statements:
                principal = statement.get("Principal", {})
                
                # Check for overly permissive trust relationships
                if isinstance(principal, dict):
                    aws_principals = principal.get("AWS", [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for aws_principal in aws_principals:
                        if aws_principal == "*":
                            event = self._create_security_event(
                                source="AWS_IAM_ROLE",
                                resource_id=role_name,
                                event_type="OVERLY_PERMISSIVE_TRUST",
                                severity="CRITICAL",
                                description=f"IAM role '{role_name}' has trust policy allowing any AWS principal (*)",
                                raw_event=trust_policy,
                                additional_fields={
                                    "role": {
                                        "name": role_name,
                                        "trust_policy": trust_policy,
                                        "statement": statement
                                    }
                                }
                            )
                            events.append(event)
                            
        except Exception as e:
            self.logger.error(f"Error analyzing trust policy for {role_name}: {e}")
            
        return events
    
    def _analyze_iam_policies(self) -> List[Dict]:
        """Analyze IAM policies for security issues"""
        events = []
        
        try:
            # Get account summary for policy analysis
            try:
                account_summary = self.iam.get_account_summary()
                summary_map = account_summary.get("SummaryMap", {})
                
                # Check for weak password policy
                if summary_map.get("MinPasswordLength", 0) < 8:
                    event = self._create_security_event(
                        source="AWS_IAM_ACCOUNT",
                        resource_id="ACCOUNT",
                        event_type="WEAK_PASSWORD_POLICY",
                        severity="HIGH",
                        description=f"Account has weak password policy (min length: {summary_map.get('MinPasswordLength', 0)})",
                        raw_event=account_summary,
                        additional_fields={
                            "account": {
                                "min_password_length": summary_map.get("MinPasswordLength", 0),
                                "password_policy": summary_map
                            }
                        }
                    )
                    events.append(event)
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    self.logger.error(f"Error getting account summary: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing IAM policies: {e}")
            
        return events
    
    def collect_cloudtrail_security(self) -> List[Dict]:
        """Collect CloudTrail events for security analysis"""
        events = []
        
        try:
            # Get recent CloudTrail events
            response = self.cloudtrail.lookup_events(
                MaxResults=min(self.max_events, 50),  # CloudTrail has limits
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(hours=24),
                EndTime=datetime.datetime.utcnow()
            )
            
            for event in response.get("Events", []):
                try:
                    cloudtrail_event = json.loads(event.get("CloudTrailEvent", "{}"))
                    security_event = self._analyze_cloudtrail_event(cloudtrail_event)
                    if security_event:
                        events.append(security_event)
                except json.JSONDecodeError:
                    continue
                    
        except ClientError as e:
            error_event = self._create_security_event(
                source="AWS_CLOUDTRAIL",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"CloudTrail security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"CloudTrail collection failed: {e}")
            
        return events
    
    def _analyze_cloudtrail_event(self, event: Dict) -> Optional[Dict]:
        """Analyze CloudTrail event for security issues"""
        event_name = event.get("eventName", "")
        user_identity = event.get("userIdentity", {})
        user_type = user_identity.get("type", "")
        user_arn = user_identity.get("arn", "")
        
        # High-risk events
        high_risk_events = [
            "DeleteBucket", "DeleteUser", "DeleteRole", "DeletePolicy",
            "StopLogging", "ConsoleLogin", "TerminateInstances",
            "PutBucketPolicy", "CreateAccessKey", "AttachUserPolicy",
            "AssumeRole", "CreateRole", "PutUserPolicy"
        ]
        
        # Check for root account usage
        if user_type == "Root":
            return self._create_security_event(
                source="AWS_CLOUDTRAIL",
                resource_id=user_arn,
                event_type="ROOT_ACCOUNT_USAGE",
                severity="CRITICAL",
                description=f"Root account used for action: {event_name}",
                raw_event=event,
                additional_fields={
                    "event": {
                        "action": event_name,
                        "user": user_arn,
                        "user_type": user_type,
                        "mfa": user_identity.get("mfaAuthenticated", False),
                        "source_ip": event.get("sourceIPAddress"),
                        "region": event.get("awsRegion")
                    }
                }
            )
        
        # Check for high-risk events
        if event_name in high_risk_events:
            severity = "CRITICAL" if event_name in ["DeleteBucket", "DeleteUser", "DeleteRole", "StopLogging"] else "HIGH"
            return self._create_security_event(
                source="AWS_CLOUDTRAIL",
                resource_id=user_arn,
                event_type="HIGH_RISK_ACTION",
                severity=severity,
                description=f"High-risk action detected: {event_name} by {user_arn}",
                raw_event=event,
                additional_fields={
                    "event": {
                        "action": event_name,
                        "user": user_arn,
                        "user_type": user_type,
                        "mfa": user_identity.get("mfaAuthenticated", False),
                        "source_ip": event.get("sourceIPAddress"),
                        "region": event.get("awsRegion")
                    }
                }
            )
        
        # Check for console login without MFA
        if event_name == "ConsoleLogin" and not user_identity.get("mfaAuthenticated", False):
            return self._create_security_event(
                source="AWS_CLOUDTRAIL",
                resource_id=user_arn,
                event_type="CONSOLE_LOGIN_NO_MFA",
                severity="HIGH",
                description=f"Console login without MFA by {user_arn}",
                raw_event=event,
                additional_fields={
                    "event": {
                        "action": event_name,
                        "user": user_arn,
                        "user_type": user_type,
                        "mfa": False,
                        "source_ip": event.get("sourceIPAddress"),
                        "region": event.get("awsRegion")
                    }
                }
            )
        
        return None
    
    def collect_guardduty_security(self) -> List[Dict]:
        """Collect GuardDuty findings for security analysis"""
        events = []
        
        try:
            # List GuardDuty detectors
            detectors_response = self.guardduty.list_detectors()
            detector_ids = detectors_response.get("DetectorIds", [])
            
            for detector_id in detector_ids:
                # Get recent findings
                findings_response = self.guardduty.list_findings(
                    DetectorId=detector_id,
                    MaxResults=min(self.max_events, 50)
                )
                
                finding_ids = findings_response.get("FindingIds", [])
                if finding_ids:
                    # Get detailed findings
                    details_response = self.guardduty.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids
                    )
                    
                    for finding in details_response.get("Findings", []):
                        security_event = self._analyze_guardduty_finding(finding)
                        if security_event:
                            events.append(security_event)
                            
        except ClientError as e:
            if e.response['Error']['Code'] != 'BadRequestException':  # GuardDuty not enabled
                error_event = self._create_security_event(
                    source="AWS_GUARDDUTY",
                    resource_id="N/A",
                    event_type="COLLECTION_ERROR",
                    severity="CRITICAL",
                    description=f"GuardDuty security collection failed: {e}",
                    raw_event={"error": str(e)}
                )
                events.append(error_event)
                self.logger.error(f"GuardDuty collection failed: {e}")
            
        return events
    
    def _analyze_guardduty_finding(self, finding: Dict) -> Dict:
        """Analyze GuardDuty finding and create security event"""
        finding_type = finding.get("Type", "")
        severity_score = finding.get("Severity", 0)
        title = finding.get("Title", "GuardDuty Finding")
        
        # Map GuardDuty severity to our severity levels
        if severity_score >= 8.0:
            severity = "CRITICAL"
        elif severity_score >= 6.0:
            severity = "HIGH"
        elif severity_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        return self._create_security_event(
            source="AWS_GUARDDUTY",
            resource_id=finding.get("Id", "unknown"),
            event_type="THREAT_DETECTION",
            severity=severity,
            description=f"GuardDuty finding: {title}",
            raw_event=finding,
            additional_fields={
                "guardduty": {
                    "finding_type": finding_type,
                    "severity_score": severity_score,
                    "title": title,
                    "description": finding.get("Description", ""),
                    "region": finding.get("Region", ""),
                    "account_id": finding.get("AccountId", "")
                }
            }
        )
    
    def collect_all_security_data(self) -> List[Dict]:
        """Collect all security-relevant data from AWS"""
        all_events = []
        
        self.logger.info("Starting AWS security data collection...")
        
        # Collect EC2 security data
        self.logger.info("Collecting EC2 security data...")
        ec2_events = self.collect_ec2_security()
        all_events.extend(ec2_events)
        self.logger.info(f"Collected {len(ec2_events)} EC2 security events")
        
        # Collect S3 security data
        self.logger.info("Collecting S3 security data...")
        s3_events = self.collect_s3_security()
        all_events.extend(s3_events)
        self.logger.info(f"Collected {len(s3_events)} S3 security events")
        
        # Collect IAM security data
        self.logger.info("Collecting IAM security data...")
        iam_events = self.collect_iam_security()
        all_events.extend(iam_events)
        self.logger.info(f"Collected {len(iam_events)} IAM security events")
        
        # Collect CloudTrail security data
        self.logger.info("Collecting CloudTrail security data...")
        cloudtrail_events = self.collect_cloudtrail_security()
        all_events.extend(cloudtrail_events)
        self.logger.info(f"Collected {len(cloudtrail_events)} CloudTrail security events")
        
        # Collect GuardDuty security data
        self.logger.info("Collecting GuardDuty security data...")
        guardduty_events = self.collect_guardduty_security()
        all_events.extend(guardduty_events)
        self.logger.info(f"Collected {len(guardduty_events)} GuardDuty security events")
        
        self.logger.info(f"Total security events collected: {len(all_events)}")
        
        return all_events
    
    def save_security_events(self, events: List[Dict], output_dir: str = "logs") -> str:
        """Save security events to JSON file"""
        try:
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Create filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aws_security_events_{timestamp}.json"
            filepath = os.path.join(output_dir, filename)
            
            # Save events
            with open(filepath, 'w') as f:
                json.dump(events, f, indent=2, default=str)
            
            self.logger.info(f"Security events saved to: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to save security events: {e}")
            raise
        


if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Initialize collector
        collector = AWSCollector(region="us-east-1", max_events=1000)
        
        print("🦅 CloudHawk AWS Security Collector")
        print("=" * 50)
        
        # Collect all security data
        security_events = collector.collect_all_security_data()
        
        # Save to file
        output_file = collector.save_security_events(security_events)
        
        # Print summary
        print("\n📊 Collection Summary:")
        print(f"Total security events collected: {len(security_events)}")
        
        # Count by severity
        severity_counts = {}
        for event in security_events:
            severity = event.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("\n🚨 Events by Severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")
        
        # Count by source
        source_counts = {}
        for event in security_events:
            source = event.get("source", "UNKNOWN")
            source_counts[source] = source_counts.get(source, 0) + 1
        
        print("\n📋 Events by Source:")
        for source, count in sorted(source_counts.items()):
            print(f"  {source}: {count}")
        
        print(f"\n✅ Security events saved to: {output_file}")
        print("\n🔍 Next steps:")
        print("1. Review the collected events")
        print("2. Run the rule engine to detect security issues")
        print("3. Configure alerting for critical findings")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        logging.error(f"Collection failed: {e}")
