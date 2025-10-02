"""
CloudHawk Compliance Engine
Provides compliance reporting for SOC2, PCI-DSS, and CIS benchmarks
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    SOC2 = "SOC2"
    PCI_DSS = "PCI-DSS"
    CIS = "CIS"

@dataclass
class ComplianceControl:
    """Represents a compliance control"""
    id: str
    title: str
    description: str
    framework: ComplianceFramework
    category: str
    severity: str
    requirements: List[str]
    evidence_required: List[str]
    remediation: str

@dataclass
class ComplianceResult:
    """Represents compliance assessment result"""
    control_id: str
    status: str  # PASS, FAIL, WARNING, NOT_APPLICABLE
    score: float  # 0.0 to 1.0
    evidence: List[Dict]
    findings: List[Dict]
    last_assessed: datetime

class ComplianceEngine:
    """Multi-framework compliance assessment engine"""
    
    def __init__(self, config: Dict = None):
        """Initialize compliance engine"""
        self.config = config or {}
        self.controls = {}
        self.results = {}
        
        # Load compliance controls
        self._load_compliance_controls()
    
    def _load_compliance_controls(self):
        """Load compliance controls for all frameworks"""
        # SOC2 Controls
        self._load_soc2_controls()
        
        # PCI-DSS Controls
        self._load_pci_dss_controls()
        
        # CIS Controls
        self._load_cis_controls()
    
    def _load_soc2_controls(self):
        """Load SOC2 Type II controls"""
        soc2_controls = [
            ComplianceControl(
                id="CC6.1",
                title="Logical and Physical Access Security",
                description="The entity implements logical and physical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives.",
                framework=ComplianceFramework.SOC2,
                category="Access Control",
                severity="HIGH",
                requirements=[
                    "Implement multi-factor authentication",
                    "Regular access reviews",
                    "Principle of least privilege",
                    "Secure access controls"
                ],
                evidence_required=[
                    "IAM policies and configurations",
                    "Access review reports",
                    "Authentication logs",
                    "Network security controls"
                ],
                remediation="Implement strong access controls and regular access reviews"
            ),
            ComplianceControl(
                id="CC6.2",
                title="Prior to Issuing System Credentials",
                description="Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity.",
                framework=ComplianceFramework.SOC2,
                category="Access Control",
                severity="HIGH",
                requirements=[
                    "User provisioning process",
                    "Identity verification",
                    "Access authorization",
                    "Credential management"
                ],
                evidence_required=[
                    "User provisioning procedures",
                    "Identity verification records",
                    "Access authorization documentation"
                ],
                remediation="Establish formal user provisioning and deprovisioning processes"
            ),
            ComplianceControl(
                id="CC6.3",
                title="Password Management",
                description="The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on employment status or changes in job responsibilities.",
                framework=ComplianceFramework.SOC2,
                category="Access Control",
                severity="MEDIUM",
                requirements=[
                    "Strong password policies",
                    "Password complexity requirements",
                    "Password expiration",
                    "Secure password storage"
                ],
                evidence_required=[
                    "Password policy documentation",
                    "Password complexity settings",
                    "Password management procedures"
                ],
                remediation="Implement and enforce strong password policies"
            ),
            ComplianceControl(
                id="CC7.1",
                title="System Operations",
                description="To meet its objectives, the entity uses detection and monitoring procedures to identify (1) anomalies that could result in actual or potential security events and (2) security events that could result in actual or potential security incidents.",
                framework=ComplianceFramework.SOC2,
                category="Monitoring",
                severity="HIGH",
                requirements=[
                    "Security monitoring",
                    "Anomaly detection",
                    "Incident response",
                    "Log management"
                ],
                evidence_required=[
                    "Security monitoring tools",
                    "Anomaly detection systems",
                    "Incident response procedures",
                    "Security logs and reports"
                ],
                remediation="Implement comprehensive security monitoring and incident response"
            )
        ]
        
        for control in soc2_controls:
            self.controls[control.id] = control
    
    def _load_pci_dss_controls(self):
        """Load PCI-DSS controls"""
        pci_controls = [
            ComplianceControl(
                id="PCI-1",
                title="Install and Maintain Network Security Controls",
                description="Network security controls (firewalls) are installed and maintained to protect cardholder data.",
                framework=ComplianceFramework.PCI_DSS,
                category="Network Security",
                severity="CRITICAL",
                requirements=[
                    "Firewall configuration",
                    "Network segmentation",
                    "Traffic filtering",
                    "Security monitoring"
                ],
                evidence_required=[
                    "Firewall configurations",
                    "Network diagrams",
                    "Security policies",
                    "Monitoring logs"
                ],
                remediation="Implement and maintain proper network security controls"
            ),
            ComplianceControl(
                id="PCI-2",
                title="Apply Secure Configurations",
                description="System components are configured with secure settings and maintained securely.",
                framework=ComplianceFramework.PCI_DSS,
                category="System Security",
                severity="HIGH",
                requirements=[
                    "Secure system configurations",
                    "Default password changes",
                    "Unnecessary services removal",
                    "Security hardening"
                ],
                evidence_required=[
                    "System configuration documentation",
                    "Security hardening reports",
                    "Vulnerability assessments",
                    "Configuration management"
                ],
                remediation="Apply secure configurations and maintain security baselines"
            ),
            ComplianceControl(
                id="PCI-3",
                title="Protect Stored Cardholder Data",
                description="Cardholder data is protected using strong cryptography and security protocols.",
                framework=ComplianceFramework.PCI_DSS,
                category="Data Protection",
                severity="CRITICAL",
                requirements=[
                    "Data encryption at rest",
                    "Strong encryption algorithms",
                    "Key management",
                    "Data retention policies"
                ],
                evidence_required=[
                    "Encryption implementation",
                    "Key management procedures",
                    "Data retention policies",
                    "Encryption key documentation"
                ],
                remediation="Implement strong encryption for stored cardholder data"
            )
        ]
        
        for control in pci_controls:
            self.controls[control.id] = control
    
    def _load_cis_controls(self):
        """Load CIS benchmark controls"""
        cis_controls = [
            ComplianceControl(
                id="CIS-1.1",
                title="Establish and Maintain Detailed Asset Inventory",
                description="Establish and maintain a detailed asset inventory of all technology assets with the potential to store or process data.",
                framework=ComplianceFramework.CIS,
                category="Asset Management",
                severity="MEDIUM",
                requirements=[
                    "Asset inventory system",
                    "Asset classification",
                    "Asset tracking",
                    "Regular asset reviews"
                ],
                evidence_required=[
                    "Asset inventory reports",
                    "Asset classification documentation",
                    "Asset tracking systems",
                    "Regular review records"
                ],
                remediation="Implement comprehensive asset inventory and management"
            ),
            ComplianceControl(
                id="CIS-2.1",
                title="Establish and Maintain a Software Inventory",
                description="Establish and maintain a detailed inventory of all licensed software installed on organization-owned assets.",
                framework=ComplianceFramework.CIS,
                category="Software Management",
                severity="MEDIUM",
                requirements=[
                    "Software inventory",
                    "License management",
                    "Software tracking",
                    "Regular software reviews"
                ],
                evidence_required=[
                    "Software inventory reports",
                    "License documentation",
                    "Software tracking systems",
                    "Regular review records"
                ],
                remediation="Implement comprehensive software inventory and license management"
            ),
            ComplianceControl(
                id="CIS-3.1",
                title="Establish and Maintain a Data Inventory",
                description="Establish and maintain a detailed inventory of all data assets with the potential to store or process data.",
                framework=ComplianceFramework.CIS,
                category="Data Management",
                severity="HIGH",
                requirements=[
                    "Data inventory",
                    "Data classification",
                    "Data mapping",
                    "Data governance"
                ],
                evidence_required=[
                    "Data inventory reports",
                    "Data classification documentation",
                    "Data mapping diagrams",
                    "Data governance policies"
                ],
                remediation="Implement comprehensive data inventory and classification"
            )
        ]
        
        for control in cis_controls:
            self.controls[control.id] = control
    
    def assess_compliance(self, events: List[Dict], framework: ComplianceFramework = None) -> Dict:
        """Assess compliance against specified framework"""
        logger.info(f"Starting compliance assessment for {framework.value if framework else 'all frameworks'}")
        
        results = {
            'assessment_id': f"compliance_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            'timestamp': datetime.utcnow().isoformat(),
            'framework': framework.value if framework else 'ALL',
            'controls_assessed': 0,
            'controls_passed': 0,
            'controls_failed': 0,
            'overall_score': 0.0,
            'results': []
        }
        
        # Filter controls by framework if specified
        controls_to_assess = self.controls
        if framework:
            controls_to_assess = {k: v for k, v in self.controls.items() if v.framework == framework}
        
        # Assess each control
        for control_id, control in controls_to_assess.items():
            try:
                result = self._assess_control(control, events)
                results['results'].append(result)
                results['controls_assessed'] += 1
                
                if result.status == 'PASS':
                    results['controls_passed'] += 1
                elif result.status == 'FAIL':
                    results['controls_failed'] += 1
                    
            except Exception as e:
                logger.error(f"Error assessing control {control_id}: {e}")
        
        # Calculate overall score
        if results['controls_assessed'] > 0:
            results['overall_score'] = results['controls_passed'] / results['controls_assessed']
        
        # Store results
        self.results[results['assessment_id']] = results
        
        logger.info(f"Compliance assessment completed: {results['controls_passed']}/{results['controls_assessed']} controls passed")
        
        return results
    
    def _assess_control(self, control: ComplianceControl, events: List[Dict]) -> ComplianceResult:
        """Assess individual compliance control"""
        evidence = []
        findings = []
        score = 0.0
        status = 'NOT_APPLICABLE'
        
        try:
            # Assess based on control type
            if control.category == "Access Control":
                evidence, findings, score = self._assess_access_control(control, events)
            elif control.category == "Network Security":
                evidence, findings, score = self._assess_network_security(control, events)
            elif control.category == "Data Protection":
                evidence, findings, score = self._assess_data_protection(control, events)
            elif control.category == "Monitoring":
                evidence, findings, score = self._assess_monitoring(control, events)
            elif control.category == "Asset Management":
                evidence, findings, score = self._assess_asset_management(control, events)
            else:
                evidence, findings, score = self._assess_generic_control(control, events)
            
            # Determine status based on score
            if score >= 0.8:
                status = 'PASS'
            elif score >= 0.5:
                status = 'WARNING'
            else:
                status = 'FAIL'
                
        except Exception as e:
            logger.error(f"Error assessing control {control.id}: {e}")
            status = 'FAIL'
            findings.append({
                'type': 'ERROR',
                'description': f"Assessment error: {str(e)}",
                'severity': 'HIGH'
            })
        
        return ComplianceResult(
            control_id=control.id,
            status=status,
            score=score,
            evidence=evidence,
            findings=findings,
            last_assessed=datetime.utcnow()
        )
    
    def _assess_access_control(self, control: ComplianceControl, events: List[Dict]) -> Tuple[List[Dict], List[Dict], float]:
        """Assess access control compliance"""
        evidence = []
        findings = []
        score = 0.0
        
        # Check for IAM-related events
        iam_events = [e for e in events if 'IAM' in e.get('source', '')]
        
        # Evidence: IAM policies and configurations
        if iam_events:
            evidence.append({
                'type': 'IAM_EVENTS',
                'description': f"Found {len(iam_events)} IAM-related events",
                'count': len(iam_events)
            })
            score += 0.3
        
        # Check for MFA implementation
        mfa_events = [e for e in iam_events if 'MFA' in e.get('description', '')]
        if mfa_events:
            evidence.append({
                'type': 'MFA_IMPLEMENTATION',
                'description': "MFA-related events found",
                'count': len(mfa_events)
            })
            score += 0.4
        else:
            findings.append({
                'type': 'MISSING_MFA',
                'description': "No MFA implementation evidence found",
                'severity': 'HIGH'
            })
        
        # Check for access review events
        access_review_events = [e for e in iam_events if 'access' in e.get('description', '').lower()]
        if access_review_events:
            evidence.append({
                'type': 'ACCESS_REVIEWS',
                'description': "Access review activities found",
                'count': len(access_review_events)
            })
            score += 0.3
        
        return evidence, findings, min(score, 1.0)
    
    def _assess_network_security(self, control: ComplianceControl, events: List[Dict]) -> Tuple[List[Dict], List[Dict], float]:
        """Assess network security compliance"""
        evidence = []
        findings = []
        score = 0.0
        
        # Check for firewall/security group events
        network_events = [e for e in events if any(keyword in e.get('source', '') for keyword in ['FIREWALL', 'SECURITY_GROUP', 'NSG'])]
        
        if network_events:
            evidence.append({
                'type': 'NETWORK_CONTROLS',
                'description': f"Found {len(network_events)} network security events",
                'count': len(network_events)
            })
            score += 0.5
        
        # Check for overly permissive rules
        permissive_events = [e for e in network_events if 'permissive' in e.get('description', '').lower() or 'open' in e.get('description', '').lower()]
        if permissive_events:
            findings.append({
                'type': 'PERMISSIVE_RULES',
                'description': f"Found {len(permissive_events)} overly permissive network rules",
                'severity': 'HIGH'
            })
            score -= 0.3
        
        return evidence, findings, max(score, 0.0)
    
    def _assess_data_protection(self, control: ComplianceControl, events: List[Dict]) -> Tuple[List[Dict], List[Dict], float]:
        """Assess data protection compliance"""
        evidence = []
        findings = []
        score = 0.0
        
        # Check for encryption events
        encryption_events = [e for e in events if 'encryption' in e.get('description', '').lower()]
        
        if encryption_events:
            evidence.append({
                'type': 'ENCRYPTION_EVENTS',
                'description': f"Found {len(encryption_events)} encryption-related events",
                'count': len(encryption_events)
            })
            score += 0.4
        
        # Check for unencrypted resources
        unencrypted_events = [e for e in events if 'no encryption' in e.get('description', '').lower()]
        if unencrypted_events:
            findings.append({
                'type': 'UNENCRYPTED_RESOURCES',
                'description': f"Found {len(unencrypted_events)} unencrypted resources",
                'severity': 'CRITICAL'
            })
            score -= 0.5
        
        return evidence, findings, max(score, 0.0)
    
    def _assess_monitoring(self, control: ComplianceControl, events: List[Dict]) -> Tuple[List[Dict], List[Dict], float]:
        """Assess monitoring compliance"""
        evidence = []
        findings = []
        score = 0.0
        
        # Check for monitoring/logging events
        monitoring_events = [e for e in events if any(keyword in e.get('source', '') for keyword in ['LOGGING', 'MONITORING', 'CLOUDTRAIL', 'ACTIVITY_LOG'])]
        
        if monitoring_events:
            evidence.append({
                'type': 'MONITORING_SYSTEMS',
                'description': f"Found {len(monitoring_events)} monitoring/logging events",
                'count': len(monitoring_events)
            })
            score += 0.6
        
        # Check for security findings
        security_events = [e for e in events if 'security' in e.get('description', '').lower()]
        if security_events:
            evidence.append({
                'type': 'SECURITY_MONITORING',
                'description': f"Found {len(security_events)} security-related events",
                'count': len(security_events)
            })
            score += 0.4
        
        return evidence, findings, min(score, 1.0)
    
    def _assess_asset_management(self, control: ComplianceControl, events: List[Dict]) -> Tuple[List[Dict], List[Dict], float]:
        """Assess asset management compliance"""
        evidence = []
        findings = []
        score = 0.0
        
        # Check for asset discovery events
        asset_events = [e for e in events if 'asset' in e.get('description', '').lower() or 'inventory' in e.get('description', '').lower()]
        
        if asset_events:
            evidence.append({
                'type': 'ASSET_DISCOVERY',
                'description': f"Found {len(asset_events)} asset-related events",
                'count': len(asset_events)
            })
            score += 0.5
        
        # Check for compute instances
        compute_events = [e for e in events if 'compute' in e.get('source', '').lower() or 'instance' in e.get('source', '').lower()]
        if compute_events:
            evidence.append({
                'type': 'COMPUTE_ASSETS',
                'description': f"Found {len(compute_events)} compute asset events",
                'count': len(compute_events)
            })
            score += 0.5
        
        return evidence, findings, min(score, 1.0)
    
    def _assess_generic_control(self, control: ComplianceControl, events: List[Dict]) -> Tuple[List[Dict], List[Dict], float]:
        """Generic control assessment"""
        evidence = []
        findings = []
        score = 0.5  # Default neutral score
        
        # Basic evidence collection
        relevant_events = [e for e in events if control.category.lower() in e.get('source', '').lower()]
        
        if relevant_events:
            evidence.append({
                'type': 'RELEVANT_EVENTS',
                'description': f"Found {len(relevant_events)} relevant events",
                'count': len(relevant_events)
            })
            score += 0.3
        
        return evidence, findings, min(score, 1.0)
    
    def generate_compliance_report(self, assessment_id: str) -> Dict:
        """Generate detailed compliance report"""
        if assessment_id not in self.results:
            raise ValueError(f"Assessment {assessment_id} not found")
        
        assessment = self.results[assessment_id]
        
        report = {
            'report_id': f"compliance_report_{assessment_id}",
            'generated_at': datetime.utcnow().isoformat(),
            'assessment': assessment,
            'executive_summary': self._generate_executive_summary(assessment),
            'detailed_findings': self._generate_detailed_findings(assessment),
            'recommendations': self._generate_recommendations(assessment),
            'next_steps': self._generate_next_steps(assessment)
        }
        
        return report
    
    def _generate_executive_summary(self, assessment: Dict) -> Dict:
        """Generate executive summary"""
        total_controls = assessment['controls_assessed']
        passed_controls = assessment['controls_passed']
        failed_controls = assessment['controls_failed']
        overall_score = assessment['overall_score']
        
        return {
            'overall_score': overall_score,
            'compliance_status': 'COMPLIANT' if overall_score >= 0.8 else 'NON_COMPLIANT' if overall_score < 0.5 else 'PARTIALLY_COMPLIANT',
            'controls_summary': {
                'total': total_controls,
                'passed': passed_controls,
                'failed': failed_controls,
                'pass_rate': (passed_controls / total_controls * 100) if total_controls > 0 else 0
            },
            'key_risks': self._identify_key_risks(assessment),
            'improvement_areas': self._identify_improvement_areas(assessment)
        }
    
    def _generate_detailed_findings(self, assessment: Dict) -> List[Dict]:
        """Generate detailed findings"""
        findings = []
        
        for result in assessment['results']:
            if result['status'] != 'PASS':
                findings.append({
                    'control_id': result['control_id'],
                    'status': result['status'],
                    'score': result['score'],
                    'findings': result['findings'],
                    'evidence': result['evidence']
                })
        
        return findings
    
    def _generate_recommendations(self, assessment: Dict) -> List[Dict]:
        """Generate compliance recommendations"""
        recommendations = []
        
        for result in assessment['results']:
            if result['status'] == 'FAIL':
                control = self.controls.get(result['control_id'])
                if control:
                    recommendations.append({
                        'control_id': result['control_id'],
                        'title': control.title,
                        'priority': 'HIGH',
                        'recommendation': control.remediation,
                        'timeline': '30 days'
                    })
        
        return recommendations
    
    def _generate_next_steps(self, assessment: Dict) -> List[str]:
        """Generate next steps"""
        next_steps = []
        
        if assessment['overall_score'] < 0.8:
            next_steps.append("Address failed compliance controls immediately")
            next_steps.append("Implement remediation plans for high-priority findings")
            next_steps.append("Schedule follow-up compliance assessment")
        
        next_steps.append("Continue monitoring compliance status")
        next_steps.append("Update compliance documentation")
        
        return next_steps
    
    def _identify_key_risks(self, assessment: Dict) -> List[str]:
        """Identify key compliance risks"""
        risks = []
        
        failed_controls = [r for r in assessment['results'] if r['status'] == 'FAIL']
        
        if len(failed_controls) > 0:
            risks.append(f"{len(failed_controls)} controls failed compliance assessment")
        
        high_severity_findings = []
        for result in assessment['results']:
            for finding in result.get('findings', []):
                if finding.get('severity') == 'CRITICAL':
                    high_severity_findings.append(finding)
        
        if high_severity_findings:
            risks.append(f"{len(high_severity_findings)} critical findings require immediate attention")
        
        return risks
    
    def _identify_improvement_areas(self, assessment: Dict) -> List[str]:
        """Identify areas for improvement"""
        improvements = []
        
        warning_controls = [r for r in assessment['results'] if r['status'] == 'WARNING']
        if warning_controls:
            improvements.append(f"Improve {len(warning_controls)} controls with warning status")
        
        low_score_controls = [r for r in assessment['results'] if r['score'] < 0.6]
        if low_score_controls:
            improvements.append(f"Enhance {len(low_score_controls)} controls with low scores")
        
        return improvements
