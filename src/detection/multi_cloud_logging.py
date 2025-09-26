#!/usr/bin/env python3
"""
CloudHawk Multi-Cloud Logging Configuration

This module provides centralized logging configuration for AWS, Azure, and GCP
security event collection and analysis.
"""

import os
import json
import logging
import logging.handlers
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

class MultiCloudLogger:
    """Centralized logging for multi-cloud security operations"""
    
    def __init__(self, config: Dict = None):
        """Initialize multi-cloud logger"""
        self.config = config or {}
        self.log_dir = self.config.get('log_dir', 'logs')
        self.max_file_size = self.config.get('max_file_size', 10 * 1024 * 1024)  # 10MB
        self.backup_count = self.config.get('backup_count', 5)
        
        # Ensure log directory exists
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        
        # Setup loggers for each cloud provider
        self.aws_logger = self._setup_provider_logger('aws')
        self.azure_logger = self._setup_provider_logger('azure')
        self.gcp_logger = self._setup_provider_logger('gcp')
        self.detection_logger = self._setup_detection_logger()
        
    def _setup_provider_logger(self, provider: str) -> logging.Logger:
        """Setup logger for specific cloud provider"""
        logger = logging.getLogger(f'cloudhawk.{provider}')
        logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers
        if logger.handlers:
            return logger
            
        # File handler for provider-specific logs
        log_file = os.path.join(self.log_dir, f'{provider}_security_events.log')
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=self.max_file_size, 
            backupCount=self.backup_count
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _setup_detection_logger(self) -> logging.Logger:
        """Setup logger for detection operations"""
        logger = logging.getLogger('cloudhawk.detection')
        logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers
        if logger.handlers:
            return logger
            
        # File handler for detection logs
        log_file = os.path.join(self.log_dir, 'detection_operations.log')
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=self.max_file_size, 
            backupCount=self.backup_count
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def log_collection_start(self, provider: str, services: List[str]) -> None:
        """Log start of data collection for provider"""
        logger = getattr(self, f'{provider}_logger')
        logger.info(f"Starting {provider.upper()} security data collection for services: {', '.join(services)}")
    
    def log_collection_complete(self, provider: str, events_count: int, duration: float) -> None:
        """Log completion of data collection"""
        logger = getattr(self, f'{provider}_logger')
        logger.info(f"{provider.upper()} collection complete: {events_count} events in {duration:.2f}s")
    
    def log_collection_error(self, provider: str, service: str, error: str) -> None:
        """Log collection error for specific service"""
        logger = getattr(self, f'{provider}_logger')
        logger.error(f"{provider.upper()} {service} collection failed: {error}")
    
    def log_detection_start(self, detection_type: str, events_count: int) -> None:
        """Log start of detection operation"""
        self.detection_logger.info(f"Starting {detection_type} detection on {events_count} events")
    
    def log_detection_complete(self, detection_type: str, findings_count: int, duration: float) -> None:
        """Log completion of detection operation"""
        self.detection_logger.info(f"{detection_type} detection complete: {findings_count} findings in {duration:.2f}s")
    
    def log_security_event(self, provider: str, event: Dict) -> None:
        """Log security event with provider context"""
        logger = getattr(self, f'{provider}_logger')
        logger.info(f"Security event: {event.get('event_type', 'UNKNOWN')} - {event.get('description', 'No description')}")
    
    def log_alert_generated(self, alert: Dict) -> None:
        """Log generated security alert"""
        self.detection_logger.warning(f"Security alert generated: {alert.get('title', 'Unknown')} - Severity: {alert.get('severity', 'UNKNOWN')}")
    
    def log_health_score(self, provider: str, score: float, category_scores: Dict) -> None:
        """Log health score calculation"""
        logger = getattr(self, f'{provider}_logger')
        logger.info(f"Health score calculated: {score:.2f} - Category scores: {category_scores}")
    
    def get_provider_logs(self, provider: str, lines: int = 100) -> List[str]:
        """Get recent logs for specific provider"""
        log_file = os.path.join(self.log_dir, f'{provider}_security_events.log')
        if not os.path.exists(log_file):
            return []
        
        try:
            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                return all_lines[-lines:] if lines > 0 else all_lines
        except Exception as e:
            self.detection_logger.error(f"Failed to read {provider} logs: {e}")
            return []
    
    def get_detection_logs(self, lines: int = 100) -> List[str]:
        """Get recent detection logs"""
        log_file = os.path.join(self.log_dir, 'detection_operations.log')
        if not os.path.exists(log_file):
            return []
        
        try:
            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                return all_lines[-lines:] if lines > 0 else all_lines
        except Exception as e:
            self.detection_logger.error(f"Failed to read detection logs: {e}")
            return []
    
    def cleanup_old_logs(self, days: int = 30) -> None:
        """Clean up logs older than specified days"""
        import time
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        
        for log_file in Path(self.log_dir).glob('*.log*'):
            if log_file.stat().st_mtime < cutoff_time:
                try:
                    log_file.unlink()
                    self.detection_logger.info(f"Cleaned up old log file: {log_file}")
                except Exception as e:
                    self.detection_logger.error(f"Failed to clean up {log_file}: {e}")

# Global logger instance
multi_cloud_logger = MultiCloudLogger()

def get_provider_logger(provider: str) -> logging.Logger:
    """Get logger for specific cloud provider"""
    return getattr(multi_cloud_logger, f'{provider}_logger')

def get_detection_logger() -> logging.Logger:
    """Get detection operations logger"""
    return multi_cloud_logger.detection_logger

def log_multi_cloud_operation(operation: str, provider: str, details: Dict) -> None:
    """Log multi-cloud operation with structured details"""
    logger = get_provider_logger(provider)
    logger.info(f"Multi-cloud operation: {operation} - Details: {json.dumps(details, default=str)}")

def log_cross_cloud_correlation(correlation_type: str, providers: List[str], findings: List[Dict]) -> None:
    """Log cross-cloud security correlation findings"""
    detection_logger = get_detection_logger()
    detection_logger.warning(f"Cross-cloud correlation detected: {correlation_type} across {', '.join(providers)} - {len(findings)} findings")

if __name__ == "__main__":
    # Test the multi-cloud logging system
    logger = MultiCloudLogger()
    
    # Test provider logging
    logger.log_collection_start('aws', ['ec2', 's3', 'iam'])
    logger.log_collection_complete('aws', 150, 45.2)
    
    logger.log_collection_start('azure', ['vm', 'storage', 'keyvault'])
    logger.log_collection_complete('azure', 89, 32.1)
    
    logger.log_collection_start('gcp', ['compute', 'storage', 'iam'])
    logger.log_collection_complete('gcp', 203, 67.8)
    
    # Test detection logging
    logger.log_detection_start('vulnerability_scan', 442)
    logger.log_detection_complete('vulnerability_scan', 12, 15.3)
    
    logger.log_detection_start('misconfiguration_scan', 442)
    logger.log_detection_complete('misconfiguration_scan', 8, 12.7)
    
    # Test cross-cloud correlation
    log_cross_cloud_correlation('credential_exposure', ['aws', 'azure'], [
        {'type': 'exposed_key', 'severity': 'HIGH'},
        {'type': 'weak_password', 'severity': 'MEDIUM'}
    ])
    
    print("Multi-cloud logging test completed")
