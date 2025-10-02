#!/usr/bin/env python3
"""
CloudHawk Anomaly Detection Module

This module implements machine learning-based anomaly detection for AWS security events.
It uses statistical analysis and pattern recognition to identify unusual behavior patterns.
"""

import os
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import statistics
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Multi-cloud anomaly detection engine for AWS, Azure, and GCP security events"""
    
    def __init__(self, config: Dict = None):
        """Initialize the anomaly detector"""
        self.config = config or {}
        self.baseline_data = {}
        self.anomaly_threshold = self.config.get('anomaly_threshold', 2.0)  # Standard deviations
        self.min_samples = self.config.get('min_samples', 10)  # Minimum samples for baseline
        self.time_window_hours = self.config.get('time_window_hours', 24)
        
        # ML Models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.pca = PCA(n_components=0.95)
        
        # Model persistence
        self.model_dir = os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Load existing models if available
        self._load_models()
        
        # Anomaly patterns to detect
        self.patterns = {
            'unusual_access_times': self._detect_unusual_access_times,
            'unusual_geographic_access': self._detect_unusual_geographic_access,
            'unusual_api_usage': self._detect_unusual_api_usage,
            'unusual_resource_access': self._detect_unusual_resource_access,
            'unusual_user_behavior': self._detect_unusual_user_behavior,
            'unusual_error_patterns': self._detect_unusual_error_patterns,
            'unusual_data_transfer': self._detect_unusual_data_transfer,
            'unusual_privilege_escalation': self._detect_unusual_privilege_escalation,
            'ml_anomaly_detection': self._detect_ml_anomalies,
            'behavioral_analysis': self._detect_behavioral_anomalies
        }
    
    def analyze_events(self, events: List[Dict]) -> List[Dict]:
        """Analyze events for anomalies"""
        logger.info(f"Starting anomaly analysis on {len(events)} events")
        
        anomalies = []
        
        # Group events by type and source
        grouped_events = self._group_events(events)
        
        # Update baseline data
        self._update_baseline(grouped_events)
        
        # Detect anomalies for each pattern
        for pattern_name, detector_func in self.patterns.items():
            try:
                pattern_anomalies = detector_func(grouped_events)
                anomalies.extend(pattern_anomalies)
                logger.info(f"Detected {len(pattern_anomalies)} anomalies for pattern: {pattern_name}")
            except Exception as e:
                logger.error(f"Error detecting anomalies for pattern {pattern_name}: {e}")
        
        # Remove duplicates and sort by severity
        anomalies = self._deduplicate_anomalies(anomalies)
        anomalies.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
        
        logger.info(f"Total anomalies detected: {len(anomalies)}")
        return anomalies
    
    def _load_models(self):
        """Load pre-trained models if available"""
        try:
            isolation_forest_path = os.path.join(self.model_dir, 'isolation_forest.joblib')
            scaler_path = os.path.join(self.model_dir, 'scaler.joblib')
            
            if os.path.exists(isolation_forest_path):
                self.isolation_forest = joblib.load(isolation_forest_path)
                logger.info("Loaded pre-trained Isolation Forest model")
            
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info("Loaded pre-trained scaler")
                
        except Exception as e:
            logger.warning(f"Could not load pre-trained models: {e}")
    
    def _save_models(self):
        """Save trained models"""
        try:
            isolation_forest_path = os.path.join(self.model_dir, 'isolation_forest.joblib')
            scaler_path = os.path.join(self.model_dir, 'scaler.joblib')
            
            joblib.dump(self.isolation_forest, isolation_forest_path)
            joblib.dump(self.scaler, scaler_path)
            
            logger.info("Saved trained models")
            
        except Exception as e:
            logger.error(f"Could not save models: {e}")
    
    def _detect_ml_anomalies(self, grouped_events: Dict) -> List[Dict]:
        """Detect anomalies using machine learning models"""
        anomalies = []
        
        try:
            # Prepare features for ML
            features_df = self._prepare_features(grouped_events)
            
            if len(features_df) < self.min_samples:
                logger.warning("Not enough samples for ML anomaly detection")
                return anomalies
            
            # Scale features
            features_scaled = self.scaler.fit_transform(features_df)
            
            # Train Isolation Forest
            self.isolation_forest.fit(features_scaled)
            
            # Predict anomalies
            anomaly_scores = self.isolation_forest.decision_function(features_scaled)
            anomaly_predictions = self.isolation_forest.predict(features_scaled)
            
            # Identify anomalies
            for i, (score, prediction) in enumerate(zip(anomaly_scores, anomaly_predictions)):
                if prediction == -1:  # Anomaly
                    anomaly_score = abs(score)
                    
                    # Create anomaly event
                    anomaly = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'source': 'ML_ANOMALY_DETECTOR',
                        'resource_id': f"ml_anomaly_{i}",
                        'event_type': 'ML_ANOMALY',
                        'severity': self._map_anomaly_score_to_severity(anomaly_score),
                        'description': f"ML-based anomaly detected with score {anomaly_score:.3f}",
                        'raw_event': {
                            'anomaly_score': anomaly_score,
                            'features': features_df.iloc[i].to_dict(),
                            'model': 'IsolationForest'
                        },
                        'additional_fields': {
                            'ml_anomaly': {
                                'score': anomaly_score,
                                'model': 'IsolationForest',
                                'features_used': list(features_df.columns),
                                'confidence': min(anomaly_score * 2, 1.0)
                            }
                        }
                    }
                    anomalies.append(anomaly)
            
            # Save updated models
            self._save_models()
            
        except Exception as e:
            logger.error(f"Error in ML anomaly detection: {e}")
        
        return anomalies
    
    def _detect_behavioral_anomalies(self, grouped_events: Dict) -> List[Dict]:
        """Detect behavioral anomalies using clustering and pattern analysis"""
        anomalies = []
        
        try:
            # Prepare behavioral features
            behavioral_df = self._prepare_behavioral_features(grouped_events)
            
            if len(behavioral_df) < self.min_samples:
                return anomalies
            
            # Apply PCA for dimensionality reduction
            features_scaled = self.scaler.fit_transform(behavioral_df)
            features_pca = self.pca.fit_transform(features_scaled)
            
            # Cluster analysis
            clusters = self.dbscan.fit_predict(features_pca)
            
            # Find outliers (noise points in DBSCAN)
            noise_points = np.where(clusters == -1)[0]
            
            for point_idx in noise_points:
                if point_idx < len(behavioral_df):
                    anomaly = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'source': 'BEHAVIORAL_ANALYZER',
                        'resource_id': f"behavioral_anomaly_{point_idx}",
                        'event_type': 'BEHAVIORAL_ANOMALY',
                        'severity': 'MEDIUM',
                        'description': f"Behavioral anomaly detected in cluster analysis",
                        'raw_event': {
                            'cluster_id': -1,
                            'behavioral_features': behavioral_df.iloc[point_idx].to_dict()
                        },
                        'additional_fields': {
                            'behavioral_anomaly': {
                                'cluster_id': -1,
                                'features': behavioral_df.iloc[point_idx].to_dict(),
                                'analysis_type': 'DBSCAN_Clustering'
                            }
                        }
                    }
                    anomalies.append(anomaly)
            
        except Exception as e:
            logger.error(f"Error in behavioral anomaly detection: {e}")
        
        return anomalies
    
    def _prepare_features(self, grouped_events: Dict) -> pd.DataFrame:
        """Prepare features for ML models"""
        features = []
        
        for event_type, events in grouped_events.items():
            for event in events:
                feature_vector = self._extract_event_features(event)
                if feature_vector:
                    features.append(feature_vector)
        
        if not features:
            return pd.DataFrame()
        
        return pd.DataFrame(features)
    
    def _prepare_behavioral_features(self, grouped_events: Dict) -> pd.DataFrame:
        """Prepare behavioral features for clustering"""
        features = []
        
        # Extract behavioral patterns
        for event_type, events in grouped_events.items():
            for event in events:
                behavioral_vector = self._extract_behavioral_features(event)
                if behavioral_vector:
                    features.append(behavioral_vector)
        
        if not features:
            return pd.DataFrame()
        
        return pd.DataFrame(features)
    
    def _extract_event_features(self, event: Dict) -> Optional[Dict]:
        """Extract numerical features from event"""
        try:
            features = {}
            
            # Time-based features
            timestamp = event.get('timestamp', '')
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                features['hour'] = dt.hour
                features['day_of_week'] = dt.weekday()
                features['day_of_month'] = dt.day
            
            # Severity encoding
            severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            features['severity_numeric'] = severity_map.get(event.get('severity', 'INFO'), 0)
            
            # Source encoding (simple hash)
            source = event.get('source', '')
            features['source_hash'] = hash(source) % 1000
            
            # Event type encoding
            event_type = event.get('event_type', '')
            features['event_type_hash'] = hash(event_type) % 1000
            
            # Resource ID length (proxy for complexity)
            resource_id = event.get('resource_id', '')
            features['resource_id_length'] = len(resource_id)
            
            # Raw event size
            raw_event = event.get('raw_event', {})
            features['raw_event_size'] = len(str(raw_event))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting event features: {e}")
            return None
    
    def _extract_behavioral_features(self, event: Dict) -> Optional[Dict]:
        """Extract behavioral features for clustering"""
        try:
            features = {}
            
            # User behavior patterns
            user_identity = event.get('raw_event', {}).get('userIdentity', {})
            if user_identity:
                features['user_type_encoded'] = hash(user_identity.get('type', '')) % 100
                features['has_mfa'] = 1 if user_identity.get('mfaAuthenticated') else 0
            
            # Geographic patterns
            source_ip = event.get('raw_event', {}).get('sourceIPAddress', '')
            features['has_source_ip'] = 1 if source_ip else 0
            features['ip_length'] = len(source_ip)
            
            # API usage patterns
            event_name = event.get('raw_event', {}).get('eventName', '')
            features['event_name_length'] = len(event_name)
            features['is_high_risk_event'] = 1 if event_name in [
                'DeleteBucket', 'DeleteUser', 'DeleteRole', 'StopLogging'
            ] else 0
            
            # Resource access patterns
            resource_id = event.get('resource_id', '')
            features['resource_complexity'] = len(resource_id.split('/'))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting behavioral features: {e}")
            return None
    
    def _map_anomaly_score_to_severity(self, score: float) -> str:
        """Map anomaly score to severity level"""
        if score > 0.8:
            return 'CRITICAL'
        elif score > 0.6:
            return 'HIGH'
        elif score > 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _group_events(self, events: List[Dict]) -> Dict:
        """Group events by various dimensions"""
        grouped = {
            'by_source': defaultdict(list),
            'by_type': defaultdict(list),
            'by_user': defaultdict(list),
            'by_resource': defaultdict(list),
            'by_region': defaultdict(list),
            'by_time': defaultdict(list),
            'by_ip': defaultdict(list)
        }
        
        for event in events:
            # Group by source
            source = event.get('source', 'UNKNOWN')
            grouped['by_source'][source].append(event)
            
            # Group by event type
            event_type = event.get('event_type', 'UNKNOWN')
            grouped['by_type'][event_type].append(event)
            
            # Group by user (if available)
            user = event.get('raw_event', {}).get('userIdentity', {}).get('userName', 'UNKNOWN')
            if user != 'UNKNOWN':
                grouped['by_user'][user].append(event)
            
            # Group by resource
            resource = event.get('resource_id', 'UNKNOWN')
            grouped['by_resource'][resource].append(event)
            
            # Group by region
            region = event.get('region', 'UNKNOWN')
            grouped['by_region'][region].append(event)
            
            # Group by time (hour)
            timestamp = event.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour_key = dt.strftime('%Y-%m-%d-%H')
                    grouped['by_time'][hour_key].append(event)
                except:
                    pass
            
            # Group by IP (if available)
            ip = event.get('raw_event', {}).get('sourceIPAddress', 'UNKNOWN')
            if ip != 'UNKNOWN':
                grouped['by_ip'][ip].append(event)
        
        return grouped
    
    def _update_baseline(self, grouped_events: Dict):
        """Update baseline statistics for anomaly detection"""
        current_time = datetime.utcnow()
        
        # Update access time patterns
        if 'by_time' in grouped_events:
            self._update_time_baseline(grouped_events['by_time'])
        
        # Update user behavior patterns
        if 'by_user' in grouped_events:
            self._update_user_baseline(grouped_events['by_user'])
        
        # Update API usage patterns
        if 'by_type' in grouped_events:
            self._update_api_baseline(grouped_events['by_type'])
        
        # Update geographic patterns
        if 'by_ip' in grouped_events:
            self._update_geographic_baseline(grouped_events['by_ip'])
    
    def _update_time_baseline(self, time_events: Dict):
        """Update baseline for time-based patterns"""
        if 'time_patterns' not in self.baseline_data:
            self.baseline_data['time_patterns'] = defaultdict(list)
        
        for hour_key, events in time_events.items():
            self.baseline_data['time_patterns'][hour_key].extend(events)
            
            # Keep only recent data (last 7 days)
            cutoff_time = datetime.utcnow() - timedelta(days=7)
            self.baseline_data['time_patterns'][hour_key] = [
                event for event in self.baseline_data['time_patterns'][hour_key]
                if self._get_event_time(event) > cutoff_time
            ]
    
    def _update_user_baseline(self, user_events: Dict):
        """Update baseline for user behavior patterns"""
        if 'user_patterns' not in self.baseline_data:
            self.baseline_data['user_patterns'] = {}
        
        for user, events in user_events.items():
            if user not in self.baseline_data['user_patterns']:
                self.baseline_data['user_patterns'][user] = {
                    'event_counts': [],
                    'api_calls': [],
                    'resources_accessed': set(),
                    'regions_used': set(),
                    'ip_addresses': set()
                }
            
            user_data = self.baseline_data['user_patterns'][user]
            user_data['event_counts'].append(len(events))
            
            # Track API calls
            for event in events:
                api_call = event.get('raw_event', {}).get('eventName', '')
                if api_call:
                    user_data['api_calls'].append(api_call)
                
                # Track resources
                resource = event.get('resource_id', '')
                if resource:
                    user_data['resources_accessed'].add(resource)
                
                # Track regions
                region = event.get('region', '')
                if region:
                    user_data['regions_used'].add(region)
                
                # Track IP addresses
                ip = event.get('raw_event', {}).get('sourceIPAddress', '')
                if ip:
                    user_data['ip_addresses'].add(ip)
            
            # Keep only recent data
            cutoff_time = datetime.utcnow() - timedelta(days=7)
            user_data['event_counts'] = user_data['event_counts'][-100:]  # Keep last 100 counts
            user_data['api_calls'] = user_data['api_calls'][-500:]  # Keep last 500 API calls
    
    def _update_api_baseline(self, type_events: Dict):
        """Update baseline for API usage patterns"""
        if 'api_patterns' not in self.baseline_data:
            self.baseline_data['api_patterns'] = defaultdict(list)
        
        for event_type, events in type_events.items():
            self.baseline_data['api_patterns'][event_type].extend(events)
            
            # Keep only recent data
            cutoff_time = datetime.utcnow() - timedelta(days=7)
            self.baseline_data['api_patterns'][event_type] = [
                event for event in self.baseline_data['api_patterns'][event_type]
                if self._get_event_time(event) > cutoff_time
            ]
    
    def _update_geographic_baseline(self, ip_events: Dict):
        """Update baseline for geographic patterns"""
        if 'geographic_patterns' not in self.baseline_data:
            self.baseline_data['geographic_patterns'] = defaultdict(list)
        
        for ip, events in ip_events.items():
            self.baseline_data['geographic_patterns'][ip].extend(events)
            
            # Keep only recent data
            cutoff_time = datetime.utcnow() - timedelta(days=7)
            self.baseline_data['geographic_patterns'][ip] = [
                event for event in self.baseline_data['geographic_patterns'][ip]
                if self._get_event_time(event) > cutoff_time
            ]
    
    def _detect_unusual_access_times(self, grouped_events: Dict) -> List[Dict]:
        """Detect unusual access time patterns"""
        anomalies = []
        
        if 'time_patterns' not in self.baseline_data:
            return anomalies
        
        current_hour = datetime.utcnow().strftime('%Y-%m-%d-%H')
        current_events = grouped_events.get('by_time', {}).get(current_hour, [])
        
        if not current_events:
            return anomalies
        
        # Calculate baseline statistics for this hour of day
        hour_of_day = datetime.utcnow().hour
        baseline_counts = []
        
        for hour_key, events in self.baseline_data['time_patterns'].items():
            try:
                hour_dt = datetime.strptime(hour_key, '%Y-%m-%d-%H')
                if hour_dt.hour == hour_of_day:
                    baseline_counts.append(len(events))
            except:
                continue
        
        if len(baseline_counts) < self.min_samples:
            return anomalies
        
        # Calculate statistics
        mean_count = statistics.mean(baseline_counts)
        std_count = statistics.stdev(baseline_counts) if len(baseline_counts) > 1 else 0
        
        current_count = len(current_events)
        
        # Check if current count is anomalous
        if std_count > 0:
            z_score = abs(current_count - mean_count) / std_count
            if z_score > self.anomaly_threshold:
                anomaly = {
                    'type': 'unusual_access_times',
                    'title': 'Unusual Access Time Pattern Detected',
                    'description': f'Unusually high activity detected at {current_hour}. '
                                 f'Current: {current_count}, Baseline: {mean_count:.1f}±{std_count:.1f}',
                    'severity': 'HIGH' if z_score > 3.0 else 'MEDIUM',
                    'severity_score': min(z_score * 2, 10.0),
                    'timestamp': datetime.utcnow().isoformat(),
                    'affected_events': current_events[:10],  # Limit to first 10 events
                    'statistics': {
                        'current_count': current_count,
                        'baseline_mean': mean_count,
                        'baseline_std': std_count,
                        'z_score': z_score
                    }
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_unusual_geographic_access(self, grouped_events: Dict) -> List[Dict]:
        """Detect unusual geographic access patterns"""
        anomalies = []
        
        if 'geographic_patterns' not in self.baseline_data:
            return anomalies
        
        current_ips = set(grouped_events.get('by_ip', {}).keys())
        baseline_ips = set(self.baseline_data['geographic_patterns'].keys())
        
        # Find new IP addresses
        new_ips = current_ips - baseline_ips
        
        for new_ip in new_ips:
            events = grouped_events.get('by_ip', {}).get(new_ip, [])
            if events:
                anomaly = {
                    'type': 'unusual_geographic_access',
                    'title': 'New Geographic Location Detected',
                    'description': f'Access from new IP address: {new_ip}',
                    'severity': 'MEDIUM',
                    'severity_score': 6.0,
                    'timestamp': datetime.utcnow().isoformat(),
                    'affected_events': events[:5],
                    'metadata': {
                        'new_ip': new_ip,
                        'event_count': len(events)
                    }
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_unusual_api_usage(self, grouped_events: Dict) -> List[Dict]:
        """Detect unusual API usage patterns"""
        anomalies = []
        
        if 'api_patterns' not in self.baseline_data:
            return anomalies
        
        # Count API calls by type
        current_api_counts = Counter()
        for event_type, events in grouped_events.get('by_type', {}).items():
            current_api_counts[event_type] = len(events)
        
        # Compare with baseline
        for api_type, current_count in current_api_counts.items():
            baseline_events = self.baseline_data['api_patterns'].get(api_type, [])
            if len(baseline_events) < self.min_samples:
                continue
            
            baseline_counts = [len(baseline_events)]
            mean_count = statistics.mean(baseline_counts)
            std_count = statistics.stdev(baseline_counts) if len(baseline_counts) > 1 else 0
            
            if std_count > 0:
                z_score = abs(current_count - mean_count) / std_count
                if z_score > self.anomaly_threshold:
                    anomaly = {
                        'type': 'unusual_api_usage',
                        'title': f'Unusual {api_type} API Usage',
                        'description': f'Unusually high usage of {api_type} API. '
                                     f'Current: {current_count}, Baseline: {mean_count:.1f}±{std_count:.1f}',
                        'severity': 'HIGH' if z_score > 3.0 else 'MEDIUM',
                        'severity_score': min(z_score * 2, 10.0),
                        'timestamp': datetime.utcnow().isoformat(),
                        'affected_events': grouped_events.get('by_type', {}).get(api_type, [])[:5],
                        'statistics': {
                            'api_type': api_type,
                            'current_count': current_count,
                            'baseline_mean': mean_count,
                            'baseline_std': std_count,
                            'z_score': z_score
                        }
                    }
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_unusual_resource_access(self, grouped_events: Dict) -> List[Dict]:
        """Detect unusual resource access patterns"""
        anomalies = []
        
        # Look for resources with unusually high access
        resource_counts = Counter()
        for resource, events in grouped_events.get('by_resource', {}).items():
            resource_counts[resource] = len(events)
        
        # Find resources with high access counts
        for resource, count in resource_counts.most_common(5):
            if count > 50:  # Threshold for unusual access
                anomaly = {
                    'type': 'unusual_resource_access',
                    'title': f'Unusual Access to Resource: {resource}',
                    'description': f'High number of access attempts to resource: {resource} ({count} events)',
                    'severity': 'MEDIUM',
                    'severity_score': min(count / 10, 10.0),
                    'timestamp': datetime.utcnow().isoformat(),
                    'affected_events': grouped_events.get('by_resource', {}).get(resource, [])[:5],
                    'metadata': {
                        'resource': resource,
                        'access_count': count
                    }
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_unusual_user_behavior(self, grouped_events: Dict) -> List[Dict]:
        """Detect unusual user behavior patterns"""
        anomalies = []
        
        if 'user_patterns' not in self.baseline_data:
            return anomalies
        
        for user, events in grouped_events.get('by_user', {}).items():
            if user not in self.baseline_data['user_patterns']:
                # New user
                anomaly = {
                    'type': 'unusual_user_behavior',
                    'title': f'New User Detected: {user}',
                    'description': f'First-time activity detected for user: {user}',
                    'severity': 'LOW',
                    'severity_score': 3.0,
                    'timestamp': datetime.utcnow().isoformat(),
                    'affected_events': events[:5],
                    'metadata': {
                        'user': user,
                        'event_count': len(events)
                    }
                }
                anomalies.append(anomaly)
                continue
            
            user_data = self.baseline_data['user_patterns'][user]
            current_count = len(events)
            
            # Check for unusual activity volume
            if user_data['event_counts']:
                baseline_counts = user_data['event_counts']
                mean_count = statistics.mean(baseline_counts)
                std_count = statistics.stdev(baseline_counts) if len(baseline_counts) > 1 else 0
                
                if std_count > 0:
                    z_score = abs(current_count - mean_count) / std_count
                    if z_score > self.anomaly_threshold:
                        anomaly = {
                            'type': 'unusual_user_behavior',
                            'title': f'Unusual Activity for User: {user}',
                            'description': f'Unusual activity volume for user {user}. '
                                         f'Current: {current_count}, Baseline: {mean_count:.1f}±{std_count:.1f}',
                            'severity': 'HIGH' if z_score > 3.0 else 'MEDIUM',
                            'severity_score': min(z_score * 2, 10.0),
                            'timestamp': datetime.utcnow().isoformat(),
                            'affected_events': events[:5],
                            'statistics': {
                                'user': user,
                                'current_count': current_count,
                                'baseline_mean': mean_count,
                                'baseline_std': std_count,
                                'z_score': z_score
                            }
                        }
                        anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_unusual_error_patterns(self, grouped_events: Dict) -> List[Dict]:
        """Detect unusual error patterns"""
        anomalies = []
        
        # Look for events with error indicators
        error_events = []
        for event in grouped_events.get('by_type', {}).get('ERROR', []):
            error_events.append(event)
        
        # Also check for events with error in description
        for event_type, events in grouped_events.get('by_type', {}).items():
            for event in events:
                description = event.get('description', '').lower()
                if 'error' in description or 'failed' in description or 'exception' in description:
                    error_events.append(event)
        
        if len(error_events) > 10:  # Threshold for unusual error count
            anomaly = {
                'type': 'unusual_error_patterns',
                'title': 'Unusual Error Pattern Detected',
                'description': f'High number of errors detected: {len(error_events)} error events',
                'severity': 'HIGH',
                'severity_score': min(len(error_events) / 5, 10.0),
                'timestamp': datetime.utcnow().isoformat(),
                'affected_events': error_events[:10],
                'metadata': {
                    'error_count': len(error_events)
                }
            }
            anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_unusual_data_transfer(self, grouped_events: Dict) -> List[Dict]:
        """Detect unusual data transfer patterns"""
        anomalies = []
        
        # Look for S3 events that might indicate data transfer
        s3_events = grouped_events.get('by_source', {}).get('AWS_S3', [])
        
        # Count S3 operations
        s3_operations = Counter()
        for event in s3_events:
            operation = event.get('raw_event', {}).get('eventName', '')
            if operation:
                s3_operations[operation] += 1
        
        # Check for unusual S3 operations
        for operation, count in s3_operations.items():
            if operation in ['GetObject', 'PutObject', 'DeleteObject'] and count > 100:
                anomaly = {
                    'type': 'unusual_data_transfer',
                    'title': f'Unusual S3 {operation} Activity',
                    'description': f'High number of S3 {operation} operations: {count}',
                    'severity': 'MEDIUM',
                    'severity_score': min(count / 20, 10.0),
                    'timestamp': datetime.utcnow().isoformat(),
                    'affected_events': [e for e in s3_events if e.get('raw_event', {}).get('eventName') == operation][:5],
                    'metadata': {
                        'operation': operation,
                        'count': count
                    }
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_unusual_privilege_escalation(self, grouped_events: Dict) -> List[Dict]:
        """Detect unusual privilege escalation patterns"""
        anomalies = []
        
        # Look for IAM events that might indicate privilege escalation
        iam_events = grouped_events.get('by_source', {}).get('AWS_IAM', [])
        
        # Check for privilege escalation indicators
        escalation_indicators = [
            'AttachUserPolicy',
            'AttachRolePolicy',
            'PutUserPolicy',
            'PutRolePolicy',
            'CreateRole',
            'AssumeRole'
        ]
        
        for event in iam_events:
            event_name = event.get('raw_event', {}).get('eventName', '')
            if event_name in escalation_indicators:
                anomaly = {
                    'type': 'unusual_privilege_escalation',
                    'title': f'Potential Privilege Escalation: {event_name}',
                    'description': f'Privilege escalation indicator detected: {event_name}',
                    'severity': 'HIGH',
                    'severity_score': 8.0,
                    'timestamp': datetime.utcnow().isoformat(),
                    'affected_events': [event],
                    'metadata': {
                        'event_name': event_name,
                        'user': event.get('raw_event', {}).get('userIdentity', {}).get('userName', 'UNKNOWN')
                    }
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _get_event_time(self, event: Dict) -> datetime:
        """Extract timestamp from event"""
        timestamp = event.get('timestamp', '')
        if timestamp:
            try:
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                pass
        return datetime.utcnow()
    
    def _deduplicate_anomalies(self, anomalies: List[Dict]) -> List[Dict]:
        """Remove duplicate anomalies"""
        seen = set()
        unique_anomalies = []
        
        for anomaly in anomalies:
            # Create a key for deduplication
            key = (
                anomaly.get('type', ''),
                anomaly.get('title', ''),
                anomaly.get('timestamp', '')[:10]  # Use date only
            )
            
            if key not in seen:
                seen.add(key)
                unique_anomalies.append(anomaly)
        
        return unique_anomalies
    
    def save_baseline(self, filepath: str):
        """Save baseline data to file"""
        try:
            # Convert sets to lists for JSON serialization
            baseline_copy = {}
            for key, value in self.baseline_data.items():
                if isinstance(value, dict):
                    baseline_copy[key] = {}
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, set):
                            baseline_copy[key][sub_key] = list(sub_value)
                        else:
                            baseline_copy[key][sub_key] = sub_value
                else:
                    baseline_copy[key] = value
            
            with open(filepath, 'w') as f:
                json.dump(baseline_copy, f, indent=2, default=str)
            logger.info(f"Baseline data saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save baseline data: {e}")
    
    def load_baseline(self, filepath: str):
        """Load baseline data from file"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    data = json.load(f)
                
                # Convert lists back to sets where needed
                self.baseline_data = {}
                for key, value in data.items():
                    if isinstance(value, dict):
                        self.baseline_data[key] = {}
                        for sub_key, sub_value in value.items():
                            if sub_key in ['resources_accessed', 'regions_used', 'ip_addresses']:
                                self.baseline_data[key][sub_key] = set(sub_value)
                            else:
                                self.baseline_data[key][sub_key] = sub_value
                    else:
                        self.baseline_data[key] = value
                
                logger.info(f"Baseline data loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load baseline data: {e}")


def main():
    """Test the anomaly detector"""
    # Sample events for testing
    sample_events = [
        {
            'timestamp': datetime.utcnow().isoformat(),
            'source': 'AWS_IAM',
            'event_type': 'API_CALL',
            'resource_id': 'user123',
            'region': 'us-east-1',
            'raw_event': {
                'eventName': 'AttachUserPolicy',
                'userIdentity': {'userName': 'testuser'},
                'sourceIPAddress': '192.168.1.1'
            }
        }
    ]
    
    detector = AnomalyDetector()
    anomalies = detector.analyze_events(sample_events)
    
    print(f"Detected {len(anomalies)} anomalies:")
    for anomaly in anomalies:
        print(f"- {anomaly['title']}: {anomaly['description']}")


if __name__ == "__main__":
    main()
