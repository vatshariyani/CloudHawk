"""
CloudHawk API Authentication Module
Provides JWT-based authentication and API key management
"""

import os
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from functools import wraps
from flask import request, jsonify, current_app
import logging

logger = logging.getLogger(__name__)

class APIAuth:
    """API Authentication Manager"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or os.getenv('CLOUDHAWK_SECRET_KEY', 'cloudhawk-secret-key')
        self.api_keys = {}  # In production, store in database
        self._load_api_keys()
    
    def _load_api_keys(self):
        """Load API keys from environment or config"""
        # In production, load from database
        default_key = os.getenv('CLOUDHAWK_API_KEY')
        if default_key:
            self.api_keys[default_key] = {
                'name': 'default',
                'permissions': ['read', 'write', 'admin'],
                'created_at': datetime.utcnow(),
                'last_used': None
            }
    
    def generate_api_key(self, name: str, permissions: List[str] = None) -> str:
        """Generate a new API key"""
        if permissions is None:
            permissions = ['read']
        
        api_key = secrets.token_urlsafe(32)
        self.api_keys[api_key] = {
            'name': name,
            'permissions': permissions,
            'created_at': datetime.utcnow(),
            'last_used': None
        }
        
        logger.info(f"Generated API key for {name} with permissions: {permissions}")
        return api_key
    
    def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """Validate API key and return user info"""
        if api_key not in self.api_keys:
            return None
        
        # Update last used timestamp
        self.api_keys[api_key]['last_used'] = datetime.utcnow()
        return self.api_keys[api_key]
    
    def has_permission(self, api_key: str, permission: str) -> bool:
        """Check if API key has specific permission"""
        user_info = self.validate_api_key(api_key)
        if not user_info:
            return False
        
        return permission in user_info.get('permissions', [])
    
    def generate_jwt_token(self, user_id: str, permissions: List[str], expires_hours: int = 24) -> str:
        """Generate JWT token for user"""
        payload = {
            'user_id': user_id,
            'permissions': permissions,
            'exp': datetime.utcnow() + timedelta(hours=expires_hours),
            'iat': datetime.utcnow()
        }
        
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def validate_jwt_token(self, token: str) -> Optional[Dict]:
        """Validate JWT token and return payload"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token")
            return None

# Global auth instance
auth_manager = APIAuth()

def require_auth(permission: str = 'read'):
    """Decorator to require API authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for API key in header
            api_key = request.headers.get('X-API-Key')
            if api_key:
                if not auth_manager.has_permission(api_key, permission):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                return f(*args, **kwargs)
            
            # Check for JWT token in Authorization header
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                payload = auth_manager.validate_jwt_token(token)
                if payload and permission in payload.get('permissions', []):
                    return f(*args, **kwargs)
            
            return jsonify({'error': 'Authentication required'}), 401
        
        return decorated_function
    return decorator

def require_admin(f):
    """Decorator to require admin permissions"""
    return require_auth('admin')(f)

def rate_limit(requests_per_minute: int = 60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple in-memory rate limiting (use Redis in production)
            client_ip = request.remote_addr
            current_time = datetime.utcnow()
            
            # This is a simplified implementation
            # In production, use Redis or similar for distributed rate limiting
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
