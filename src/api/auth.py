"""
CloudHawk API Authentication

Supports two credential schemes on every protected endpoint:
  1. Bearer JWT — Authorization: Bearer <token>
                  Token is issued by POST /api/v1/auth/token
  2. API Key    — X-API-Key: <key>
                  Key is issued by POST /api/v1/auth/api-key (admin only)

The secret key used to sign JWTs is read from the CLOUDHAWK_SECRET_KEY
environment variable.  A fallback is provided so the server starts in
development without configuration, but production deployments MUST set this
variable to a strong random value.

Permissions
-----------
"read"   — GET endpoints
"write"  — POST/PUT/DELETE endpoints
"admin"  — key-generation endpoint; also implies read + write
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional

import jwt
from flask import jsonify, request

logger = logging.getLogger(__name__)

_JWT_ALGORITHM = "HS256"
_JWT_EXPIRY_HOURS = 24


class APIAuth:
    """Manages JWT tokens and in-process API key store."""

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = (
            secret_key
            or os.getenv("CLOUDHAWK_SECRET_KEY")
            or "cloudhawk-dev-secret-change-in-production"
        )
        if self.secret_key == "cloudhawk-dev-secret-change-in-production":
            logger.warning(
                "CLOUDHAWK_SECRET_KEY is not set — using insecure default. "
                "Set this env var before deploying to production."
            )
        self._api_keys: Dict[str, Dict] = {}
        self._load_env_key()

    def _load_env_key(self):
        """Bootstrap an API key from CLOUDHAWK_API_KEY env var if present."""
        key = os.getenv("CLOUDHAWK_API_KEY")
        if key:
            self._api_keys[key] = {
                "name": "env-default",
                "permissions": ["read", "write", "admin"],
                "created_at": datetime.utcnow().isoformat(),
                "last_used": None,
            }

    # ------------------------------------------------------------------
    # API keys
    # ------------------------------------------------------------------

    def generate_api_key(self, name: str, permissions: Optional[List[str]] = None) -> str:
        key = secrets.token_urlsafe(32)
        self._api_keys[key] = {
            "name": name,
            "permissions": permissions or ["read"],
            "created_at": datetime.utcnow().isoformat(),
            "last_used": None,
        }
        logger.info("Generated API key '%s' with permissions %s", name, permissions)
        return key

    def _lookup_api_key(self, key: str) -> Optional[Dict]:
        info = self._api_keys.get(key)
        if info:
            info["last_used"] = datetime.utcnow().isoformat()
        return info

    def _key_has_permission(self, key: str, permission: str) -> bool:
        info = self._lookup_api_key(key)
        if not info:
            return False
        perms = info.get("permissions", [])
        return permission in perms or "admin" in perms

    # ------------------------------------------------------------------
    # JWT tokens
    # ------------------------------------------------------------------

    def generate_jwt_token(
        self,
        user_id: str,
        permissions: Optional[List[str]] = None,
        expires_hours: int = _JWT_EXPIRY_HOURS,
    ) -> str:
        now = datetime.utcnow()
        payload = {
            "sub": user_id,
            "permissions": permissions or ["read"],
            "iat": now,
            "exp": now + timedelta(hours=expires_hours),
        }
        return jwt.encode(payload, self.secret_key, algorithm=_JWT_ALGORITHM)

    def validate_jwt_token(self, token: str) -> Optional[Dict]:
        try:
            return jwt.decode(token, self.secret_key, algorithms=[_JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            logger.debug("JWT token expired")
        except jwt.InvalidTokenError as exc:
            logger.debug("Invalid JWT token: %s", exc)
        return None

    def _jwt_has_permission(self, token: str, permission: str) -> bool:
        payload = self.validate_jwt_token(token)
        if not payload:
            return False
        perms = payload.get("permissions", [])
        return permission in perms or "admin" in perms


# Module-level singleton
auth_manager = APIAuth()


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def require_auth(permission: str = "read"):
    """Require a valid API key or Bearer JWT with the given permission."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # 1. API key
            api_key = request.headers.get("X-API-Key")
            if api_key:
                if auth_manager._key_has_permission(api_key, permission):
                    return f(*args, **kwargs)
                return jsonify({"error": "Insufficient permissions"}), 403

            # 2. Bearer JWT
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                if auth_manager._jwt_has_permission(token, permission):
                    return f(*args, **kwargs)
                # Token present but invalid/expired/insufficient
                return jsonify({"error": "Invalid or expired token"}), 401

            return jsonify({"error": "Authentication required"}), 401
        return wrapper
    return decorator


def require_admin(f):
    """Shortcut for require_auth('admin')."""
    return require_auth("admin")(f)


def rate_limit(requests_per_minute: int = 60):
    """Stub rate-limiter — plug in Redis / flask-limiter for production."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator
