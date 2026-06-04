"""
CloudHawk credential store.

Priority order for credentials:
  1. config/auth.json (written by change-password; survives restarts)
  2. CLOUDHAWK_USER / CLOUDHAWK_PASSWORD env vars
  3. Built-in defaults: root / toor

Passwords are stored as PBKDF2-SHA256 hashes with a per-entry salt.
Reset tokens are kept in-process memory (16-char hex, 15-min TTL).
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUTH_FILE = os.path.join(_BASE_DIR, "config", "auth.json")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
_DEFAULT_USER = os.environ.get("CLOUDHAWK_USER", "root")
_DEFAULT_PASS = os.environ.get("CLOUDHAWK_PASSWORD", "toor")

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
_ITERATIONS = 260_000  # OWASP 2023 recommendation for PBKDF2-SHA256


def _hash(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Return (hex_hash, hex_salt). Generates a new salt if not provided."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), _ITERATIONS
    )
    return dk.hex(), salt


def _verify(password: str, stored_hash: str, salt: str) -> bool:
    """Constant-time comparison to avoid timing attacks."""
    computed, _ = _hash(password, salt)
    return hmac.compare_digest(computed, stored_hash)


# ---------------------------------------------------------------------------
# Persistent store
# ---------------------------------------------------------------------------

def _load() -> dict:
    """Load auth.json; return {} if missing or corrupt."""
    try:
        with open(AUTH_FILE) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    with open(AUTH_FILE, "w") as fh:
        json.dump(data, fh, indent=2)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_username() -> str:
    """Return the stored username (or env-var / default fallback)."""
    data = _load()
    return data.get("username") or _DEFAULT_USER


def check_password(username: str, password: str) -> bool:
    """Return True if username+password are correct."""
    data = _load()
    if data.get("username"):
        if username != data["username"]:
            return False
        return _verify(password, data["hash"], data["salt"])
    # Fall back to env-var / defaults
    return username == _DEFAULT_USER and password == _DEFAULT_PASS


def change_password(new_username: str, new_password: str) -> None:
    """Hash and persist new credentials."""
    hashed, salt = _hash(new_password)
    _save({"username": new_username, "hash": hashed, "salt": salt})
    logger.info("Credentials updated for user '%s'", new_username)


# ---------------------------------------------------------------------------
# Reset tokens (in-process; cleared on restart)
# ---------------------------------------------------------------------------
_TOKEN_TTL = 900  # 15 minutes
_reset_tokens: dict = {}  # token → expiry_ts


def generate_reset_token() -> str:
    """Return a fresh 32-char hex token valid for 15 minutes."""
    # Expire old tokens first
    now = time.time()
    expired = [t for t, exp in _reset_tokens.items() if exp < now]
    for t in expired:
        del _reset_tokens[t]

    token = secrets.token_hex(16)
    _reset_tokens[token] = now + _TOKEN_TTL
    return token


def consume_reset_token(token: str) -> bool:
    """Return True and invalidate the token if it's valid and unexpired."""
    exp = _reset_tokens.pop(token, None)
    if exp is None:
        return False
    if time.time() > exp:
        return False
    return True
