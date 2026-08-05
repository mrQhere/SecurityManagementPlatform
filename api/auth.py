"""
API Authentication Module V9.0.1
================================
JWT token issuance and verification for the SMP API.

Tokens are signed with a secret derived from the SMP master password salt,
so tokens are invalidated when the password changes.

Token format: HS256 JWT with 24h expiry (configurable).
"""
import os
import json
import logging
import hashlib
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("smp.api")

_JWT_EXPIRY_HOURS = 24


def _get_jwt_secret() -> str:
    """
    Derive a stable JWT signing secret from the auth file salt.
    Falls back to a random env var or a startup-generated secret.
    """
    # Primary: derive from auth.json salt (invalidated on password change)
    try:
        from tools.config_manager import BASE_DIR
        auth_path = os.path.join(BASE_DIR, "config", "auth.json")
        if os.path.exists(auth_path):
            with open(auth_path) as f:
                data = json.load(f)
            salt = data.get("salt", "")
            return hashlib.sha256(f"smp-api-jwt-{salt}".encode()).hexdigest()
    except Exception:
        pass

    # Fallback: env var
    env_secret = os.environ.get("SMP_JWT_SECRET")
    if env_secret:
        return env_secret

    # Last resort: fixed string (only for development)
    logger.warning("[Auth] Using fallback JWT secret — set SMP_JWT_SECRET env var in production.")
    return "smp-v6-fallback-jwt-secret-change-me"


def create_token(username: str, expiry_hours: int = _JWT_EXPIRY_HOURS) -> str:
    """
    Create a signed JWT token for the given username.
    
    Returns: JWT string
    """
    try:
        from jose import jwt as jose_jwt
        now    = datetime.now(timezone.utc)
        expire = now + timedelta(hours=expiry_hours)
        payload = {
            "sub": username,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
            "iss": "smp-v6",
        }
        secret = _get_jwt_secret()
        token = jose_jwt.encode(payload, secret, algorithm="HS256")
        logger.info(f"[Auth] Token created for '{username}', expires {expire.isoformat()}")
        return token
    except ImportError:
        # Fallback: simple base64 token (no jose library)
        logger.warning("[Auth] python-jose not installed. Using simple token fallback.")
        import base64
        payload = json.dumps({"sub": username, "exp": (datetime.now() + timedelta(hours=expiry_hours)).isoformat()})
        return base64.urlsafe_b64encode(payload.encode()).decode()


def verify_token(token: str) -> str:
    """
    Verify a JWT token.
    
    Returns: username string if valid, None if invalid/expired.
    """
    try:
        from jose import jwt as jose_jwt, JWTError, ExpiredSignatureError
        secret = _get_jwt_secret()
        payload = jose_jwt.decode(token, secret, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            return None
        return username
    except ImportError:
        # Fallback: decode simple base64 token
        try:
            import base64
            payload = json.loads(base64.urlsafe_b64decode(token.encode() + b"=="))
            exp = datetime.fromisoformat(payload["exp"])
            if datetime.now() > exp:
                return None
            return payload.get("sub")
        except Exception:
            return None
    except Exception as e:
        logger.warning(f"[Auth] Token verification failed: {e}")
        return None
