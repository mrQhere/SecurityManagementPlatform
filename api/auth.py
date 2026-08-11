"""
API Authentication Module V9.4.2
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
    except Exception as e:
        from tools.errors import SMPUnclassifiedError
        import traceback, logging
        logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
        raise SMPUnclassifiedError(str(e))
        pass

    # Fallback: env var
    env_secret = os.environ.get("SMP_JWT_SECRET")
    if env_secret:
        return env_secret

    # Last resort: generate and persist a new secret
    import secrets
    from tools.config_manager import BASE_DIR
    auth_path = os.path.join(BASE_DIR, "config", "auth.json")
    
    try:
        data = {}
        if os.path.exists(auth_path):
            with open(auth_path) as f:
                data = json.load(f)
        
        # If there's an already generated secret in the file, use it
        if "jwt_secret" in data:
            return data["jwt_secret"]
            
        new_secret = secrets.token_hex(32)
        data["jwt_secret"] = new_secret
        os.makedirs(os.path.dirname(auth_path), exist_ok=True)
        with open(auth_path, "w") as f:
            json.dump(data, f, indent=4)
        logger.info("[Auth] Generated and persisted new JWT secret.")
        return new_secret
    except Exception as e:
        logger.error(f"[Auth] Failed to generate/persist JWT secret: {e}")
        raise RuntimeError("Failed to obtain or generate JWT secret. Failing closed.")


def create_token(username: str, expiry_hours: int = _JWT_EXPIRY_HOURS) -> str:
    """
    Create a signed JWT token for the given username.
    
    Returns: JWT string
    """
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


def verify_token(token: str) -> str:
    """
    Verify a JWT token.
    
    Returns: username string if valid, None if invalid/expired.
    """
    from jose import jwt as jose_jwt, JWTError, ExpiredSignatureError
    try:
        secret = _get_jwt_secret()
        payload = jose_jwt.decode(token, secret, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            return None
        return username
    except Exception as e:
        logger.warning(f"[Auth] Token verification failed: {e}")
        return None
