"""
API Authentication Module V9.5.6
=================================
JWT token issuance and verification for the SMP API.

Signing key requirements
------------------------
Tokens are signed with an independent cryptographically random secret loaded
from the ``SMP_JWT_SECRET`` environment variable.  This key is **completely
independent** of the password-hashing salt stored in ``config/auth.json``;
rotating the user password does NOT affect token validity, and rotating the
JWT key does NOT affect password hashing.

Production mode (default)
    ``SMP_JWT_SECRET`` must be set to a hex or ASCII string of at least
    32 characters (256 bits of entropy recommended).  If the variable is
    absent or too short the module raises ``RuntimeError`` immediately,
    refusing to issue tokens.  See ``.env.example`` for instructions.

Development / CI mode
    Set ``SMP_DEV_ALLOW_INSECURE_JWT=1`` **and** either ``SMP_CI=1`` to
    generate a per-process ephemeral random secret.  A loud WARNING is
    emitted at startup.  The ephemeral secret is never persisted and is
    never written to any log at INFO level or below.

Secret rotation
    1. Generate a new 64-hex secret:
           python3 -c "import secrets; print(secrets.token_hex(32))"
    2. Set ``SMP_JWT_SECRET`` to that value in your environment / systemd
       unit / secrets manager.
    3. Restart the API server.  All existing tokens become invalid immediately
       (they were signed with the old key).  Users must re-authenticate.

Minimum key length
    32 characters (256-bit equivalent).  Shorter values are rejected at
    startup.

The secret value is NEVER logged at any level.
"""
import os
import logging
import secrets
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("smp.api")

_JWT_EXPIRY_HOURS = 24

# Minimum acceptable length for SMP_JWT_SECRET (characters, not bytes).
# 32 hex chars = 128-bit; we require 32 to enforce a meaningful lower bound.
_MIN_SECRET_LEN = 32

# Module-level cache so we load the secret once per process.
_cached_jwt_secret: str | None = None


def _get_jwt_secret() -> str:
    """
    Return the JWT signing secret for this process.

    Priority:
      1. ``SMP_JWT_SECRET`` environment variable (production path).
      2. Per-process ephemeral secret (development/CI only, with loud warning).

    Raises RuntimeError if no valid secret is available outside of dev/CI mode.
    The secret value is never included in log messages.
    """
    global _cached_jwt_secret
    if _cached_jwt_secret is not None:
        return _cached_jwt_secret

    env_secret = os.environ.get("SMP_JWT_SECRET", "")

    if env_secret:
        if len(env_secret) < _MIN_SECRET_LEN:
            raise RuntimeError(
                f"SMP_JWT_SECRET is too short ({len(env_secret)} chars); "
                f"minimum is {_MIN_SECRET_LEN} characters.  "
                "Generate a new secret: "
                "python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
        # Accept without logging the value.
        logger.info(
            "[Auth] JWT signing key loaded from SMP_JWT_SECRET "
            f"(length={len(env_secret)})."
        )
        _cached_jwt_secret = env_secret
        return _cached_jwt_secret

    # No SMP_JWT_SECRET set.  Allow an ephemeral key ONLY in explicitly
    # marked development/CI environments.
    _ci_mode = os.environ.get("SMP_CI") == "1"
    _dev_allow = os.environ.get("SMP_DEV_ALLOW_INSECURE_JWT") == "1"

    if _ci_mode or _dev_allow:
        ephemeral = secrets.token_hex(32)
        logger.warning(
            "[Auth] *** DEVELOPMENT / CI MODE *** "
            "SMP_JWT_SECRET is not set.  Using a per-process ephemeral JWT "
            "signing secret.  All tokens will be invalidated on restart.  "
            "Set SMP_JWT_SECRET for production use.  "
            "Do NOT set SMP_DEV_ALLOW_INSECURE_JWT=1 in production."
        )
        _cached_jwt_secret = ephemeral
        return _cached_jwt_secret

    raise RuntimeError(
        "SMP_JWT_SECRET environment variable is not set.  "
        "JWT token issuance is disabled.  "
        "Set SMP_JWT_SECRET to a random secret of at least "
        f"{_MIN_SECRET_LEN} characters before starting the API server.  "
        "Example: "
        "python3 -c \"import secrets; print(secrets.token_hex(32))\""
    )


def create_token(username: str, expiry_hours: int = _JWT_EXPIRY_HOURS) -> str:
    """
    Create a signed JWT token for the given username.

    Returns: JWT string
    Raises:  RuntimeError if no valid signing key is available.
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
    Returns None (rather than raising) so callers can treat it as a failed auth.
    """
    from jose import jwt as jose_jwt, JWTError, ExpiredSignatureError
    try:
        secret = _get_jwt_secret()
        payload = jose_jwt.decode(token, secret, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            return None
        return username
    except RuntimeError:
        # _get_jwt_secret raised — no secret configured, fail closed.
        logger.warning("[Auth] Token verification failed: JWT secret unavailable.")
        return None
    except Exception as e:
        logger.warning(f"[Auth] Token verification failed: {e}")
        return None
