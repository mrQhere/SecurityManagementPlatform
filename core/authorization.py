"""
core/authorization.py — Authorization tracking and validity checking.

The public helper `is_authorization_currently_valid(auth)` is the single
source of truth for whether a raw authorization dict (as stored in the DB)
represents an authorization that may currently be used to create allow rules.
It is shared with `core/scope_engine.py` to avoid duplicated expiry logic.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class AuthStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


def is_authorization_currently_valid(auth: dict) -> bool:
    """
    Timezone-safe validity check for a raw authorization dict.

    Returns True only when ALL of the following hold:
      - ``status`` equals ``AuthStatus.ACTIVE``
      - ``expires_at`` is absent, None, or a datetime that has not yet passed
        (naive datetimes are treated as UTC)

    Returns False for any malformed, missing, or revoked/expired authorization.
    Raises no exceptions — parse failures are treated as invalid.

    This function is the **single canonical validity gate** shared between
    ``AuthorizationTracker.is_valid()`` and ``ScopeEngine._load_scope_rules()``.
    """
    if not auth or not isinstance(auth, dict):
        return False

    # Status check
    if auth.get("status") != AuthStatus.ACTIVE.value:
        return False

    # Expiry check — timezone-safe
    raw_expiry = auth.get("expires_at")
    if raw_expiry is not None:
        try:
            if isinstance(raw_expiry, str):
                expires_at = datetime.fromisoformat(raw_expiry)
            elif isinstance(raw_expiry, datetime):
                expires_at = raw_expiry
            else:
                # Unknown type — treat as invalid (fail closed)
                return False

            # Normalize to UTC
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            else:
                expires_at = expires_at.astimezone(timezone.utc)

            now_utc = datetime.now(timezone.utc)
            if now_utc >= expires_at:
                return False
        except (ValueError, OverflowError, OSError):
            # Malformed expiry string — fail closed
            return False

    return True


class AuthorizationSchema(BaseModel):
    auth_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_id: str
    target: str
    authorized_by: str
    authorized_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    scope: str
    limitations: List[str] = Field(default_factory=list)
    status: AuthStatus = Field(default=AuthStatus.ACTIVE)


class AuthorizationTracker:
    def track_authorization(self, data: dict) -> str:
        model = AuthorizationSchema(**data)
        serialized = model.model_dump()
        serialized["authorized_at"] = serialized["authorized_at"].isoformat()
        if serialized["expires_at"]:
            serialized["expires_at"] = serialized["expires_at"].isoformat()

        from tools.db_manager import add_authorization
        auth_id = serialized["auth_id"]
        add_authorization(serialized)
        return auth_id

    def get_authorization(self, auth_id: str) -> Optional[dict]:
        from tools.db_manager import get_authorization as db_get_auth
        return db_get_auth(auth_id)

    def revoke_authorization(self, auth_id: str):
        from tools.db_manager import update_authorization_status
        update_authorization_status(auth_id, AuthStatus.REVOKED.value)

    def is_valid(self, auth_id: str) -> bool:
        """
        Check whether a stored authorization is currently valid.

        Delegates expiry logic to ``is_authorization_currently_valid`` so
        the validation rules stay in one place.  If the authorization is
        expired, its DB record is updated to ``EXPIRED`` as a side effect.
        """
        from tools.db_manager import get_authorization as db_get_auth, update_authorization_status
        auth = db_get_auth(auth_id)
        if not auth:
            return False

        valid = is_authorization_currently_valid(auth)

        # Side-effect: mark expired authorizations in the database.
        if not valid and auth.get("status") == AuthStatus.ACTIVE.value:
            # Only update to EXPIRED if it's not already REVOKED.
            raw_expiry = auth.get("expires_at")
            if raw_expiry is not None:
                try:
                    update_authorization_status(auth_id, AuthStatus.EXPIRED.value)
                except Exception:
                    pass

        return valid
