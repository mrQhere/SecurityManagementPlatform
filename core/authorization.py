import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class AuthStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"

class AuthorizationSchema(BaseModel):
    auth_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_id: str
    target: str
    authorized_by: str
    authorized_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    scope: str
    limitations: List[str] = Field(default_factory=list)
    status: AuthStatus = Field(default=AuthStatus.ACTIVE)

class AuthorizationTracker:
    def __init__(self):
        self.authorizations = {}

    def track_authorization(self, data: dict) -> str:
        model = AuthorizationSchema(**data)
        serialized = model.model_dump()
        serialized["authorized_at"] = serialized["authorized_at"].isoformat()
        if serialized["expires_at"]:
            serialized["expires_at"] = serialized["expires_at"].isoformat()
            
        auth_id = serialized["auth_id"]
        self.authorizations[auth_id] = serialized
        return auth_id

    def get_authorization(self, auth_id: str) -> Optional[dict]:
        return self.authorizations.get(auth_id)

    def revoke_authorization(self, auth_id: str):
        if auth_id in self.authorizations:
            self.authorizations[auth_id]["status"] = AuthStatus.REVOKED.value

    def is_valid(self, auth_id: str) -> bool:
        auth = self.authorizations.get(auth_id)
        if not auth:
            return False
            
        if auth["status"] != AuthStatus.ACTIVE.value:
            return False
            
        if auth["expires_at"]:
            expires_at = datetime.fromisoformat(auth["expires_at"])
            if datetime.utcnow() > expires_at:
                auth["status"] = AuthStatus.EXPIRED.value
                return False
                
        return True
