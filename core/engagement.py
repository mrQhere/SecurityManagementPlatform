import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class EngagementStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"

class EngagementBase(BaseModel):
    engagement_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    start_date: datetime
    end_date: Optional[datetime] = None
    status: EngagementStatus = Field(default=EngagementStatus.ACTIVE)
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    team_members: List[str] = Field(default_factory=list)

class Engagement:
    def __init__(self, data: dict):
        model = EngagementBase(**data)
        self.data = model.model_dump()
        self.data["start_date"] = self.data["start_date"].isoformat()
        if self.data["end_date"]:
            self.data["end_date"] = self.data["end_date"].isoformat()
        self.data["created_at"] = self.data["created_at"].isoformat()

    def validate(self, data: dict):
        """Validate against engagement schema."""
        EngagementBase(**data)

    def to_dict(self) -> dict:
        return self.data.copy()
