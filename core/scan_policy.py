import uuid
from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from core.scanner_manifest import ActivityLevel

class TimeWindows(BaseModel):
    allowed_hours: List[int] = Field(default_factory=lambda: list(range(24))) # 0-23
    allowed_days: List[int] = Field(default_factory=lambda: list(range(7)))  # 0-6 (Mon-Sun)

class RateLimits(BaseModel):
    requests_per_second: int = 10
    concurrent_scanners: int = 5

class ScanPolicySchema(BaseModel):
    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_id: str
    name: str
    scanner_allowlist: List[str] = Field(default_factory=list)
    scanner_denylist: List[str] = Field(default_factory=list)
    activity_level_limit: ActivityLevel = Field(default=ActivityLevel.ACTIVE)
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    time_windows: TimeWindows = Field(default_factory=TimeWindows)
    max_duration: int = 3600 # seconds
    auto_approve_scope: bool = False

class ScanPolicy:
    def __init__(self, data: dict):
        model = ScanPolicySchema(**data)
        self.data = model.model_dump()

    def validate(self, data: dict):
        """Validate against policy schema."""
        ScanPolicySchema(**data)
        
    def to_dict(self) -> dict:
        return self.data.copy()
        
    def is_scanner_allowed(self, scanner_name: str) -> bool:
        """Check if a specific scanner is allowed by this policy."""
        if self.data["scanner_allowlist"] and scanner_name not in self.data["scanner_allowlist"]:
            return False
        if scanner_name in self.data["scanner_denylist"]:
            return False
        return True
