import uuid
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List, Set, Union
from pydantic import BaseModel, Field

class FindingSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"

class FindingBase(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: Optional[str] = None
    engagement_id: str
    title: str
    vulnerability_class: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: List[str] = Field(default_factory=list)
    asset_id: Optional[str] = None
    service_id: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    severity: FindingSeverity
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list)
    affected_observations: List[str] = Field(default_factory=list)
    scanner_sources: List[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    validation: Optional[str] = None
    status: FindingStatus = Field(default=FindingStatus.OPEN)
    provenance: Optional[Dict[str, Any]] = None
    first_observed_at: datetime = Field(default_factory=datetime.utcnow)
    last_observed_at: datetime = Field(default_factory=datetime.utcnow)
    occurrence_count: int = 1

class Finding:
    def __init__(self, data: dict):
        # Handle string severity if passed directly
        if isinstance(data.get("severity"), str):
            # Already matches enum format mostly, but Pydantic handles coercion
            pass
            
        # Ensure cve_id is list if passed as string (from old tests)
        if isinstance(data.get("cve_id"), str):
            data["cve_id"] = [data["cve_id"]]
            
        model = FindingBase(**data)
        self.data = model.model_dump()
        self.data["first_observed_at"] = self.data["first_observed_at"].isoformat()
        self.data["last_observed_at"] = self.data["last_observed_at"].isoformat()

    def validate(self, data: dict):
        """Validate against finding schema."""
        FindingBase(**data)

    def to_dict(self) -> dict:
        return self.data.copy()
