import uuid
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class ObservationType(str, Enum):
    ASSET = "asset"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    HTTP = "http"
    DNS = "dns"
    CONFIGURATION = "configuration"
    VULNERABILITY_CANDIDATE = "vulnerability_candidate"
    VULNERABILITY = "vulnerability"
    SECRET = "secret"
    CREDENTIAL = "credential"
    CLOUD_ASSET = "cloud_asset"
    SOURCE_CODE = "source_code"
    DEPENDENCY = "dependency"
    CPE = "cpe"

class ObservationBase(BaseModel):
    observation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    asset_id: Optional[str] = None
    service_id: Optional[str] = None
    scanner_id: str
    scanner_version: Optional[str] = None
    observation_type: ObservationType
    title: str
    raw_value: Optional[Dict[str, Any]] = None
    normalized_value: Optional[Dict[str, Any]] = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    observed_at: datetime = Field(default_factory=datetime.utcnow)
    evidence_ids: List[str] = Field(default_factory=list)
    raw_output_hash: Optional[str] = None
    parser_version: Optional[str] = None

class Observation:
    def __init__(self, data: dict):
        model = ObservationBase(**data)
        self.data = model.model_dump()
        self.data["observed_at"] = self.data["observed_at"].isoformat()
        self.immutable = True

    def validate(self, data: dict):
        ObservationBase(**data)

    def to_dict(self) -> dict:
        return self.data.copy()

    def add_evidence(self, evidence_id: str):
        if not self.immutable:
            if evidence_id not in self.data['evidence_ids']:
                self.data['evidence_ids'].append(evidence_id)
        else:
            raise Exception("Cannot modify immutable observation")

class AssetObservation(Observation):
    def __init__(self, data: dict):
        data["observation_type"] = ObservationType.ASSET
        super().__init__(data)

class PortObservation(Observation):
    def __init__(self, data: dict):
        data["observation_type"] = ObservationType.PORT
        super().__init__(data)

class CVEObservation(Observation):
    def __init__(self, data: dict):
        data["observation_type"] = ObservationType.VULNERABILITY_CANDIDATE
        super().__init__(data)

class ObservationFactory:
    @staticmethod
    def create(data: dict) -> Observation:
        obs_type = data.get("observation_type")
        if obs_type == ObservationType.ASSET:
            return AssetObservation(data)
        elif obs_type == ObservationType.PORT:
            return PortObservation(data)
        elif obs_type == ObservationType.VULNERABILITY_CANDIDATE:
            return CVEObservation(data)
        else:
            return Observation(data)
