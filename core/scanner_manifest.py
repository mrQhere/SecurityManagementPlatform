from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class ScannerCategory(str, Enum):
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    NETWORK = "network"
    WEB = "web"
    CODE = "code"
    CLOUD = "cloud"

class InputType(str, Enum):
    HOST = "host"
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    FILE = "file"
    CODE = "code"

class OutputFormat(str, Enum):
    JSON = "json"
    XML = "xml"
    JSONL = "jsonl"
    TXT = "txt"
    CSV = "csv"

_ACTIVITY_ORDER = {
    "PASSIVE": 1,
    "LOW_IMPACT_ACTIVE": 2,
    "ACTIVE": 3,
    "INTRUSIVE": 4,
    "DESTRUCTIVE": 5,
}

class ActivityLevel(str, Enum):
    PASSIVE = "PASSIVE"
    LOW_IMPACT_ACTIVE = "LOW_IMPACT_ACTIVE"
    ACTIVE = "ACTIVE"
    INTRUSIVE = "INTRUSIVE"
    DESTRUCTIVE = "DESTRUCTIVE"

    def _rank(self, other):
        val = other.value if isinstance(other, Enum) else str(other)
        return _ACTIVITY_ORDER.get(self.value, 0), _ACTIVITY_ORDER.get(val, 0)

    def __ge__(self, other):
        s, o = self._rank(other)
        return s >= o

    def __gt__(self, other):
        s, o = self._rank(other)
        return s > o

    def __le__(self, other):
        s, o = self._rank(other)
        return s <= o

    def __lt__(self, other):
        s, o = self._rank(other)
        return s < o

class ScannerManifest(BaseModel):
    id: str
    name: str
    adapter_version: str
    tool_version: str
    category: ScannerCategory
    input_type: InputType
    output_format: OutputFormat
    activity_level: ActivityLevel
    requires_network: bool
    external_services: List[str] = Field(default_factory=list)
    requires_credentials: bool
    requires_root: bool
    supports_offline: bool
    default_timeout: int
    max_timeout: int
    max_concurrency: int
    max_requests: int
    max_output_bytes: int
    supported_profiles: List[str] = Field(default_factory=list)
    parser: str
    test_fixture: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
