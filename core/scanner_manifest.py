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

class ActivityLevel(str, Enum):
    PASSIVE = "PASSIVE"
    LOW_IMPACT_ACTIVE = "LOW_IMPACT_ACTIVE"
    ACTIVE = "ACTIVE"
    INTRUSIVE = "INTRUSIVE"
    DESTRUCTIVE = "DESTRUCTIVE"

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
