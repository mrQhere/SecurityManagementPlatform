from abc import ABC, abstractmethod
from typing import Dict, List, Any
import datetime

class IntelAdapter(ABC):
    @abstractmethod
    def fetch(self, params: Dict) -> Dict:
        """Fetch intelligence from source."""
        pass
    
    @abstractmethod
    def parse(self, raw_data: Dict) -> List[Dict]:
        """Parse raw data into normalized format."""
        pass
    
    @abstractmethod
    def validate(self, parsed_data: List[Dict]) -> bool:
        """Validate parsed data integrity."""
        pass
    
    @abstractmethod
    def get_source_metadata(self) -> Dict:
        """Return source metadata (version, timestamp, etc.)."""
        pass


class NVDAdapter(IntelAdapter):
    def fetch(self, params: Dict) -> Dict:
        # Stub: Normally this would query the NVD API
        return {"cve_items": []}
    
    def parse(self, raw_data: Dict) -> List[Dict]:
        # Stub: Parse NVD JSON into internal format
        return []
    
    def validate(self, parsed_data: List[Dict]) -> bool:
        return True
    
    def get_source_metadata(self) -> Dict:
        return {
            "source": "NVD",
            "version": "2.0",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }


class KEVAdapter(IntelAdapter):
    def fetch(self, params: Dict) -> Dict:
        # Stub: Fetch CISA KEV catalog
        return {"catalog": []}
    
    def parse(self, raw_data: Dict) -> List[Dict]:
        return []
    
    def validate(self, parsed_data: List[Dict]) -> bool:
        return True
    
    def get_source_metadata(self) -> Dict:
        return {
            "source": "CISA_KEV",
            "version": "1.0",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }


class EPSSAdapter(IntelAdapter):
    def fetch(self, params: Dict) -> Dict:
        # Stub: Fetch EPSS scores
        return {"data": []}
    
    def parse(self, raw_data: Dict) -> List[Dict]:
        return []
    
    def validate(self, parsed_data: List[Dict]) -> bool:
        return True
    
    def get_source_metadata(self) -> Dict:
        return {
            "source": "EPSS",
            "version": "1.0",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }


class AdapterRegistry:
    def __init__(self):
        self.adapters: Dict[str, IntelAdapter] = {
            "nvd": NVDAdapter(),
            "kev": KEVAdapter(),
            "epss": EPSSAdapter()
        }
        
    def get_adapter(self, source_name: str) -> IntelAdapter:
        return self.adapters.get(source_name)
