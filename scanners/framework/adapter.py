from abc import ABC, abstractmethod
from typing import Dict, List, Tuple
from core.scanner_manifest import ScannerManifest

class ScannerAdapter(ABC):
    """Base class for all scanner adapters."""
    
    @abstractmethod
    def get_manifest(self) -> ScannerManifest:
        """Return scanner manifest."""
        pass
    
    @abstractmethod
    def verify_binary(self) -> Tuple[bool, str]:
        """Verify binary availability and version."""
        pass
    
    @abstractmethod
    def prepare_execution(self, target: str, config: Dict) -> Dict:
        """Prepare execution parameters."""
        pass
    
    @abstractmethod
    def execute(self, target: str, config: Dict) -> Dict:
        """Execute scanner and return raw result."""
        pass
    
    @abstractmethod
    def parse_output(self, raw_output: str) -> List[Dict]:
        """Parse raw output into observations."""
        pass
    
    @abstractmethod
    def cleanup(self, workspace: str):
        """Clean up temporary workspace."""
        pass


class AdapterRegistry:
    def __init__(self):
        self.adapters: Dict[str, ScannerAdapter] = {}
    
    def register(self, adapter: ScannerAdapter):
        """Register a scanner adapter."""
        manifest = adapter.get_manifest()
        self.adapters[manifest.id] = adapter
    
    def get_adapter(self, scanner_id: str) -> ScannerAdapter:
        """Get adapter by scanner ID."""
        return self.adapters.get(scanner_id)
    
    def list_adapters(self) -> List[Dict]:
        """List all registered adapters."""
        return [adapter.get_manifest().model_dump() for adapter in self.adapters.values()]
