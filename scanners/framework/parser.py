from abc import ABC, abstractmethod
from typing import Dict, List
from core.observation import Observation

class ObservationParser(ABC):
    @abstractmethod
    def parse(self, raw_output: str, scanner_context: Dict) -> List[Dict]:
        """Parse raw output into observations."""
        pass
    
    def validate_observation(self, observation: Dict) -> bool:
        """Validate observation against schema."""
        try:
            obs = Observation(observation)
            return True
        except Exception:
            return False
    
    @abstractmethod
    def normalize_observation(self, observation: Dict) -> Dict:
        """Normalize observation to standard format."""
        pass


class ParserRegistry:
    def __init__(self):
        self.parsers: Dict[str, ObservationParser] = {}
        
    def register_parser(self, scanner_id: str, parser: ObservationParser):
        """Register parser for scanner."""
        self.parsers[scanner_id] = parser
    
    def get_parser(self, scanner_id: str) -> ObservationParser:
        """Get parser for scanner."""
        return self.parsers.get(scanner_id)
