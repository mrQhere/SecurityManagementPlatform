from typing import Dict
from datetime import datetime

class ProvenanceRecorder:
    def __init__(self):
        self.records: Dict[str, Dict] = {}
        
    def record_execution(self, execution_data: Dict) -> str:
        """Record execution provenance."""
        scan_id = execution_data.get("scan_id")
        scanner_name = execution_data.get("scanner_name")
        record_id = f"{scan_id}_{scanner_name}"
        
        self.records[record_id] = {
            "scanner_id": execution_data.get("scanner_id"),
            "scanner_name": scanner_name,
            "scanner_version": execution_data.get("scanner_version"),
            "adapter_version": execution_data.get("adapter_version"),
            "command_identifier": execution_data.get("command_identifier"),
            "configuration_hash": execution_data.get("configuration_hash"),
            "target": execution_data.get("target"),
            "scope": execution_data.get("scope"),
            "start_time": execution_data.get("start_time"),
            "end_time": execution_data.get("end_time"),
            "exit_code": execution_data.get("exit_code"),
            "status": execution_data.get("status"),
            "raw_output_hash": execution_data.get("raw_output_hash"),
            "parser_version": execution_data.get("parser_version"),
            "recorded_at": datetime.utcnow().isoformat()
        }
        return record_id
    
    def get_provenance(self, scan_id: str, scanner_name: str) -> Dict:
        """Retrieve execution provenance."""
        record_id = f"{scan_id}_{scanner_name}"
        return self.records.get(record_id, {})
