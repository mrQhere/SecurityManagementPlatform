import logging
from typing import Dict, List, Any
import time

logger = logging.getLogger("smp")

class ScanScheduler:
    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self.active_scans: Dict[str, Dict] = {}
        self.scan_queue: List[Dict] = []
        
    def schedule_scan(self, scan_id: str, execution_plan: Dict) -> str:
        """Schedule a scan for execution."""
        scan_job = {
            "scan_id": scan_id,
            "execution_graph": execution_plan.get("execution_graph", {}),
            "status": "QUEUED",
            "completed_phases": set(),
            "in_progress_phases": set(),
            "failed_phases": set()
        }
        self.scan_queue.append(scan_job)
        return scan_id

    def pause_scan(self, scan_id: str):
        """Pause an active scan."""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]["status"] = "PAUSED"
            logger.info(f"Scan {scan_id} paused.")

    def resume_scan(self, scan_id: str):
        """Resume a paused scan."""
        if scan_id in self.active_scans:
            if self.active_scans[scan_id]["status"] == "PAUSED":
                self.active_scans[scan_id]["status"] = "RUNNING"
                logger.info(f"Scan {scan_id} resumed.")

    def cancel_scan(self, scan_id: str):
        """Cancel a scan execution."""
        # Check queue
        for i, job in enumerate(self.scan_queue):
            if job["scan_id"] == scan_id:
                self.scan_queue.pop(i)
                return
                
        # Check active
        if scan_id in self.active_scans:
            self.active_scans[scan_id]["status"] = "CANCELLED"
            logger.info(f"Scan {scan_id} cancelled.")

    def get_scan_status(self, scan_id: str) -> Dict:
        """Get current scan status."""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]
            
        for job in self.scan_queue:
            if job["scan_id"] == scan_id:
                return job
                
        return {"status": "NOT_FOUND"}

    def tick(self):
        """Advance the scheduling state machine (DAG execution via Kahn's variation)."""
        # Move queued items to active if capacity permits
        while len(self.active_scans) < self.max_concurrent and self.scan_queue:
            job = self.scan_queue.pop(0)
            job["status"] = "RUNNING"
            self.active_scans[job["scan_id"]] = job
            
        # Process active scans
        for scan_id, job in list(self.active_scans.items()):
            if job["status"] != "RUNNING":
                continue
                
            graph = job["execution_graph"]
            
            # Find eligible phases (dependencies met and not already started)
            eligible_phases = []
            for phase, details in graph.items():
                if phase in job["completed_phases"] or phase in job["in_progress_phases"] or phase in job["failed_phases"]:
                    continue
                    
                deps = details.get("depends_on", [])
                if all(d in job["completed_phases"] for d in deps):
                    eligible_phases.append(phase)
            
            # Start eligible phases
            for phase in eligible_phases:
                job["in_progress_phases"].add(phase)
                self._dispatch_phase(scan_id, phase, graph[phase])
                
            # Check for overall completion
            all_phases = set(graph.keys())
            done_phases = job["completed_phases"].union(job["failed_phases"])
            if all_phases == done_phases:
                job["status"] = "COMPLETED" if not job["failed_phases"] else "FAILED"
                # Keep in memory briefly or notify completion

    def _dispatch_phase(self, scan_id: str, phase: str, details: Dict):
        """Dispatch scanners for a specific phase (Stubbed for actual execution)."""
        logger.info(f"Dispatching scan {scan_id} phase {phase}: {details['scanners']}")
        # In a real implementation, this would spawn worker threads/processes
        # and eventually update completed_phases/failed_phases via callbacks.
