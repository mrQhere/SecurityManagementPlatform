from typing import List, Dict, Any
from core.scope_engine import ScopeEngine
from core.scan_policy import ScanPolicy
from core.scanner_manifest import ActivityLevel

class ScopeViolationError(Exception):
    pass

class ScanPlanner:
    def __init__(self, engagement_id: str, target: str, scan_policy: ScanPolicy):
        self.engagement_id = engagement_id
        self.target = target
        self.policy = scan_policy
        self.scope_engine = ScopeEngine(engagement_id)
        
    def create_plan(self) -> Dict[str, Any]:
        """Create comprehensive scan plan based on target and policy."""
        # 1. Validate target against scope
        allowed, reason = self.scope_engine.is_allowed(self.target, self.policy.data["activity_level_limit"])
        if not allowed:
            raise ScopeViolationError(reason)
            
        # 2. Asset discovery phase
        asset_plan = self._plan_asset_discovery()
        
        # 3. Enumeration phase
        enum_plan = self._plan_enumeration()
        
        # 4. Technology detection
        tech_plan = self._plan_technology_detection()
        
        # 5. CVE matching (offline intelligence)
        cve_plan = self._plan_cve_matching()
        
        # 6. Vulnerability scanning
        vuln_plan = self._plan_vulnerability_scanning()
        
        # 7. Build dependency graph
        final_plan = self._build_dependency_graph([
            asset_plan, enum_plan, tech_plan, cve_plan, vuln_plan
        ])
        
        return final_plan
        
    def _plan_asset_discovery(self) -> Dict[str, Any]:
        """Plan asset discovery scanners."""
        return {
            "phase": "asset_discovery",
            "scanners": ["nmap", "subfinder"] if self.policy.is_scanner_allowed("nmap") else []
        }
        
    def _plan_enumeration(self) -> Dict[str, Any]:
        """Plan enumeration scanners."""
        return {
            "phase": "enumeration",
            "scanners": ["httpx", "whatweb"] if self.policy.is_scanner_allowed("httpx") else []
        }
        
    def _plan_technology_detection(self) -> Dict[str, Any]:
        """Plan technology detection."""
        return {
            "phase": "technology_detection",
            "scanners": ["wappalyzer"] if self.policy.is_scanner_allowed("wappalyzer") else []
        }
        
    def _plan_cve_matching(self) -> Dict[str, Any]:
        """Plan CVE intelligence matching."""
        return {
            "phase": "cve_matching",
            "scanners": ["offline_cve"] # Local operation
        }
        
    def _plan_vulnerability_scanning(self) -> Dict[str, Any]:
        """Plan vulnerability scanners based on policy."""
        vuln_scanners = []
        if self.policy.is_scanner_allowed("nuclei"):
            vuln_scanners.append("nuclei")
        if self.policy.is_scanner_allowed("nikto"):
            vuln_scanners.append("nikto")
            
        return {
            "phase": "vulnerability_scanning",
            "scanners": vuln_scanners
        }
        
    def _build_dependency_graph(self, phases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build dependency-resolved execution graph."""
        graph = {}
        for i, phase in enumerate(phases):
            deps = []
            if i > 0:
                deps.append(phases[i-1]["phase"])
                
            graph[phase["phase"]] = {
                "scanners": phase["scanners"],
                "depends_on": deps
            }
            
        return {
            "target": self.target,
            "engagement_id": self.engagement_id,
            "policy_id": self.policy.data["policy_id"],
            "execution_graph": graph,
            "resource_estimates": {
                "max_duration_seconds": self.policy.data["max_duration"],
                "concurrent_scanners": self.policy.data["rate_limits"]["concurrent_scanners"]
            }
        }
