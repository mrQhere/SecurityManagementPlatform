import logging
import hashlib
import json
from typing import List, Dict, Any
from core.finding import Finding
from core.observation import ObservationType
from intelligence.matching import OfflineMatchingEngine

logger = logging.getLogger("smp")

class FindingEngine:
    def __init__(self, vulnerability_db_path: str):
        self.intel_engine = OfflineMatchingEngine(vulnerability_db_path)
    
    def _generate_fingerprint(self, components: Dict[str, Any]) -> str:
        """Generate deduplication fingerprint."""
        # Ensure consistent ordering
        serialized = json.dumps(components, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def correlate_findings(self, observations: List[Dict]) -> List[Dict]:
        """Correlate observations into findings."""
        grouped_findings: Dict[str, Dict] = {}
        
        for obs in observations:
            # Match against CVE intelligence
            intel_result = self.intel_engine.match_observation(obs)
            matched_cves = [c.get("cve_id") for c in intel_result.get("cves", []) if "cve_id" in c]
            
            # Determine vulnerability class based on observation type / title
            vuln_class = obs.get("title", "Unknown")
            
            # Build fingerprint components
            components = {
                "asset_id": obs.get("asset_id"),
                "service_id": obs.get("service_id"),
                "vulnerability_class": vuln_class,
                "cve_ids": matched_cves
            }
            fingerprint = self._generate_fingerprint(components)
            
            if fingerprint not in grouped_findings:
                # Create base canonical finding
                severity = "Medium" # Stub logic
                confidence = obs.get("confidence", 0.5)
                
                if intel_result["status"] == "CONFIRMED_BY_EVIDENCE":
                    severity = "Critical"
                    confidence = 1.0
                elif intel_result["status"] == "LIKELY_AFFECTED":
                    severity = "High"
                    confidence = 0.8
                
                grouped_findings[fingerprint] = {
                    "fingerprint": fingerprint,
                    "engagement_id": obs.get("scan_id"), # In real implementation, resolve from scan_id
                    "title": vuln_class,
                    "vulnerability_class": vuln_class,
                    "cve_id": matched_cves,
                    "asset_id": obs.get("asset_id"),
                    "service_id": obs.get("service_id"),
                    "severity": severity,
                    "confidence": confidence,
                    "affected_observations": [obs.get("observation_id")],
                    "scanner_sources": {obs.get("scanner_id")},
                    "risk_score": self._calculate_risk(severity, confidence),
                    "status": "open",
                    "occurrence_count": 1
                }
            else:
                # Merge evidence-preserving observations
                existing = grouped_findings[fingerprint]
                existing["affected_observations"].append(obs.get("observation_id"))
                existing["scanner_sources"].add(obs.get("scanner_id"))
                existing["occurrence_count"] += 1
                # Increase confidence slightly on multi-source confirmation
                existing["confidence"] = min(1.0, existing["confidence"] + 0.1)
                existing["risk_score"] = self._calculate_risk(existing["severity"], existing["confidence"])
        
        # Convert sets to list for final output
        final_findings = []
        for finding in grouped_findings.values():
            finding["scanner_sources"] = list(finding["scanner_sources"])
            # Validate against schema
            try:
                Finding(finding)
                final_findings.append(finding)
            except Exception as e:
                logger.error(f"Failed to validate correlated finding {finding.get('title')}: {e}")
                
        return final_findings

    def _calculate_risk(self, severity: str, confidence: float) -> float:
        """Calculate base risk score."""
        sev_map = {"Critical": 100, "High": 80, "Medium": 60, "Low": 30, "Info": 10}
        base = sev_map.get(severity, 0)
        return round(base * confidence, 2)
