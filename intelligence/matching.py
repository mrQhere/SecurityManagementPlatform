import re
from typing import Dict, List, Optional
import logging

logger = logging.getLogger("smp")

class CPENormalizer:
    @staticmethod
    def normalize(vendor: str, product: str, version: str) -> str:
        """Convert basic product info into a CPE v2.3 string."""
        v = vendor.lower().replace(" ", "_")
        p = product.lower().replace(" ", "_")
        ver = version.lower() if version else "*"
        return f"cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*"

class VersionComparator:
    @staticmethod
    def satisfies_range(version: str, start: str, start_inc: bool, end: str, end_inc: bool) -> bool:
        """Check if a version falls within the specified range."""
        # Simple string matching stub; real implementation requires semantic version parsing
        try:
            from packaging.version import parse as parse_version
            v = parse_version(version)
            
            if start:
                vs = parse_version(start)
                if start_inc and v < vs: return False
                if not start_inc and v <= vs: return False
                
            if end:
                ve = parse_version(end)
                if end_inc and v > ve: return False
                if not end_inc and v >= ve: return False
                
            return True
        except Exception:
            # Fallback to simple matching if parsing fails
            return version == start or version == end

class OfflineMatchingEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    def match_observation(self, observation: Dict) -> Dict:
        """
        Evaluate observation against local vulnerability intelligence.
        Returns match status and candidate CVEs.
        """
        cpe_candidates = self._generate_cpe_candidates(observation)
        if not cpe_candidates:
            return {"status": "NO_MATCH", "cves": []}
            
        cves = self._query_local_cves(cpe_candidates)
        
        if not cves:
            return {"status": "NO_MATCH", "cves": []}
            
        # Refine by version range
        refined_cves = []
        for cve in cves:
            if self._evaluate_version(observation.get("version"), cve):
                refined_cves.append(cve)
                
        if refined_cves:
            return {"status": "LIKELY_AFFECTED", "cves": refined_cves}
            
        return {"status": "CANDIDATE", "cves": cves}
        
    def _generate_cpe_candidates(self, obs: Dict) -> List[str]:
        # Extract basic info
        vendor = obs.get("vendor", "")
        product = obs.get("product", "")
        if vendor and product:
            return [CPENormalizer.normalize(vendor, product, obs.get("version", ""))]
        return []
        
    def _query_local_cves(self, cpe_uris: List[str]) -> List[Dict]:
        """Query local database for matching CPEs."""
        # Stub: normally execute SQL against vulnerability.db
        return []
        
    def _evaluate_version(self, detected_version: str, cve_record: Dict) -> bool:
        """Evaluate if detected version falls in CVE's vulnerable ranges."""
        if not detected_version:
            return True
            
        start = cve_record.get("version_start")
        start_inc = cve_record.get("version_start_including", False)
        end = cve_record.get("version_end")
        end_inc = cve_record.get("version_end_including", False)
        
        if not any([start, end]):
            return True # No range specified, assume vulnerable
            
        return VersionComparator.satisfies_range(detected_version, start, start_inc, end, end_inc)
