import requests
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("smp.api_client")

class SMPApiClient:
    """
    Client for communicating with the SMP FastAPI backend.
    Replaces direct SQLite connections in the UI.
    """
    def __init__(self, base_url: str = "http://127.0.0.1:8000/api/v6"):
        self.base_url = base_url.rstrip("/")
        self.token: Optional[str] = None
        self.session = requests.Session()
        
    def authenticate(self, username: str, password: str) -> bool:
        try:
            resp = self.session.post(
                f"{self.base_url}/auth/token",
                json={"username": username, "password": password},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("access_token")
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                return True
            return False
        except Exception as e:
            logger.error(f"[ApiClient] Authentication failed: {e}")
            return False

    def get_targets(self) -> list:
        try:
            resp = self.session.get(f"{self.base_url}/target", timeout=10)
            if resp.status_code == 200:
                return resp.json().get("targets", [])
            return []
        except Exception as e:
            logger.error(f"[ApiClient] get_targets failed: {e}")
            return []
            
    def get_active_scans(self) -> list:
        try:
            resp = self.session.get(f"{self.base_url}/scan", timeout=10)
            if resp.status_code == 200:
                return resp.json().get("scans", [])
            return []
        except Exception as e:
            logger.error(f"[ApiClient] get_active_scans failed: {e}")
            return []
            
    def get_cve_stats(self) -> dict:
        try:
            resp = self.session.get(f"{self.base_url}/cve/stats", timeout=10)
            if resp.status_code == 200:
                return resp.json()
            return {}
        except Exception as e:
            logger.error(f"[ApiClient] get_cve_stats failed: {e}")
            return {}

# Global instance for UI components to use
api = SMPApiClient()
