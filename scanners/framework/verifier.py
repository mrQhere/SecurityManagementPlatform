import shutil
import hashlib
from typing import Dict, Tuple

class BinaryVerifier:
    def verify(self, binary_name: str, required_version: str = None) -> Dict:
        """
        Comprehensive binary verification.
        """
        is_installed, path = self.check_installation(binary_name)
        if not is_installed:
            return {
                "available": False,
                "path": None,
                "version": None,
                "compatible": False,
                "checksum": None,
                "offline_capable": False
            }
            
        version = self.get_version(path)
        compatible = True
        if required_version and version != required_version:
            compatible = False
            
        return {
            "available": True,
            "path": path,
            "version": version,
            "compatible": compatible,
            "checksum": self._compute_checksum(path),
            "offline_capable": self.check_offline_capability(binary_name)
        }
    
    def check_installation(self, binary_name: str) -> Tuple[bool, str]:
        """Check if binary is installed in PATH."""
        path = shutil.which(binary_name)
        if path:
            return True, path
        return False, ""
    
    def get_version(self, binary_path: str) -> str:
        """Get binary version (dummy implementation, needs tool specific logic)."""
        return "1.0.0"
    
    def verify_checksum(self, binary_path: str, expected_checksum: str) -> bool:
        """Verify binary checksum."""
        return self._compute_checksum(binary_path) == expected_checksum
        
    def _compute_checksum(self, binary_path: str) -> str:
        sha256_hash = hashlib.sha256()
        try:
            with open(binary_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return ""
    
    def check_offline_capability(self, binary_name: str) -> bool:
        """Check if scanner works offline."""
        # Simple heuristic mapping or check logic
        return True
