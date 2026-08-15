import os
import uuid
import json
import logging
from datetime import datetime
from typing import Dict, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from tools.encryption_manager import get_active_key

logger = logging.getLogger("smp")

class EvidenceStore:
    def __init__(self, base_path: str):
        self.base_path = base_path
    
    def _get_encryption_key(self) -> bytes:
        """Fetch the EEK (Evidence Encryption Key) from the manager."""
        eek = get_active_key("EEK")
        if not eek:
            raise ValueError("Evidence Encryption Key (EEK) not available. Is the application unlocked?")
        return eek

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt evidence using AESGCM."""
        key = self._get_encryption_key()
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
        
    def _decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt evidence."""
        key = self._get_encryption_key()
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    def _get_evidence_path(self, evidence_id: str, engagement_id: str, scan_id: str) -> str:
        return os.path.join(self.base_path, engagement_id, scan_id, evidence_id)

    def store_evidence(self, engagement_id: str, scan_id: str, evidence_type: str, data: bytes, metadata: dict) -> str:
        """Store evidence with encryption."""
        import hashlib
        evidence_id = str(uuid.uuid4())
        
        metadata["evidence_id"] = evidence_id
        metadata["type"] = evidence_type
        metadata["size_bytes"] = len(data)
        metadata["sha256"] = hashlib.sha256(data).hexdigest()
        metadata["created_at"] = datetime.utcnow().isoformat()
        
        encrypted_data = self._encrypt(data)
        
        path = self._get_evidence_path(evidence_id, engagement_id, scan_id)
        os.makedirs(path, exist_ok=True)
        
        # Save encrypted evidence
        with open(os.path.join(path, "evidence.enc"), 'wb') as f:
            f.write(encrypted_data)
            
        # Save metadata and checksum
        self._store_metadata(path, metadata)
        with open(os.path.join(path, "checksum.txt"), 'w') as f:
            f.write(metadata["sha256"])
            
        return evidence_id

    def retrieve_evidence(self, engagement_id: str, scan_id: str, evidence_id: str) -> Tuple[bytes, dict]:
        """Retrieve and decrypt evidence."""
        path = self._get_evidence_path(evidence_id, engagement_id, scan_id)
        metadata = self._get_metadata(path)
        
        with open(os.path.join(path, "evidence.enc"), 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_data = self._decrypt(encrypted_data)
        return decrypted_data, metadata

    def _store_metadata(self, path: str, metadata: dict):
        with open(os.path.join(path, "metadata.json"), 'w') as f:
            json.dump(metadata, f, indent=4)
            
    def _get_metadata(self, path: str) -> dict:
        with open(os.path.join(path, "metadata.json"), 'r') as f:
            return json.load(f)
