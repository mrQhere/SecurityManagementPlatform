import json
import os
import hashlib
from datetime import datetime, timedelta

# Path to responsibility flag file
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RESPONSIBILITY_PATH = os.path.join(BASE_DIR, 'config', 'responsibility.json')

def load_all_attestations() -> dict:
    if not os.path.exists(RESPONSIBILITY_PATH):
        return {}
    try:
        with open(RESPONSIBILITY_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def check_target_attestation(target_id: int) -> bool:
    """Check if the target has a valid attestation less than 30 days old."""
    data = load_all_attestations()
    target_str = str(target_id)
    if target_str not in data:
        return False
        
    attestation = data[target_str]
    expires_at_str = attestation.get("expires_at")
    if not expires_at_str:
        return False
        
    try:
        expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
        if datetime.now() > expires_at:
            return False
    except ValueError:
        return False
        
    return True

def set_target_attestation(target_id: int, typed_sentence: str) -> None:
    """Persist the target attestation with hashed sentence and expiration."""
    os.makedirs(os.path.dirname(RESPONSIBILITY_PATH), exist_ok=True)
    data = load_all_attestations()
    
    now = datetime.now()
    expires = now + timedelta(days=30)
    
    text_hash = hashlib.sha256(typed_sentence.strip().encode()).hexdigest()
    
    data[str(target_id)] = {
        'attestation_text_hash': text_hash,
        'accepted_at': now.strftime("%Y-%m-%d %H:%M:%S"),
        'expires_at': expires.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    with open(RESPONSIBILITY_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

    # Record in the scans database
    try:
        from tools.db_manager import record_responsibility_acceptance
        record_responsibility_acceptance(
            notes=f"User accepted responsibility disclaimer for target {target_id} at {now.strftime('%Y-%m-%d %H:%M:%S')}"
        )
    except Exception:
        pass
