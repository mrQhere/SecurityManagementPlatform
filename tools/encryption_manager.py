"""
Encryption Manager — manages database and file encryption keys with hierarchical model.
V9.5  Rebuild.
"""

import os
import json
import base64
import hashlib
import logging
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tools.config_manager import BASE_DIR

logger = logging.getLogger("smp")

AUTH_FILE = os.path.join(BASE_DIR, "config", "auth.json")
AUDIT_LOG_FILE = os.path.join(BASE_DIR, "logs", "key_audit.log")

# In-memory secure storage
class KeyStore:
    def __init__(self):
        self._kek = None
        self._dek = None
        self._iek = None
        self._eek = None

    def clear(self):
        """Secure memory cleanup."""
        self._kek = None
        self._dek = None
        self._iek = None
        self._eek = None

    @property
    def kek(self): return self._kek
    @kek.setter
    def kek(self, val): self._kek = val

    @property
    def dek(self): return self._dek
    @dek.setter
    def dek(self, val): self._dek = val

    @property
    def iek(self): return self._iek
    @iek.setter
    def iek(self, val): self._iek = val

    @property
    def eek(self): return self._eek
    @eek.setter
    def eek(self, val): self._eek = val

_ACTIVE_STORE = KeyStore()
_PBKDF2_ITERATIONS = 600_000

def _audit_log(action: str, details: str = ""):
    """Audit logging for key operations."""
    os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)
    with open(AUDIT_LOG_FILE, "a") as f:
        ts = datetime.utcnow().isoformat()
        f.write(f"{ts} - ACTION: {action} - {details}\n")

def validate_password_complexity(password: str) -> tuple:
    """Enforce password complexity policy."""
    import re
    errors = []
    if len(password) < 12:
        errors.append("At least 12 characters")
    if not re.search(r'[A-Z]', password):
        errors.append("At least one uppercase letter (A-Z)")
    if not re.search(r'[a-z]', password):
        errors.append("At least one lowercase letter (a-z)")
    if not re.search(r'\d', password):
        errors.append("At least one digit (0-9)")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'"\\|,.<>\/?`~]', password):
        errors.append("At least one special character (!@#$%^&* etc.)")
    
    if errors:
        return False, "Password does not meet policy requirements:\n  • " + "\n  • ".join(errors)
    return True, ""

def hash_password(password: str, salt: bytes, iterations: int = _PBKDF2_ITERATIONS) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode())
    return hashlib.sha256(key).hexdigest()

def generate_sub_key(kek: bytes, key_data: dict) -> bytes:
    """Decrypt subkey from key_data using KEK."""
    nonce = base64.b64decode(key_data['nonce'])
    ciphertext = base64.b64decode(key_data['ciphertext'])
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_sub_key(kek: bytes, subkey: bytes) -> dict:
    """Encrypt a subkey with KEK."""
    aesgcm = AESGCM(kek)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, subkey, None)
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def has_password_set() -> bool:
    return os.path.exists(AUTH_FILE)

def setup_password(password: str):
    is_valid, error_msg = validate_password_complexity(password)
    if not is_valid:
        raise ValueError(f"Password rejected: {error_msg}")
    
    salt = os.urandom(16)
    pw_hash = hash_password(password, salt)
    
    # Generate KEK
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    kek = kdf.derive(password.encode())
    
    # Generate DEK, IEK, EEK
    dek = secrets.token_bytes(32)
    iek = secrets.token_bytes(32)
    eek = secrets.token_bytes(32)
    
    auth_data = {
        "salt": salt.hex(),
        "hash": pw_hash,
        "pbkdf2_iterations": _PBKDF2_ITERATIONS,
        "version": "V9.5",
        "keys": {
            "dek": encrypt_sub_key(kek, dek),
            "iek": encrypt_sub_key(kek, iek),
            "eek": encrypt_sub_key(kek, eek)
        }
    }
    
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(auth_data, f, indent=4)
        
    _ACTIVE_STORE.kek = kek
    _ACTIVE_STORE.dek = dek
    _ACTIVE_STORE.iek = iek
    _ACTIVE_STORE.eek = eek
    
    _audit_log("SETUP_PASSWORD", "Master password and hierarchical keys generated.")

def verify_password(password: str) -> bool:
    if not has_password_set():
        return False
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        salt = bytes.fromhex(data["salt"])
        pw_hash = data["hash"]
        
        calculated_hash = hash_password(password, salt, iterations=data.get("pbkdf2_iterations", _PBKDF2_ITERATIONS))
        if calculated_hash == pw_hash:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=data.get("pbkdf2_iterations", _PBKDF2_ITERATIONS),
            )
            kek = kdf.derive(password.encode())
            
            _ACTIVE_STORE.kek = kek
            if "keys" in data:
                _ACTIVE_STORE.dek = generate_sub_key(kek, data["keys"]["dek"])
                _ACTIVE_STORE.iek = generate_sub_key(kek, data["keys"]["iek"])
                _ACTIVE_STORE.eek = generate_sub_key(kek, data["keys"]["eek"])
            
            _audit_log("VERIFY_PASSWORD", "Master password verified and keys loaded to memory.")
            return True
        else:
            _audit_log("VERIFY_PASSWORD_FAILED", "Invalid password attempt.")
    except Exception as e:
        logger.error(f"Error during password verification: {e}")
        _audit_log("VERIFY_PASSWORD_ERROR", str(e))
    return False

def is_decryption_ok() -> bool:
    return _ACTIVE_STORE.kek is not None

def get_active_key(key_name: str = "DEK"):
    """Retrieve requested key (DEK, IEK, EEK) if application is unlocked."""
    if key_name.upper() == "DEK":
        return _ACTIVE_STORE.dek
    elif key_name.upper() == "IEK":
        return _ACTIVE_STORE.iek
    elif key_name.upper() == "EEK":
        return _ACTIVE_STORE.eek
    elif key_name.upper() == "KEK":
        return _ACTIVE_STORE.kek
    return None

def clear_keys():
    """Clear all keys from memory when locking application."""
    _ACTIVE_STORE.clear()
    _audit_log("CLEAR_KEYS", "Memory wiped of encryption keys.")

def rotate_master_password(old_password: str, new_password: str):
    """Rotate master password without changing DEK/IEK/EEK."""
    if not verify_password(old_password):
        raise ValueError("Invalid old password.")
    
    is_valid, error_msg = validate_password_complexity(new_password)
    if not is_valid:
        raise ValueError(f"New password rejected: {error_msg}")
    
    salt = os.urandom(16)
    pw_hash = hash_password(new_password, salt)
    
    # Generate new KEK
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    new_kek = kdf.derive(new_password.encode())
    
    # Re-encrypt subkeys
    auth_data = {
        "salt": salt.hex(),
        "hash": pw_hash,
        "pbkdf2_iterations": _PBKDF2_ITERATIONS,
        "version": "V9.5",
        "keys": {
            "dek": encrypt_sub_key(new_kek, _ACTIVE_STORE.dek),
            "iek": encrypt_sub_key(new_kek, _ACTIVE_STORE.iek),
            "eek": encrypt_sub_key(new_kek, _ACTIVE_STORE.eek)
        }
    }
    
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(auth_data, f, indent=4)
        
    _ACTIVE_STORE.kek = new_kek
    _audit_log("ROTATE_PASSWORD", "Master password rotated successfully.")
