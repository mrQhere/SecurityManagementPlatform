"""
Encryption Manager — manages SQLite database encryption and decryption at application level.
"""

import os
import json
import base64
import hashlib
import logging
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from tools.config_manager import BASE_DIR

logger = logging.getLogger("smp")

AUTH_FILE = os.path.join(BASE_DIR, "config", "auth.json")

# Database paths to secure
# NOTE: cve_secondary.db is intentionally excluded — CVE data is public threat
# intelligence, not sensitive user data. Encrypting it wastes I/O on every
# app open/close (240k+ rows) with zero security benefit.
DB_FILES = {
    os.path.join(BASE_DIR, "database", "security.db"): os.path.join(BASE_DIR, "database", "security.db.enc"),
    os.path.join(BASE_DIR, "database", "backup", "active_scans.db"): os.path.join(BASE_DIR, "database", "backup", "active_scans.db.enc"),
}

ACTIVE_KEY = None  # Stored in memory while running

# Track whether decryption succeeded so the rest of the app can check
_DECRYPTION_SUCCEEDED = False

# V9.2.1: NIST 2024 recommendation — 600,000 iterations for PBKDF2-SHA256
_PBKDF2_ITERATIONS = 600_000


def validate_password_complexity(password: str) -> tuple:
    """
    V9.2.1 — Enforce password complexity policy.
    
    Requirements:
      - Minimum 12 characters
      - At least one uppercase letter
      - At least one lowercase letter  
      - At least one digit
      - At least one special character (!@#$%^&*...)
    
    Returns: (is_valid: bool, error_message: str)
    """
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
    """Derive hash from password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode())
    return hashlib.sha256(key).hexdigest()

def has_password_set() -> bool:
    """Check if a master password has already been configured."""
    return os.path.exists(AUTH_FILE)

def setup_password(password: str):
    """V9.2.1 — Establish master password with complexity check and generate encryption keys."""
    # Complexity check on first setup
    is_valid, error_msg = validate_password_complexity(password)
    if not is_valid:
        raise ValueError(f"Password rejected: {error_msg}")
    
    salt = os.urandom(16)
    pw_hash = hash_password(password, salt)
    
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "salt": salt.hex(),
            "hash": pw_hash,
            "pbkdf2_iterations": _PBKDF2_ITERATIONS,
            "version": "V9.2.1"
        }, f, indent=4)
        
    global ACTIVE_KEY
    # Derive the key for encryption
    ACTIVE_KEY = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    ).derive(password.encode())
    ACTIVE_KEY = ACTIVE_KEY.hex()

def verify_password(password: str) -> bool:
    """Verify master password against stored credentials and load key."""
    if not has_password_set():
        return False
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        salt = bytes.fromhex(data["salt"])
        pw_hash = data["hash"]
        
        calculated_hash = hash_password(password, salt, iterations=data.get("pbkdf2_iterations", 100000))
        if calculated_hash == pw_hash:
            global ACTIVE_KEY
            ACTIVE_KEY = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=data.get("pbkdf2_iterations", 100000),
            ).derive(password.encode())
            ACTIVE_KEY = ACTIVE_KEY.hex()
            return True
    except Exception:
        pass
    return False

def encrypt_databases():
    """No-op: Database encryption is now handled transparently by SQLCipher."""
    pass


def decrypt_databases():
    """No-op: Database encryption is now handled transparently by SQLCipher.
    Returns True to indicate readiness.
    """
    global _DECRYPTION_SUCCEEDED
    _DECRYPTION_SUCCEEDED = True
    return True


def is_decryption_ok() -> bool:
    """Returns True if decryption succeeded this session (or no encrypted files exist)."""
    global ACTIVE_KEY
    return ACTIVE_KEY is not None


def get_active_key():
    """Retrieve active Fernet key if application is unlocked."""
    global ACTIVE_KEY
    return ACTIVE_KEY
