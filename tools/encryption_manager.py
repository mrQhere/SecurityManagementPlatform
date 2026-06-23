# =============================================================================
# PROPRIETARY SOFTWARE — ALL RIGHTS RESERVED
# Security Management Platform (SMP)
# Owner: Authorised Personnel Only
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  ⚠  CRITICAL NOTICE — Read way.md before ANY changes.                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# =============================================================================
"""
Encryption Manager — manages SQLite database encryption and decryption at application level.
"""

import os
import json
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from tools.config_manager import BASE_DIR

AUTH_FILE = os.path.join(BASE_DIR, "config", "auth.json")

# Database paths to secure
DB_FILES = {
    os.path.join(BASE_DIR, "database", "security.db"): os.path.join(BASE_DIR, "database", "security.db.enc"),
    os.path.join(BASE_DIR, "backup", "active_scans.db"): os.path.join(BASE_DIR, "backup", "active_scans.db.enc"),
    os.path.join(BASE_DIR, "backup", "important_results.db"): os.path.join(BASE_DIR, "backup", "important_results.db.enc"),
    os.path.join(BASE_DIR, "backup", "cve_secondary.db"): os.path.join(BASE_DIR, "backup", "cve_secondary.db.enc"),
}

ACTIVE_KEY = None  # Stored in memory while running

def hash_password(password: str, salt: bytes) -> str:
    """Derive hash from password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return hashlib.sha256(key).hexdigest()

def has_password_set() -> bool:
    """Check if a master password has already been configured."""
    return os.path.exists(AUTH_FILE)

def setup_password(password: str):
    """Establish master password and generate encryption keys."""
    salt = os.urandom(16)
    pw_hash = hash_password(password, salt)
    
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "salt": salt.hex(),
            "hash": pw_hash
        }, f, indent=4)
        
    global ACTIVE_KEY
    # Derive the key for encryption
    ACTIVE_KEY = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    ).derive(password.encode())
    ACTIVE_KEY = base64.urlsafe_b64encode(ACTIVE_KEY)
    
    # Encrypt existing files if any
    encrypt_databases()

def verify_password(password: str) -> bool:
    """Verify master password against stored credentials and load key."""
    if not has_password_set():
        return False
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        salt = bytes.fromhex(data["salt"])
        pw_hash = data["hash"]
        
        calculated_hash = hash_password(password, salt)
        if calculated_hash == pw_hash:
            global ACTIVE_KEY
            ACTIVE_KEY = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            ).derive(password.encode())
            ACTIVE_KEY = base64.urlsafe_b64encode(ACTIVE_KEY)
            return True
    except Exception:
        pass
    return False

def encrypt_databases():
    """Encrypt plain SQLite databases and delete unencrypted copies."""
    global ACTIVE_KEY
    if not ACTIVE_KEY:
        return
    fernet = Fernet(ACTIVE_KEY)
    for plain_path, enc_path in DB_FILES.items():
        if os.path.exists(plain_path):
            try:
                # Read plain text
                with open(plain_path, "rb") as f:
                    data = f.read()
                # Encrypt
                enc_data = fernet.encrypt(data)
                # Write to encrypted file
                os.makedirs(os.path.dirname(enc_path), exist_ok=True)
                with open(enc_path, "wb") as f:
                    f.write(enc_data)
                # Securely overwrite and remove plain text file
                size = os.path.getsize(plain_path)
                with open(plain_path, "wb") as f:
                    f.write(os.urandom(size))
                os.remove(plain_path)
            except Exception:
                pass

def decrypt_databases():
    """Decrypt encrypted database files back into plain SQLite databases."""
    global ACTIVE_KEY
    if not ACTIVE_KEY:
        return
    fernet = Fernet(ACTIVE_KEY)
    for plain_path, enc_path in DB_FILES.items():
        if os.path.exists(enc_path):
            try:
                with open(enc_path, "rb") as f:
                    enc_data = f.read()
                dec_data = fernet.decrypt(enc_data)
                # Ensure parent directory exists
                os.makedirs(os.path.dirname(plain_path), exist_ok=True)
                with open(plain_path, "wb") as f:
                    f.write(dec_data)
            except Exception:
                pass
