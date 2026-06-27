import os
import shutil
import sys
from pathlib import Path

# Adjust path so imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from tools.config_manager import BASE_DIR
from tools.db_manager import init_db

def reset_databases():
    print("Wiping all databases in database/ and backup/ directories...")
    
    db_dir = os.path.join(BASE_DIR, "database")
    backup_dir = os.path.join(BASE_DIR, "backup")
    
    if os.path.exists(db_dir):
        for f in os.listdir(db_dir):
            if f.endswith(".db") or f.endswith(".db-wal") or f.endswith(".db-shm"):
                os.remove(os.path.join(db_dir, f))
                
    if os.path.exists(backup_dir):
        for f in os.listdir(backup_dir):
            if f.endswith(".db") or f.endswith(".db-wal") or f.endswith(".db-shm"):
                os.remove(os.path.join(backup_dir, f))
                
    print("Databases deleted. Initializing new databases...")
    init_db()
    print("Database reset complete.")

if __name__ == "__main__":
    reset_databases()
