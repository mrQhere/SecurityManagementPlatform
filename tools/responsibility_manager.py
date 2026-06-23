import json, os
from datetime import datetime

# Path to responsibility flag file
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RESPONSIBILITY_PATH = os.path.join(BASE_DIR, 'config', 'responsibility.json')

def load_responsibility_flag() -> bool:
    """Load the responsibility acceptance flag. Returns True if user has accepted."""
    if not os.path.exists(RESPONSIBILITY_PATH):
        return False
    try:
        with open(RESPONSIBILITY_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('accepted', False)
    except Exception:
        return False

def set_responsibility_flag(accepted: bool = True) -> None:
    """Persist the responsibility acceptance flag with timestamp, and log to scans database."""
    os.makedirs(os.path.dirname(RESPONSIBILITY_PATH), exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = {
        'accepted': accepted,
        'accepted_at': now if accepted else None,
    }
    with open(RESPONSIBILITY_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

    # Also record in the scans database for full audit trail
    if accepted:
        try:
            from tools.db_manager import record_responsibility_acceptance
            record_responsibility_acceptance(
                notes=f"User accepted responsibility disclaimer at {now}"
            )
        except Exception:
            pass  # Non-critical — file record is the primary store

# Ensure the flag file is present (defaults to False) when the module is imported
if not os.path.exists(RESPONSIBILITY_PATH):
    set_responsibility_flag(False)
