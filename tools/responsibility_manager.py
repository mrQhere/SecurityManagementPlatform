import json, os

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
    """Persist the responsibility acceptance flag."""
    os.makedirs(os.path.dirname(RESPONSIBILITY_PATH), exist_ok=True)
    with open(RESPONSIBILITY_PATH, 'w', encoding='utf-8') as f:
        json.dump({'accepted': accepted}, f, indent=4)

# Ensure the flag file is present (defaults to False) when the module is imported
if not os.path.exists(RESPONSIBILITY_PATH):
    set_responsibility_flag(False)
