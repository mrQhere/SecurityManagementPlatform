from enum import Enum
from typing import Dict, List, Optional

class ScannerState(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    BLOCKED = "BLOCKED"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    STARTED = "STARTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_FINDINGS = "COMPLETED_WITH_FINDINGS"
    COMPLETED_NO_FINDINGS = "COMPLETED_NO_FINDINGS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    PARSE_FAILED = "PARSE_FAILED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"

# State Transition Rules
# Dictionary mapping current state to allowed next states
ALLOWED_TRANSITIONS: Dict[ScannerState, List[ScannerState]] = {
    ScannerState.NOT_STARTED: [
        ScannerState.BLOCKED,
        ScannerState.DEPENDENCY_MISSING,
        ScannerState.STARTED,
        ScannerState.SKIPPED
    ],
    ScannerState.STARTED: [
        ScannerState.RUNNING,
        ScannerState.FAILED
    ],
    ScannerState.RUNNING: [
        ScannerState.COMPLETED,
        ScannerState.COMPLETED_WITH_FINDINGS,
        ScannerState.COMPLETED_NO_FINDINGS,
        ScannerState.FAILED,
        ScannerState.TIMEOUT,
        ScannerState.CANCELLED,
        ScannerState.PARSE_FAILED,
        ScannerState.PARTIAL
    ],
    # Terminal states have no outward transitions
    ScannerState.BLOCKED: [],
    ScannerState.DEPENDENCY_MISSING: [],
    ScannerState.COMPLETED: [],
    ScannerState.COMPLETED_WITH_FINDINGS: [],
    ScannerState.COMPLETED_NO_FINDINGS: [],
    ScannerState.FAILED: [],
    ScannerState.TIMEOUT: [],
    ScannerState.CANCELLED: [],
    ScannerState.PARSE_FAILED: [],
    ScannerState.PARTIAL: [],
    ScannerState.SKIPPED: []
}

class InvalidStateTransition(Exception):
    pass

class StateMachine:
    def __init__(self, initial_state: ScannerState = ScannerState.NOT_STARTED):
        self.current_state = initial_state

    def transition_to(self, new_state: ScannerState):
        """Transition to a new state if allowed."""
        if new_state not in ALLOWED_TRANSITIONS.get(self.current_state, []):
            raise InvalidStateTransition(f"Cannot transition from {self.current_state} to {new_state}")
        self.current_state = new_state

    def is_terminal(self) -> bool:
        """Check if current state is terminal."""
        return len(ALLOWED_TRANSITIONS.get(self.current_state, [])) == 0
