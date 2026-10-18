from enum import Enum
from typing import Dict, List, Optional, Set

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

# Central set of terminal ScannerState enum members (no outward transitions)
TERMINAL_SCANNER_STATES: Set[ScannerState] = {
    state for state, next_states in ALLOWED_TRANSITIONS.items() if len(next_states) == 0
}

# Central set of terminal scan status strings across database, UI, and state machine.
# Cancelled scans are terminal and must NEVER be auto-resumed.
TERMINAL_SCAN_STATUSES: Set[str] = {
    # Database / UI standard statuses
    "Completed",
    "Completed with Findings",
    "Completed no Findings",
    "Failed",
    "Cancelled",
    "Canceled",
    "Timeout",
    "Blocked",
    "Dependency Missing",
    "Parse Failed",
    "Partial",
    "Skipped",
    "Report Pending",
    # Uppercase enum string variants
    "COMPLETED",
    "COMPLETED_WITH_FINDINGS",
    "COMPLETED_NO_FINDINGS",
    "FAILED",
    "TIMEOUT",
    "CANCELLED",
    "CANCELED",
    "BLOCKED",
    "DEPENDENCY_MISSING",
    "PARSE_FAILED",
    "PARTIAL",
    "SKIPPED",
    "REPORT PENDING",
    "REPORT_PENDING",
}

# Explicitly recoverable in-flight statuses after an unclean shutdown
RECOVERABLE_IN_FLIGHT_STATUSES: Set[str] = {
    # Active pipeline phases/steps
    "Running HTTPx", "Running WhatWeb", "Running Subfinder", "Running theHarvester", "Running CRT.sh",
    "Running HackerTarget", "Running Whois", "Running Wayback Machine",
    "Running Traceroute", "Running Nmap", "Running SSL Scan",
    "Running Security Headers", "Running Robots.txt", "Running CORS",
    "Running CMS Scanner", "Running Nikto", "Running Nuclei", "Running ffuf",
    "Running Open Redirect", "Running Tech Fingerprint",
    "Running Wapiti", "Running SQLMap", "Running Shodan", "Running Gitleaks",
    "Running ZAP",
    "Running Dalfox", "Running Arjun", "Running DNSx", "Running Katana",
    "Running Commix", "Running JWT Scanner", "Running WPScan",
    "Running Masscan", "Running ParamSpider", "Running Cloud Enum",
    "Running Feroxbuster", "Running API Fuzzer", "Running GraphQL Scanner",
    "Running Retire.js Scanner", "Running CRLF Scanner",
    "Running Prototype Pollution Scanner", "Running WebSocket Scanner",
    "Running Race-the-Web Scanner", "Running SSRF Scanner", "Running XXE Scanner",
    "Running Path Traversal Scanner", "Running Auth Brute-Force Test",
    "Running TruffleHog", "Running Semgrep", "Running Trivy",
    "Running IDOR Scanner", "Running Amass", "Running SpiderFoot OSINT",
    "Running HTTP Smuggling Scanner",
    "Correlating CVEs",
    # Generic in-flight statuses
    "Started", "Running", "In Progress", "Pending",
    "STARTED", "RUNNING", "PENDING", "IN_PROGRESS",
}


def is_terminal_status(status: Optional[str]) -> bool:
    """
    Check if a scan status string represents a terminal state.
    Terminal states cannot transition to any active state and must never be auto-resumed.
    """
    if not status or not isinstance(status, str):
        return False
    clean = status.strip()
    return clean in TERMINAL_SCAN_STATUSES or clean.upper() in {
        s.upper() for s in TERMINAL_SCAN_STATUSES
    }


def is_recoverable_status(status: Optional[str]) -> bool:
    """
    Check if a scan status is explicitly classified as recoverable after an unclean shutdown.
    Fails closed: returns False for all terminal states, unknown/corrupt statuses, None, or empty.
    """
    if not status or not isinstance(status, str):
        return False
    clean = status.strip()
    if not clean:
        return False

    # Terminal statuses are strictly non-recoverable
    if is_terminal_status(clean):
        return False

    if clean in RECOVERABLE_IN_FLIGHT_STATUSES or clean.upper() in {
        s.upper() for s in RECOVERABLE_IN_FLIGHT_STATUSES
    }:
        return True

    # Active scanner steps: 'Running <Scanner>'
    if clean.startswith("Running ") and len(clean) > 8:
        return True

    return False


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
        return self.current_state in TERMINAL_SCANNER_STATES

