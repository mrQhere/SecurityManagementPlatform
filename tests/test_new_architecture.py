import pytest
from core.observation import Observation, ObservationType
from core.finding import Finding, FindingSeverity
from core.state_machine import StateMachine, ScannerState
from core.scope_engine import ScopeEngine, ScopeRule
from core.scan_policy import ScanPolicy
from core.authorization import AuthorizationTracker
from scanners.scan_planner import ScanPlanner

def test_observation_schema():
    obs = Observation({
        "scan_id": "test_scan",
        "scanner_id": "nmap",
        "observation_type": "port",
        "title": "Open Port 80"
    })
    assert obs.data["observation_type"] == ObservationType.PORT

def test_state_machine():
    sm = StateMachine()
    assert sm.current_state == ScannerState.NOT_STARTED
    sm.transition_to(ScannerState.STARTED)
    assert sm.current_state == ScannerState.STARTED

def test_scope_engine(monkeypatch):
    monkeypatch.setattr("tools.db_manager.get_authorizations_for_engagement", lambda x: [])
    engine = ScopeEngine("engagement_1")
    engine.rules = [ScopeRule("1", "domain", "example.com", "allow", 100)]
    from core.scanner_manifest import ActivityLevel
    allowed, _ = engine.is_allowed("example.com", ActivityLevel.ACTIVE)
    assert allowed
    
    allowed, _ = engine.is_allowed("other.com", ActivityLevel.ACTIVE)
    assert not allowed

def test_scan_policy():
    policy = ScanPolicy({
        "engagement_id": "e1",
        "name": "Default",
        "scanner_allowlist": ["nmap"]
    })
    assert policy.is_scanner_allowed("nmap")
    assert not policy.is_scanner_allowed("nuclei")
