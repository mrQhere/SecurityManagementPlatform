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

def test_authorization_gating_missing_auth():
    """Verify intrusive scan is blocked when auth_id is missing."""
    from tools.errors import SMPAuthError
    from core.scanner_manifest import ActivityLevel
    policy = ScanPolicy({
        "engagement_id": "e1",
        "name": "IntrusivePolicy",
        "scanner_allowlist": ["nuclei"],
        "activity_level_limit": ActivityLevel.INTRUSIVE
    })
    planner = ScanPlanner(engagement_id="e1", target="example.com", scan_policy=policy, auth_id=None)
    planner.scope_engine.rules = [ScopeRule("1", "domain", "example.com", "allow")]
    with pytest.raises(SMPAuthError, match="auth_id is required for intrusive scans"):
        planner.create_plan()

def test_authorization_gating_expired_auth(monkeypatch):
    """Verify intrusive scan is blocked when auth is expired."""
    from datetime import datetime, timedelta, timezone
    from tools.errors import SMPAuthError
    from core.scanner_manifest import ActivityLevel
    policy = ScanPolicy({
        "engagement_id": "e1",
        "name": "IntrusivePolicy",
        "scanner_allowlist": ["nuclei"],
        "activity_level_limit": ActivityLevel.INTRUSIVE
    })
    expired_auth = {
        "auth_id": "AUTH-EXPIRED-123",
        "engagement_id": "e1",
        "target": "example.com",
        "authorized_by": "secops",
        "authorized_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
        "expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        "scope": "*.example.com",
        "limitations": [],
        "status": "active"
    }
    monkeypatch.setattr("tools.db_manager.get_authorization", lambda auth_id: expired_auth if auth_id == "AUTH-EXPIRED-123" else None)
    monkeypatch.setattr("tools.db_manager.update_authorization_status", lambda auth_id, status: None)
    
    planner = ScanPlanner(engagement_id="e1", target="example.com", scan_policy=policy, auth_id="AUTH-EXPIRED-123")
    planner.scope_engine.rules = [ScopeRule("1", "domain", "example.com", "allow")]
    with pytest.raises(SMPAuthError, match="invalid, expired, or revoked"):
        planner.create_plan()

def test_authorization_gating_valid_auth(monkeypatch):
    """Verify intrusive scan succeeds when auth is valid."""
    from datetime import datetime, timedelta, timezone
    from core.scanner_manifest import ActivityLevel
    policy = ScanPolicy({
        "engagement_id": "e1",
        "name": "IntrusivePolicy",
        "scanner_allowlist": ["nuclei"],
        "activity_level_limit": ActivityLevel.INTRUSIVE
    })
    valid_auth = {
        "auth_id": "AUTH-VALID-123",
        "engagement_id": "e1",
        "target": "example.com",
        "authorized_by": "secops",
        "authorized_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        "scope": "*.example.com",
        "limitations": [],
        "status": "active"
    }
    monkeypatch.setattr("tools.db_manager.get_authorization", lambda auth_id: valid_auth if auth_id == "AUTH-VALID-123" else None)
    
    planner = ScanPlanner(engagement_id="e1", target="example.com", scan_policy=policy, auth_id="AUTH-VALID-123")
    planner.scope_engine.rules = [ScopeRule("1", "domain", "example.com", "allow")]
    plan = planner.create_plan()
    assert "vulnerability_scanning" in plan["execution_graph"]

def test_scope_engine_loads_from_database(monkeypatch):
    """Verify ScopeEngine loads active scope rules from DB authorizations."""
    from datetime import datetime, timezone
    from core.scanner_manifest import ActivityLevel
    auth_list = [
        {
            "auth_id": "RULE-1",
            "engagement_id": "eng_prod",
            "target": "api.prod.com",
            "authorized_by": "auditor",
            "authorized_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": None,
            "scope": "*.prod.com",
            "limitations": [],
            "status": "active"
        },
        {
            "auth_id": "RULE-2",
            "engagement_id": "eng_prod",
            "target": "10.10.0.0/16",
            "authorized_by": "auditor",
            "authorized_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": None,
            "scope": "10.10.0.0/16",
            "limitations": [],
            "status": "active"
        }
    ]
    monkeypatch.setattr("tools.db_manager.get_authorizations_for_engagement", lambda eng_id: auth_list if eng_id == "eng_prod" else [])
    engine = ScopeEngine("eng_prod")
    assert len(engine.rules) == 2
    
    # In-scope tests
    allowed, _ = engine.is_allowed("sub.prod.com", ActivityLevel.ACTIVE)
    assert allowed is True
    allowed, _ = engine.is_allowed("10.10.1.5", ActivityLevel.ACTIVE)
    assert allowed is True
    
    # Out-of-scope test
    allowed, reason = engine.is_allowed("evil.com", ActivityLevel.ACTIVE)
    assert allowed is False
    assert "default deny" in reason.lower()

