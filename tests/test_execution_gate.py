"""
tests/test_execution_gate.py — Unified Scan Execution Gate Regression Tests (v9.5.10).

Verifies that ALL scanner launches pass through one central server-side execution gate:
  1. Out-of-scope targets are denied and NEVER launch a subprocess.
  2. Expired or revoked authorizations fail closed before execution.
  3. Intrusive scans require valid authorization.
  4. Non-active engagements (archived, completed) fail closed.
  5. Cancelled scans (cancel_event.set()) abort immediately before execution.
  6. Scanners exceeding engagement policy activity limits are denied.
  7. Scanners disallowed by user scan policy are denied.
  8. Every production entry point is covered:
     - ScanPlanner.create_plan
     - start_scan_for_target
     - _run_scan_sequence
     - run_with_resilience
     - GenericPlugin.execute
     - ScanWorker.run (UI)
     - POST /api/v6/scan (API)
  9. Valid allow-path works only with valid scope and authorization.
"""

import importlib.util
import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.authorization import AuthStatus
from core.execution_gate import (
    get_scanner_activity_level,
    verify_scan_execution,
)
from core.scanner_manifest import ActivityLevel
from core.scan_policy import ScanPolicy
from core.scope_engine import ScopeEngine

_PYSIDE_AVAILABLE = importlib.util.find_spec("PySide6") is not None
_requires_pyside = pytest.mark.skipif(
    not _PYSIDE_AVAILABLE,
    reason="PySide6 not installed; skipping GUI worker test"
)

_FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None
_requires_fastapi = pytest.mark.skipif(
    not _FASTAPI_AVAILABLE,
    reason="fastapi not installed; skipping API route test"
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures and Helpers
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_subprocess():
    """Patches subprocess.Popen and subprocess.run to monitor for tool execution."""
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 0
        mock_proc.poll.return_value = 0
        mock_popen.return_value = mock_proc

        mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
        yield {"popen": mock_popen, "run": mock_run}


def create_auth_record(auth_id="AUTH-01", eng_id="ENG-01", scope="*.authorized.com", status="active", delta_hours=2):
    expires_at = None
    if delta_hours is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=delta_hours)).isoformat()
    return {
        "auth_id": auth_id,
        "engagement_id": eng_id,
        "target": "authorized.com",
        "scope": scope,
        "status": status,
        "expires_at": expires_at,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Suite 1: Direct Execution Gate Security Checks
# ─────────────────────────────────────────────────────────────────────────────

def test_gate_denies_empty_target():
    """Execution gate fails closed on missing or empty target."""
    allowed, reason = verify_scan_execution(target="")
    assert allowed is False
    assert "Invalid target" in reason

    allowed, reason = verify_scan_execution(target=None)
    assert allowed is False
    assert "Invalid target" in reason


def test_gate_denies_out_of_scope_target(monkeypatch):
    """Execution gate denies out-of-scope targets when scope rules exist."""
    valid_auth = create_auth_record(scope="*.target.internal")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    allowed, reason = verify_scan_execution(
        target="http://evil-attacker.com",
        engagement_id="ENG-01",
    )
    assert allowed is False
    assert "Scope violation" in reason


def test_gate_denies_when_no_authorizations_configured(monkeypatch):
    """Default deny: an engagement with zero active authorizations allows nothing."""
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: []
    )

    allowed, reason = verify_scan_execution(
        target="http://target.internal",
        engagement_id="ENG-EMPTY",
    )
    assert allowed is False
    assert "Scope violation" in reason


def test_gate_denies_expired_authorization(monkeypatch):
    """Expired authorization must never authorize a target."""
    expired_auth = create_auth_record(status="active", delta_hours=-5)
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [expired_auth]
    )
    monkeypatch.setattr(
        "tools.db_manager.get_authorization",
        lambda aid: expired_auth
    )

    allowed, reason = verify_scan_execution(
        target="sub.authorized.com",
        engagement_id="ENG-01",
        auth_id="AUTH-01",
    )
    assert allowed is False
    assert "invalid, expired, or revoked" in reason or "Scope violation" in reason


def test_gate_denies_revoked_authorization(monkeypatch):
    """Revoked authorization must never authorize a target."""
    revoked_auth = create_auth_record(status="revoked", delta_hours=24)
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [revoked_auth]
    )
    monkeypatch.setattr(
        "tools.db_manager.get_authorization",
        lambda aid: revoked_auth
    )

    allowed, reason = verify_scan_execution(
        target="sub.authorized.com",
        engagement_id="ENG-01",
        auth_id="AUTH-01",
    )
    assert allowed is False
    assert "invalid, expired, or revoked" in reason or "Scope violation" in reason


def test_gate_denies_intrusive_scanner_without_auth_id(monkeypatch):
    """Intrusive scanners (e.g. nuclei, sqlmap, zap) must strictly require auth_id."""
    valid_auth = create_auth_record(scope="*.authorized.com")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    policy = ScanPolicy({
        "engagement_id": "ENG-01",
        "name": "IntrusivePolicy",
        "activity_level_limit": "INTRUSIVE",
    })
    allowed, reason = verify_scan_execution(
        target="sub.authorized.com",
        scanner_name="nuclei",
        scan_policy=policy,
        auth_id=None,  # Missing auth_id
    )
    assert allowed is False
    assert "auth_id is required for intrusive scans" in reason


def test_gate_denies_activity_exceeding_policy_limit(monkeypatch):
    """Scanner whose activity level exceeds the policy limit is blocked."""
    valid_auth = create_auth_record(scope="*.authorized.com")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    policy = ScanPolicy({
        "engagement_id": "ENG-01",
        "name": "PassivePolicy",
        "activity_level_limit": "PASSIVE",
    })
    allowed, reason = verify_scan_execution(
        target="sub.authorized.com",
        scanner_name="nmap",  # ACTIVE > PASSIVE
        scan_policy=policy,
    )
    assert allowed is False
    assert "exceeds engagement policy limit" in reason


def test_gate_denies_inactive_or_archived_engagement():
    """Non-active engagement objects fail closed."""
    class MockEngagement:
        def __init__(self, status):
            self.status = status

    for bad_status in ["archived", "completed", "suspended"]:
        allowed, reason = verify_scan_execution(
            target="sub.authorized.com",
            engagement=MockEngagement(bad_status),
        )
        assert allowed is False
        assert f"Engagement is {bad_status} (not active)" in reason


def test_gate_denies_when_cancelled_by_event():
    """Scan execution cancelled via threading/multiprocessing Event is aborted immediately."""
    cancel_evt = threading.Event()
    cancel_evt.set()

    allowed, reason = verify_scan_execution(
        target="sub.authorized.com",
        cancel_event=cancel_evt,
    )
    assert allowed is False
    assert "cancelled by user" in reason


def test_gate_denies_when_cancelled_by_boolean():
    """cancel_event=True blocks execution immediately."""
    allowed, reason = verify_scan_execution(
        target="sub.authorized.com",
        cancel_event=True,
    )
    assert allowed is False
    assert "cancelled by user" in reason


def test_gate_denies_scanner_not_allowed_by_policy():
    """Scanners disallowed by policy's enabled_scanners or disabled_scanners are blocked."""
    policy = ScanPolicy({
        "engagement_id": "ENG-01",
        "name": "DisallowPolicy",
        "scanner_denylist": ["nikto"],
    })
    allowed, reason = verify_scan_execution(
        target="sub.authorized.com",
        scanner_name="nikto",
        scan_policy=policy,
    )
    assert allowed is False
    assert "not allowed by scan policy" in reason


# ─────────────────────────────────────────────────────────────────────────────
# Suite 2: Entry Point Assertions — Subprocess Never Called on Deny
# ─────────────────────────────────────────────────────────────────────────────

def test_scan_planner_denies_out_of_scope_target(monkeypatch, mock_subprocess):
    """ScanPlanner.create_plan raises ScopeViolationError on out-of-scope target; no subprocess called."""
    from scanners.scan_planner import ScanPlanner, ScopeViolationError

    valid_auth = create_auth_record(scope="*.authorized.com")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    policy = ScanPolicy({
        "name": "PlannerPolicy",
        "engagement_id": "ENG-01",
    })
    planner = ScanPlanner(
        engagement_id="ENG-01",
        target="http://unauthorized-evil.com",
        scan_policy=policy,
    )

    with pytest.raises(ScopeViolationError, match="Scope violation"):
        planner.create_plan()

    mock_subprocess["popen"].assert_not_called()
    mock_subprocess["run"].assert_not_called()


def test_start_scan_for_target_denies_out_of_scope(monkeypatch, mock_subprocess):
    """start_scan_for_target returns False on out-of-scope target; no process spawned."""
    from scanners.scan_runner import start_scan_for_target

    valid_auth = create_auth_record(scope="192.168.1.0/24")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    target = {
        "id": 999,
        "url": "10.0.0.50",
        "engagement_id": "ENG-01",
    }

    result = start_scan_for_target(target)
    assert result is False

    mock_subprocess["popen"].assert_not_called()
    mock_subprocess["run"].assert_not_called()


def test_run_scan_sequence_stops_on_out_of_scope(monkeypatch, mock_subprocess):
    """_run_scan_sequence fails closed on out-of-scope target; zero scanner subprocesses called."""
    from scanners.scan_runner import _run_scan_sequence

    valid_auth = create_auth_record(scope="192.168.1.0/24")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    target = {
        "id": 1001,
        "url": "http://out-of-scope-danger.com",
        "engagement_id": "ENG-01",
    }

    # Should exit cleanly at the execution gate check without spawning tools
    _run_scan_sequence(target)

    mock_subprocess["popen"].assert_not_called()
    mock_subprocess["run"].assert_not_called()


def test_run_with_resilience_denies_out_of_scope(monkeypatch, mock_subprocess):
    """run_with_resilience gate denies out-of-scope target and skips scanner function."""
    from scanners.scan_runner import run_with_resilience

    valid_auth = create_auth_record(scope="*.safe.org")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    mock_scanner_fn = MagicMock()

    result, success = run_with_resilience(
        scan_id=55,
        step_name="Running Nmap",
        scan_func=mock_scanner_fn,
        url="http://attacker.com",
        binary_name="nmap",
        engagement_id="ENG-01",
    )

    assert result is None
    assert success is False
    mock_scanner_fn.assert_not_called()
    mock_subprocess["popen"].assert_not_called()
    mock_subprocess["run"].assert_not_called()


def test_run_with_resilience_denies_when_cancelled(monkeypatch, mock_subprocess):
    """run_with_resilience aborts when cancel_event is set."""
    from scanners.scan_runner import run_with_resilience

    cancel_evt = threading.Event()
    cancel_evt.set()

    mock_scanner_fn = MagicMock()

    result, success = run_with_resilience(
        scan_id=56,
        step_name="Running HTTPx",
        scan_func=mock_scanner_fn,
        url="http://authorized.com",
        binary_name="httpx",
        cancel_event=cancel_evt,
    )

    assert result is None
    assert success is False
    mock_scanner_fn.assert_not_called()
    mock_subprocess["popen"].assert_not_called()


def test_generic_plugin_execute_denies_out_of_scope(monkeypatch, mock_subprocess):
    """GenericPlugin.execute returns empty list and does not execute when out of scope."""
    from scanners.core.plugin import GenericPlugin

    valid_auth = create_auth_record(scope="*.allowed.com")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    mock_scan_func = MagicMock()
    plugin = GenericPlugin(
        target_url="http://disallowed-target.com",
        scan_id=77,
        name="WhatWeb",
        step_name="Running WhatWeb",
        depends_on=[],
        scan_func=mock_scan_func,
        binary_name="whatweb",
        process_func=None,
        engagement_id="ENG-01",
    )

    res = plugin.execute()
    assert res == []
    mock_scan_func.assert_not_called()
    mock_subprocess["popen"].assert_not_called()
    mock_subprocess["run"].assert_not_called()


@_requires_pyside
def test_ui_scan_worker_denies_out_of_scope(monkeypatch, mock_subprocess):
    """UI ScanWorker emits scan_error and aborts on out-of-scope targets."""
    from ui.controllers.dashboard_logic import ScanWorker

    valid_auth = create_auth_record(scope="*.safe-company.com")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    target = {
        "url": "http://evil-unauthorized.com",
        "engagement_id": "ENG-01",
    }
    worker = ScanWorker(target=target, settings={})

    emitted_errors = []
    emitted_completes = []
    worker.scan_error.connect(lambda tgt, err: emitted_errors.append((tgt, err)))
    worker.scan_complete.connect(lambda tgt, ok: emitted_completes.append((tgt, ok)))

    worker.run()

    assert len(emitted_errors) == 1
    assert "Execution gate rejected" in emitted_errors[0][1]
    assert emitted_completes == [(target["url"], False)]

    mock_subprocess["popen"].assert_not_called()
    mock_subprocess["run"].assert_not_called()


@_requires_fastapi
def test_api_scan_endpoint_denies_out_of_scope(monkeypatch, mock_subprocess):
    """POST /api/v6/scan rejects out-of-scope scan with HTTP 403."""
    from fastapi.testclient import TestClient
    import api.server

    valid_auth = create_auth_record(scope="*.api-allowed.com")
    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )

    api.server.app.dependency_overrides[api.server._get_current_user] = lambda: "admin"
    client = TestClient(api.server.app)

    response = client.post("/api/v6/scan", json={
        "target_url": "http://evil-external.com",
        "engagement_id": "ENG-01",
    })

    assert response.status_code == 403
    assert "Execution gate rejected" in response.json()["detail"]

    mock_subprocess["popen"].assert_not_called()
    mock_subprocess["run"].assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Suite 3: Allow Path — Execution Proceeds with Valid Scope and Authorization
# ─────────────────────────────────────────────────────────────────────────────

def test_allow_path_with_valid_scope_and_auth(monkeypatch, mock_subprocess):
    """Valid target inside authorized scope with active authorization is authorized."""
    now_utc = datetime.now(timezone.utc)
    valid_auth = {
        "auth_id": "AUTH-PERMITTED",
        "engagement_id": "ENG-ALLOWED",
        "target": "target.company.com",
        "scope": "*.company.com",
        "status": "active",
        "expires_at": (now_utc + timedelta(days=2)).isoformat(),
    }

    monkeypatch.setattr(
        "tools.db_manager.get_authorizations_for_engagement",
        lambda eid: [valid_auth]
    )
    monkeypatch.setattr(
        "tools.db_manager.get_authorization",
        lambda aid: valid_auth
    )

    policy = ScanPolicy({
        "name": "AllowedPolicy",
        "engagement_id": "ENG-ALLOWED",
        "activity_level_limit": "ACTIVE",
    })

    allowed, reason = verify_scan_execution(
        target="app.company.com",
        scanner_name="httpx",
        engagement_id="ENG-ALLOWED",
        auth_id="AUTH-PERMITTED",
        scan_policy=policy,
    )

    assert allowed is True
    assert "authorized" in reason.lower()
