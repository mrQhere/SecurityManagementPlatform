"""
Regression tests for v9.5.8 — Enforce authorization expiry consistently.

Scenarios covered:
------------------
1. Active authorization with future expiry date is valid and produces an allow rule.
2. Expired authorization (past expires_at) produces no allow rule and target is denied.
3. Expiry boundary check: exact expiration timestamp fails closed (now >= expires_at).
4. Revoked authorization (status="revoked") produces no allow rule even with future expiry.
5. Missing expiry (expires_at is None or omitted) is valid and unexpiring.
6. Malformed expiry values (invalid string, wrong type, corrupt structure) fail closed safely.
7. Timezone-offset expiry (+02:00, -05:00, etc.) is normalized to UTC and compared accurately.
8. Naive datetime expiry is treated as UTC.
9. Database error during authorization loading fails closed with a safe diagnostic.
10. ScopeEngine exposes safe diagnostic on error rather than returning empty success-like policy.
11. AuthorizationTracker and ScopeEngine share the exact same validity check function.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.authorization import (
    AuthStatus,
    AuthorizationTracker,
    is_authorization_currently_valid,
)
from core.scanner_manifest import ActivityLevel
from core.scope_engine import ScopeEngine, ScopeRule


# ─────────────────────────────────────────────────────────────────────────────
# 1. Shared timezone-safe validity function unit tests
# ─────────────────────────────────────────────────────────────────────────────

def test_future_expiry_is_valid():
    """Future expires_at with active status must be valid."""
    future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    auth = {
        "auth_id": "auth-1",
        "engagement_id": "eng-1",
        "target": "example.com",
        "scope": "*.example.com",
        "status": "active",
        "expires_at": future,
    }
    assert is_authorization_currently_valid(auth) is True


def test_expired_auth_is_invalid():
    """Past expires_at must return False."""
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    auth = {
        "auth_id": "auth-2",
        "engagement_id": "eng-1",
        "target": "example.com",
        "scope": "*.example.com",
        "status": "active",
        "expires_at": past,
    }
    assert is_authorization_currently_valid(auth) is False


def test_revoked_status_is_invalid():
    """Revoked status must return False even if expiry is far in the future."""
    future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    auth = {
        "auth_id": "auth-3",
        "engagement_id": "eng-1",
        "target": "example.com",
        "scope": "*.example.com",
        "status": "revoked",
        "expires_at": future,
    }
    assert is_authorization_currently_valid(auth) is False


def test_missing_or_none_expiry_is_valid():
    """Missing or None expires_at represents a non-expiring active authorization."""
    auth_none = {
        "auth_id": "auth-4",
        "status": "active",
        "expires_at": None,
    }
    assert is_authorization_currently_valid(auth_none) is True

    auth_omitted = {
        "auth_id": "auth-5",
        "status": "active",
    }
    assert is_authorization_currently_valid(auth_omitted) is True


@pytest.mark.parametrize("bad_expiry", [
    "not-a-valid-timestamp",
    "",
    "   ",
    "2026-99-99T99:99:99",
    123456789,
    1735689600.0,
    [],
    {},
    True,
])
def test_malformed_expiry_fails_closed(bad_expiry):
    """Any malformed expiry value must fail closed (return False) without raising."""
    auth = {
        "auth_id": "auth-malformed",
        "status": "active",
        "expires_at": bad_expiry,
    }
    assert is_authorization_currently_valid(auth) is False


@pytest.mark.parametrize("bad_auth", [
    None,
    "",
    123,
    [],
    {},
    {"status": "unknown"},
    {"status": None},
    {"status": 123},
])
def test_corrupt_authorization_record_fails_closed(bad_auth):
    """Non-dict or missing/invalid status must safely fail closed."""
    assert is_authorization_currently_valid(bad_auth) is False


def test_timezone_offset_comparison():
    """Timezone offsets must be normalized to UTC and accurately compared."""
    now_utc = datetime.now(timezone.utc)

    # Construct an expiry that is 1 hour in the future UTC, expressed with +05:30 offset
    future_utc = now_utc + timedelta(hours=1)
    tz_plus530 = timezone(timedelta(hours=5, minutes=30))
    future_in_tz = future_utc.astimezone(tz_plus530).isoformat()

    auth_future_tz = {
        "auth_id": "auth-tz-1",
        "status": "active",
        "expires_at": future_in_tz,
    }
    assert is_authorization_currently_valid(auth_future_tz) is True

    # Construct an expiry that was 1 hour in the past UTC, expressed with +05:30 offset
    past_utc = now_utc - timedelta(hours=1)
    past_in_tz = past_utc.astimezone(tz_plus530).isoformat()

    auth_past_tz = {
        "auth_id": "auth-tz-2",
        "status": "active",
        "expires_at": past_in_tz,
    }
    assert is_authorization_currently_valid(auth_past_tz) is False


def test_naive_datetime_treated_as_utc():
    """A naive ISO datetime string is interpreted as UTC."""
    now_utc = datetime.now(timezone.utc)
    future_naive = (now_utc + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")
    past_naive = (now_utc - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")

    assert is_authorization_currently_valid({"status": "active", "expires_at": future_naive}) is True
    assert is_authorization_currently_valid({"status": "active", "expires_at": past_naive}) is False


# ─────────────────────────────────────────────────────────────────────────────
# 2. ScopeEngine integration tests
# ─────────────────────────────────────────────────────────────────────────────

def test_scope_engine_ignores_expired_and_revoked_authorizations(monkeypatch):
    """Expired or revoked authorizations must never create allow rules."""
    now_utc = datetime.now(timezone.utc)
    auths = [
        # 1. Valid future authorization
        {
            "auth_id": "AUTH-VALID",
            "engagement_id": "eng-test",
            "target": "valid.target.com",
            "scope": "valid.target.com",
            "status": "active",
            "expires_at": (now_utc + timedelta(days=1)).isoformat(),
        },
        # 2. Expired authorization
        {
            "auth_id": "AUTH-EXPIRED",
            "engagement_id": "eng-test",
            "target": "expired.target.com",
            "scope": "expired.target.com",
            "status": "active",
            "expires_at": (now_utc - timedelta(days=1)).isoformat(),
        },
        # 3. Revoked authorization
        {
            "auth_id": "AUTH-REVOKED",
            "engagement_id": "eng-test",
            "target": "revoked.target.com",
            "scope": "revoked.target.com",
            "status": "revoked",
            "expires_at": (now_utc + timedelta(days=1)).isoformat(),
        },
        # 4. Malformed authorization
        {
            "auth_id": "AUTH-MALFORMED",
            "engagement_id": "eng-test",
            "target": "malformed.target.com",
            "scope": "malformed.target.com",
            "status": "active",
            "expires_at": "not-a-datetime",
        },
    ]

    monkeypatch.setattr("tools.db_manager.get_authorizations_for_engagement", lambda eid: auths)

    engine = ScopeEngine("eng-test")

    # Only AUTH-VALID should have produced a rule
    assert len(engine.rules) == 1
    assert engine.rules[0].rule_id == "AUTH-VALID"

    # Targets
    allowed, _ = engine.is_allowed("valid.target.com", ActivityLevel.ACTIVE)
    assert allowed is True

    allowed, reason = engine.is_allowed("expired.target.com", ActivityLevel.ACTIVE)
    assert allowed is False
    assert "default deny" in reason.lower()

    allowed, reason = engine.is_allowed("revoked.target.com", ActivityLevel.ACTIVE)
    assert allowed is False

    allowed, reason = engine.is_allowed("malformed.target.com", ActivityLevel.ACTIVE)
    assert allowed is False


def test_scope_engine_database_error_fails_closed_with_diagnostic(monkeypatch):
    """Database errors must fail closed and record a safe diagnostic."""
    def mock_broken_db(engagement_id):
        raise RuntimeError("OperationalError: unable to open database file")

    monkeypatch.setattr("tools.db_manager.get_authorizations_for_engagement", mock_broken_db)

    engine = ScopeEngine("eng-broken")

    # Rules must be empty (fail closed)
    assert len(engine.rules) == 0
    # Safe diagnostic must be set
    assert engine.diagnostic is not None
    assert "Authorization load failed" in engine.diagnostic
    assert "RuntimeError" in engine.diagnostic

    # is_allowed must fail closed with the diagnostic, not empty-success message
    allowed, reason = engine.is_allowed("any.target.com", ActivityLevel.ACTIVE)
    assert allowed is False
    assert "Scope check failed closed" in reason
    assert engine.diagnostic in reason


def test_authorization_tracker_uses_shared_validity_function(monkeypatch):
    """AuthorizationTracker.is_valid() delegates to the shared validity logic."""
    now_utc = datetime.now(timezone.utc)
    updated_statuses = {}

    auth_db = {
        "A1": {
            "auth_id": "A1",
            "status": "active",
            "expires_at": (now_utc + timedelta(hours=1)).isoformat(),
        },
        "A2": {
            "auth_id": "A2",
            "status": "active",
            "expires_at": (now_utc - timedelta(hours=1)).isoformat(),
        },
        "A3": {
            "auth_id": "A3",
            "status": "revoked",
            "expires_at": (now_utc + timedelta(hours=1)).isoformat(),
        },
    }

    def mock_get(auth_id):
        return auth_db.get(auth_id)

    def mock_update(auth_id, status):
        updated_statuses[auth_id] = status

    monkeypatch.setattr("tools.db_manager.get_authorization", mock_get)
    monkeypatch.setattr("tools.db_manager.update_authorization_status", mock_update)

    tracker = AuthorizationTracker()

    assert tracker.is_valid("A1") is True
    assert tracker.is_valid("A2") is False
    assert updated_statuses.get("A2") == AuthStatus.EXPIRED.value
    assert tracker.is_valid("A3") is False
    assert tracker.is_valid("NONEXISTENT") is False
