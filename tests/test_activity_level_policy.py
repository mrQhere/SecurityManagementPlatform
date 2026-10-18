"""
Regression tests for v9.5.9 — Enforce scanner activity levels in policy.

Scenarios covered:
------------------
1. Complete 5x5 matrix test: every (configured_limit, scanner_activity) pair has an
   explicit expected decision according to the strict ranking:
     PASSIVE (1) < LOW_IMPACT_ACTIVE (2) < ACTIVE (3) < INTRUSIVE (4) < DESTRUCTIVE (5)
2. is_allowed() does not grant access based solely on target string matching when
   scanner activity exceeds policy limit.
3. Unknown scanner activity levels deny by default.
4. Unknown policy activity limits deny by default.
5. Case-insensitive string activity level resolution.
6. ScopeEngine initialization with ScanPolicy instance.
7. ScopeEngine set_policy() updates max_activity_level.
8. Per-call max_activity_level override in is_allowed().
9. check_redirect() respects activity level policy.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.scanner_manifest import ActivityLevel
from core.scan_policy import ScanPolicy
from core.scope_engine import (
    ACTIVITY_LEVEL_ORDER,
    ScopeEngine,
    ScopeRule,
    is_activity_allowed,
    resolve_activity_level,
)


ALL_LEVELS = [
    ActivityLevel.PASSIVE,
    ActivityLevel.LOW_IMPACT_ACTIVE,
    ActivityLevel.ACTIVE,
    ActivityLevel.INTRUSIVE,
    ActivityLevel.DESTRUCTIVE,
]


# ─────────────────────────────────────────────────────────────────────────────
# 1. 5x5 Activity Level Decision Matrix
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("configured_limit", ALL_LEVELS)
@pytest.mark.parametrize("scanner_activity", ALL_LEVELS)
def test_activity_level_matrix_standalone(configured_limit, scanner_activity):
    """
    Test every combination of configured_limit vs scanner_activity.
    Decision rule: allowed iff rank(scanner_activity) <= rank(configured_limit).
    """
    scanner_rank = ACTIVITY_LEVEL_ORDER[scanner_activity]
    limit_rank = ACTIVITY_LEVEL_ORDER[configured_limit]
    expected_allowed = scanner_rank <= limit_rank

    allowed, reason = is_activity_allowed(scanner_activity, configured_limit)

    assert allowed is expected_allowed
    if not expected_allowed:
        assert f"exceeds engagement policy limit '{configured_limit.value}'" in reason
    else:
        assert reason == ""


@pytest.mark.parametrize("configured_limit", ALL_LEVELS)
@pytest.mark.parametrize("scanner_activity", ALL_LEVELS)
def test_scope_engine_matrix_with_rules(configured_limit, scanner_activity):
    """
    Verify full ScopeEngine.is_allowed() enforcement across all 25 matrix combinations
    when the target is validly in-scope.
    """
    engine = ScopeEngine("matrix_eng", max_activity_level=configured_limit)
    engine.rules = [ScopeRule("R1", "domain", "target.com", "allow")]

    scanner_rank = ACTIVITY_LEVEL_ORDER[scanner_activity]
    limit_rank = ACTIVITY_LEVEL_ORDER[configured_limit]
    expected_allowed = scanner_rank <= limit_rank

    allowed, reason = engine.is_allowed("target.com", scanner_activity)

    assert allowed is expected_allowed
    if not expected_allowed:
        assert f"exceeds engagement policy limit '{configured_limit.value}'" in reason
    else:
        assert "Target allowed by rule R1" in reason


# ─────────────────────────────────────────────────────────────────────────────
# 2. Access not granted based solely on target string
# ─────────────────────────────────────────────────────────────────────────────

def test_target_in_scope_denied_when_activity_exceeds_limit():
    """
    Target strictly matches an allow rule, but scanner activity is INTRUSIVE
    while engagement policy limit is PASSIVE. Access MUST be denied.
    """
    engine = ScopeEngine("eng_strict", max_activity_level=ActivityLevel.PASSIVE)
    engine.rules = [
        ScopeRule("R_ALLOW_ALL", "domain", "in-scope.target.com", "allow", priority=100)
    ]

    # PASSIVE scanner is allowed
    allowed_passive, reason_passive = engine.is_allowed("in-scope.target.com", ActivityLevel.PASSIVE)
    assert allowed_passive is True
    assert "Target allowed" in reason_passive

    # INTRUSIVE scanner on the same target is DENIED despite matching the rule
    allowed_intrusive, reason_intrusive = engine.is_allowed("in-scope.target.com", ActivityLevel.INTRUSIVE)
    assert allowed_intrusive is False
    assert "exceeds engagement policy limit 'PASSIVE'" in reason_intrusive


# ─────────────────────────────────────────────────────────────────────────────
# 3. Unknown values denied by default
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("unknown_scanner", [
    "UNKNOWN_LEVEL",
    "SUPER_INTRUSIVE",
    "EXPLOIT",
    "",
    "   ",
    None,
    123,
    [],
    {},
])
def test_unknown_scanner_activity_denies_by_default(unknown_scanner):
    """Unknown scanner activity must be denied by default."""
    engine = ScopeEngine("eng_unknown", max_activity_level=ActivityLevel.ACTIVE)
    engine.rules = [ScopeRule("R1", "domain", "target.com", "allow")]

    allowed, reason = engine.is_allowed("target.com", unknown_scanner)
    assert allowed is False
    assert "Unknown scanner activity level" in reason
    assert "denied by default" in reason


@pytest.mark.parametrize("unknown_limit", [
    "UNRESTRICTED",
    "ROOT",
    "",
    "   ",
    None,
    456,
])
def test_unknown_policy_limit_denies_by_default(unknown_limit):
    """Unknown configured policy limit must deny all activity by default."""
    engine = ScopeEngine("eng_unknown_limit", max_activity_level=unknown_limit)
    engine.rules = [ScopeRule("R1", "domain", "target.com", "allow")]

    allowed, reason = engine.is_allowed("target.com", ActivityLevel.PASSIVE)
    assert allowed is False
    assert "Unknown policy activity level limit" in reason
    assert "denied by default" in reason


# ─────────────────────────────────────────────────────────────────────────────
# 4. String and Case-Insensitive Resolution
# ─────────────────────────────────────────────────────────────────────────────

def test_string_activity_level_resolution():
    """String values for activity levels (case-insensitive) resolve properly."""
    assert resolve_activity_level("passive") == ActivityLevel.PASSIVE
    assert resolve_activity_level("ACTIVE") == ActivityLevel.ACTIVE
    assert resolve_activity_level("low_impact_active") == ActivityLevel.LOW_IMPACT_ACTIVE
    assert resolve_activity_level("Intrusive") == ActivityLevel.INTRUSIVE
    assert resolve_activity_level("DESTRUCTIVE") == ActivityLevel.DESTRUCTIVE
    assert resolve_activity_level("nonexistent") is None


# ─────────────────────────────────────────────────────────────────────────────
# 5. Integration with ScanPolicy
# ─────────────────────────────────────────────────────────────────────────────

def test_scope_engine_with_scan_policy_instance():
    """ScopeEngine initialized with ScanPolicy enforces policy's activity_level_limit."""
    policy = ScanPolicy({
        "engagement_id": "eng_pol",
        "name": "PassiveReconPolicy",
        "activity_level_limit": ActivityLevel.PASSIVE,
    })

    engine = ScopeEngine("eng_pol", policy=policy)
    engine.rules = [ScopeRule("R1", "domain", "scan.me", "allow")]

    # Passive scanner is permitted
    allowed, _ = engine.is_allowed("scan.me", ActivityLevel.PASSIVE)
    assert allowed is True

    # Active scanner is rejected by policy limit
    allowed, reason = engine.is_allowed("scan.me", ActivityLevel.ACTIVE)
    assert allowed is False
    assert "exceeds engagement policy limit 'PASSIVE'" in reason

    # Update policy to INTRUSIVE
    policy_intrusive = ScanPolicy({
        "engagement_id": "eng_pol",
        "name": "IntrusivePolicy",
        "activity_level_limit": ActivityLevel.INTRUSIVE,
    })
    engine.set_policy(policy_intrusive)

    allowed, _ = engine.is_allowed("scan.me", ActivityLevel.ACTIVE)
    assert allowed is True
    allowed, _ = engine.is_allowed("scan.me", ActivityLevel.INTRUSIVE)
    assert allowed is True
    allowed, reason = engine.is_allowed("scan.me", ActivityLevel.DESTRUCTIVE)
    assert allowed is False


def test_per_call_max_activity_level_override():
    """is_allowed() max_activity_level parameter can override engine default."""
    engine = ScopeEngine("eng_override", max_activity_level=ActivityLevel.PASSIVE)
    engine.rules = [ScopeRule("R1", "domain", "override.com", "allow")]

    # By default, engine is PASSIVE
    allowed, _ = engine.is_allowed("override.com", ActivityLevel.ACTIVE)
    assert allowed is False

    # Explicit override allows ACTIVE
    allowed, _ = engine.is_allowed("override.com", ActivityLevel.ACTIVE, max_activity_level=ActivityLevel.ACTIVE)
    assert allowed is True


def test_check_redirect_respects_policy():
    """check_redirect() adheres to activity level enforcement."""
    engine = ScopeEngine("eng_redir", max_activity_level=ActivityLevel.PASSIVE)
    engine.rules = [ScopeRule("R1", "domain", "redirect.target.com", "allow")]

    # PASSIVE redirect is allowed
    allowed, _ = engine.check_redirect("target.com", "redirect.target.com", scanner_activity=ActivityLevel.PASSIVE)
    assert allowed is True

    # INTRUSIVE redirect is denied by policy
    allowed, reason = engine.check_redirect("target.com", "redirect.target.com", scanner_activity=ActivityLevel.INTRUSIVE)
    assert allowed is False
    assert "exceeds engagement policy limit" in reason
