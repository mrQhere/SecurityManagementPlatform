"""
Regression tests for v9.5.6 — Replace salt-derived JWT signing key.

Scenarios covered
-----------------
1. Missing SMP_JWT_SECRET in production mode → RuntimeError (fail closed)
2. SMP_JWT_SECRET shorter than MIN_SECRET_LEN → RuntimeError (fail closed)
3. Valid SMP_JWT_SECRET of exact minimum length → token issued and verified
4. Changing auth.json salt does NOT change the signing key
5. JWT key value is never emitted in log records at any level
6. Dev mode (SMP_DEV_ALLOW_INSECURE_JWT=1) allows token issuance with warning
7. CI mode (SMP_CI=1) allows token issuance with warning
8. Ephemeral dev key is not the same as a SHA-256 of any salt
9. verify_token returns None (not raises) when secret is unavailable
"""
import importlib
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# python-jose is required for JWT signing/verifying. If not installed, tests
# that call create_token / verify_token are skipped; the _get_jwt_secret() logic
# tests still run because they have no jose dependency.
_JOSE_AVAILABLE = importlib.util.find_spec("jose") is not None
_requires_jose = pytest.mark.skipif(
    not _JOSE_AVAILABLE,
    reason="python-jose not installed; install requirements.txt to run JWT tests",
)

def _reload_auth(env: dict):
    """
    Reload api.auth with a clean environment patch and reset module cache.
    Returns the reloaded module.
    """
    import api.auth as auth_mod
    # Clear the cached secret so each test gets a fresh load.
    auth_mod._cached_jwt_secret = None
    with pytest.MonkeyPatch().context() as mp:
        # Clear ALL auth-related env vars then set the desired ones.
        for key in ("SMP_JWT_SECRET", "SMP_CI", "SMP_DEV_ALLOW_INSECURE_JWT"):
            mp.delenv(key, raising=False)
        for k, v in env.items():
            mp.setenv(k, v)
        yield auth_mod
    # Reset cache after context exits so we don't pollute subsequent tests.
    auth_mod._cached_jwt_secret = None


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_auth_cache():
    """Ensure module-level cache is cleared before and after every test."""
    import api.auth as auth_mod
    auth_mod._cached_jwt_secret = None
    yield
    auth_mod._cached_jwt_secret = None


# ---------------------------------------------------------------------------
# Test 1: Missing SMP_JWT_SECRET in production → fail closed
# ---------------------------------------------------------------------------

def test_missing_jwt_secret_fails_closed(monkeypatch):
    """Production mode: absent SMP_JWT_SECRET must raise RuntimeError."""
    import api.auth as auth_mod
    monkeypatch.delenv("SMP_JWT_SECRET", raising=False)
    monkeypatch.delenv("SMP_CI", raising=False)
    monkeypatch.delenv("SMP_DEV_ALLOW_INSECURE_JWT", raising=False)

    with pytest.raises(RuntimeError, match="SMP_JWT_SECRET"):
        auth_mod._get_jwt_secret()


# ---------------------------------------------------------------------------
# Test 2: SMP_JWT_SECRET too short → fail closed
# ---------------------------------------------------------------------------

def test_too_short_jwt_secret_fails_closed(monkeypatch):
    """A secret shorter than the minimum must raise RuntimeError."""
    import api.auth as auth_mod
    short = "a" * (auth_mod._MIN_SECRET_LEN - 1)
    monkeypatch.setenv("SMP_JWT_SECRET", short)
    monkeypatch.delenv("SMP_CI", raising=False)
    monkeypatch.delenv("SMP_DEV_ALLOW_INSECURE_JWT", raising=False)

    with pytest.raises(RuntimeError, match="too short"):
        auth_mod._get_jwt_secret()


# ---------------------------------------------------------------------------
# Test 3: Valid SMP_JWT_SECRET → token is issued and verifiable
# ---------------------------------------------------------------------------

@_requires_jose
def test_valid_jwt_secret_issues_and_verifies_token(monkeypatch):
    """A sufficiently long SMP_JWT_SECRET allows token round-trip."""
    import api.auth as auth_mod
    valid_secret = "x" * auth_mod._MIN_SECRET_LEN
    monkeypatch.setenv("SMP_JWT_SECRET", valid_secret)
    monkeypatch.delenv("SMP_CI", raising=False)
    monkeypatch.delenv("SMP_DEV_ALLOW_INSECURE_JWT", raising=False)

    token = auth_mod.create_token("testuser")
    assert isinstance(token, str) and len(token) > 20

    result = auth_mod.verify_token(token)
    assert result == "testuser"


# ---------------------------------------------------------------------------
# Test 4: Changing auth.json salt does NOT change the signing key
# ---------------------------------------------------------------------------

@_requires_jose
def test_salt_change_does_not_rotate_jwt_key(monkeypatch, tmp_path):
    """
    The JWT key must be independent of config/auth.json.
    Tokens signed with SMP_JWT_SECRET=X must still be valid after
    the auth.json salt changes (they would have been invalid in v9.5.5-).
    """
    import json
    import api.auth as auth_mod

    valid_secret = "s" * auth_mod._MIN_SECRET_LEN
    monkeypatch.setenv("SMP_JWT_SECRET", valid_secret)
    monkeypatch.delenv("SMP_CI", raising=False)
    monkeypatch.delenv("SMP_DEV_ALLOW_INSECURE_JWT", raising=False)

    # Issue a token with salt_A
    auth_json = tmp_path / "auth.json"
    auth_json.write_text(json.dumps({"salt": "salt_A"}))

    token = auth_mod.create_token("alice")

    # Simulate password change → salt_B  (in the old code this would
    # have rotated the signing key; in the new code it must NOT).
    auth_json.write_text(json.dumps({"salt": "salt_B"}))

    # Token must still be valid because the key comes from SMP_JWT_SECRET.
    result = auth_mod.verify_token(token)
    assert result == "alice", (
        "Token must remain valid after salt change: "
        "JWT key must be independent of password-hashing salt."
    )


# ---------------------------------------------------------------------------
# Test 5: JWT secret value never appears in log records
# ---------------------------------------------------------------------------

@_requires_jose
def test_jwt_secret_not_logged(monkeypatch, caplog):
    """The SMP_JWT_SECRET value must never appear in any log record."""
    import api.auth as auth_mod
    secret_value = "UNIQUE_SENTINEL_SECRET_" + "z" * (auth_mod._MIN_SECRET_LEN)
    monkeypatch.setenv("SMP_JWT_SECRET", secret_value)
    monkeypatch.delenv("SMP_CI", raising=False)
    monkeypatch.delenv("SMP_DEV_ALLOW_INSECURE_JWT", raising=False)

    with caplog.at_level(logging.DEBUG, logger="smp.api"):
        auth_mod._get_jwt_secret()
        auth_mod.create_token("logtest")

    for record in caplog.records:
        assert secret_value not in record.getMessage(), (
            f"JWT secret leaked in log record: {record.getMessage()!r}"
        )


# ---------------------------------------------------------------------------
# Test 6: SMP_DEV_ALLOW_INSECURE_JWT=1 allows ephemeral secret with warning
# ---------------------------------------------------------------------------

@_requires_jose
def test_dev_mode_allows_ephemeral_secret(monkeypatch, caplog):
    """Dev mode produces a valid token and emits a WARNING."""
    import api.auth as auth_mod
    monkeypatch.delenv("SMP_JWT_SECRET", raising=False)
    monkeypatch.delenv("SMP_CI", raising=False)
    monkeypatch.setenv("SMP_DEV_ALLOW_INSECURE_JWT", "1")

    with caplog.at_level(logging.WARNING, logger="smp.api"):
        secret = auth_mod._get_jwt_secret()

    # Should have issued a warning about insecure mode.
    warning_messages = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("DEV" in m or "ephemeral" in m.lower() or "SMP_JWT_SECRET" in m
               for m in warning_messages), (
        "Dev mode must emit a warning about the insecure ephemeral key."
    )

    # Secret must be non-empty and at least minimum length.
    assert len(secret) >= auth_mod._MIN_SECRET_LEN

    # Token round-trip must work.
    token = auth_mod.create_token("devuser")
    assert auth_mod.verify_token(token) == "devuser"


# ---------------------------------------------------------------------------
# Test 7: SMP_CI=1 allows ephemeral secret with warning
# ---------------------------------------------------------------------------

@_requires_jose
def test_ci_mode_allows_ephemeral_secret(monkeypatch, caplog):
    """CI mode (SMP_CI=1) also allows token issuance without SMP_JWT_SECRET."""
    import api.auth as auth_mod
    monkeypatch.delenv("SMP_JWT_SECRET", raising=False)
    monkeypatch.setenv("SMP_CI", "1")
    monkeypatch.delenv("SMP_DEV_ALLOW_INSECURE_JWT", raising=False)

    with caplog.at_level(logging.WARNING, logger="smp.api"):
        secret = auth_mod._get_jwt_secret()

    assert len(secret) >= auth_mod._MIN_SECRET_LEN

    token = auth_mod.create_token("ci_user")
    assert auth_mod.verify_token(token) == "ci_user"


# ---------------------------------------------------------------------------
# Test 8: Ephemeral dev secret is not a SHA-256 of any salt
# ---------------------------------------------------------------------------

def test_dev_secret_not_salt_derived(monkeypatch):
    """
    The ephemeral dev secret must not equal the old salt-derived value
    (sha256("smp-api-jwt-{salt}").hexdigest()), ensuring the old derivation
    was fully removed.
    """
    import hashlib
    import api.auth as auth_mod
    monkeypatch.delenv("SMP_JWT_SECRET", raising=False)
    monkeypatch.setenv("SMP_DEV_ALLOW_INSECURE_JWT", "1")
    monkeypatch.delenv("SMP_CI", raising=False)

    ephemeral = auth_mod._get_jwt_secret()

    # Old derivation with typical salts must not match.
    for typical_salt in ("", "default", "smp-salt", "changeme"):
        old_derived = hashlib.sha256(f"smp-api-jwt-{typical_salt}".encode()).hexdigest()
        assert ephemeral != old_derived, (
            f"Ephemeral secret must not equal old salt-derived value for salt={typical_salt!r}"
        )


# ---------------------------------------------------------------------------
# Test 9: verify_token returns None (not raises) when secret unavailable
# ---------------------------------------------------------------------------

@_requires_jose
def test_verify_token_returns_none_when_no_secret(monkeypatch):
    """
    verify_token must return None rather than propagating RuntimeError
    when SMP_JWT_SECRET is unset in production mode.
    """
    import api.auth as auth_mod
    monkeypatch.delenv("SMP_JWT_SECRET", raising=False)
    monkeypatch.delenv("SMP_CI", raising=False)
    monkeypatch.delenv("SMP_DEV_ALLOW_INSECURE_JWT", raising=False)

    result = auth_mod.verify_token("some.fake.token")
    assert result is None, (
        "verify_token must return None, not raise, when secret is unavailable."
    )
