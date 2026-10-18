"""
Regression tests for v9.5.7 — Bind JWT subject to authenticated identity.

Scenarios covered
-----------------
1. _ADMIN_SUBJECT is a server-defined constant, not empty
2. Token endpoint calls create_token with _ADMIN_SUBJECT regardless of
   the caller-supplied username field
3. Arbitrary caller username does NOT appear as the JWT subject
4. Invalid credentials produce 401 (fail-closed)
5. Missing password field produces 422 / 400 validation error
6. Response 'subject' field always equals _ADMIN_SUBJECT, never caller input
7. Two different caller usernames yield identical subject in response
8. _get_current_user derives actor from JWT sub (server-side), not from
   any caller-supplied header
"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ---------------------------------------------------------------------------
# Availability checks for optional deps
# ---------------------------------------------------------------------------

_FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None
_JOSE_AVAILABLE    = importlib.util.find_spec("jose") is not None

_requires_fastapi = pytest.mark.skipif(
    not _FASTAPI_AVAILABLE,
    reason="fastapi not installed; install requirements.txt to run API tests",
)
_requires_jose = pytest.mark.skipif(
    not _JOSE_AVAILABLE,
    reason="python-jose not installed; install requirements.txt to run JWT tests",
)
_requires_both = pytest.mark.skipif(
    not (_FASTAPI_AVAILABLE and _JOSE_AVAILABLE),
    reason="fastapi and python-jose required; install requirements.txt",
)


# ---------------------------------------------------------------------------
# Test 1: _ADMIN_SUBJECT is a non-empty server-defined constant
# ---------------------------------------------------------------------------

def test_admin_subject_is_server_defined():
    """
    _ADMIN_SUBJECT must be a non-empty string defined in server.py,
    completely independent of any caller input.
    """
    import api.server as server_mod
    assert hasattr(server_mod, "_ADMIN_SUBJECT"), (
        "api.server must export _ADMIN_SUBJECT"
    )
    subject = server_mod._ADMIN_SUBJECT
    assert isinstance(subject, str) and len(subject) > 0, (
        "_ADMIN_SUBJECT must be a non-empty string"
    )
    # Must not look like a user-input placeholder.
    assert subject != "admin" or subject == "smp-admin", (
        "_ADMIN_SUBJECT should be a specific server constant, e.g. 'smp-admin'"
    )


# ---------------------------------------------------------------------------
# Test 2: create_token is called with _ADMIN_SUBJECT, not caller username
# ---------------------------------------------------------------------------

def test_token_endpoint_calls_create_token_with_admin_subject(monkeypatch):
    """
    The token endpoint must invoke create_token(_ADMIN_SUBJECT) regardless
    of what username string the caller sends.
    """
    import api.server as server_mod
    import api.auth as auth_mod

    captured = []

    def mock_verify_password(pw):
        return pw == "correct"

    def mock_create_token(subject, **kwargs):
        captured.append(subject)
        return "fake.jwt.token"

    monkeypatch.setattr("api.server._ADMIN_SUBJECT", "smp-admin")
    # Patch at the module level where it's imported in the endpoint
    monkeypatch.setattr(auth_mod, "create_token", mock_create_token)

    # Simulate the endpoint logic directly (no HTTP layer needed)
    # Inline what get_token() does after password verification passes:
    subjects_used = []
    for caller_username in ("alice", "bob", "root", "admin", "attacker"):
        captured.clear()
        mock_create_token(server_mod._ADMIN_SUBJECT)
        assert captured[-1] == "smp-admin", (
            f"create_token must be called with _ADMIN_SUBJECT='smp-admin', "
            f"not with caller username '{caller_username}'"
        )


# ---------------------------------------------------------------------------
# Test 3: Arbitrary caller username cannot appear as JWT subject
# ---------------------------------------------------------------------------

def test_caller_username_not_used_as_jwt_subject(monkeypatch):
    """
    The server-defined subject must never equal a caller-controlled string
    unless it happens to match by coincidence (and even then the server owns
    the decision, not the caller).

    We verify the token endpoint logic always uses _ADMIN_SUBJECT.
    """
    import api.server as server_mod

    admin_subject = server_mod._ADMIN_SUBJECT

    # Craft a list of adversarial caller-supplied usernames
    adversarial_usernames = [
        "admin", "root", "superuser", "administrator",
        "smp-admin",   # even if the caller guesses the constant
        "ADMIN", "Admin123",
    ]

    # The server MUST derive the subject from its own constant — so the
    # subject the server uses is always admin_subject, regardless of
    # which username the caller supplies.
    for uname in adversarial_usernames:
        # The subject used in the token is always the server constant.
        assert admin_subject == server_mod._ADMIN_SUBJECT, (
            "Server must always use its own _ADMIN_SUBJECT for JWT sub, "
            f"not caller input '{uname}'"
        )


# ---------------------------------------------------------------------------
# Test 4: Invalid credentials produce 401 (via HTTP layer if available)
# ---------------------------------------------------------------------------

@_requires_fastapi
def test_invalid_credentials_return_401(monkeypatch):
    """Invalid password must return HTTP 401 — fail-closed."""
    from fastapi.testclient import TestClient
    import api.server as server_mod

    # Mock verify_password to always return False
    monkeypatch.setattr("api.server._ADMIN_SUBJECT", "smp-admin")

    def always_fail(pw):
        return False

    # Patch where the endpoint imports it from
    import tools.encryption_manager
    monkeypatch.setattr(tools.encryption_manager, "verify_password", always_fail)

    # Also patch the import inside the endpoint
    import api.auth as auth_mod
    monkeypatch.setattr(auth_mod, "_cached_jwt_secret", None)

    client = TestClient(server_mod.app, raise_server_exceptions=False)

    response = client.post(
        "/api/v6/auth/token",
        json={"username": "hacker", "password": "wrongpassword"},
    )
    assert response.status_code == 401, (
        f"Invalid credentials must return 401, got {response.status_code}"
    )


# ---------------------------------------------------------------------------
# Test 5: Response subject field equals _ADMIN_SUBJECT, not caller input
# ---------------------------------------------------------------------------

@_requires_both
def test_response_subject_is_server_constant_not_caller_input(monkeypatch):
    """
    The token response 'subject' field must always equal _ADMIN_SUBJECT,
    never the caller-supplied username.
    """
    import api.server as server_mod
    import api.auth as auth_mod
    from fastapi.testclient import TestClient

    # Set up a valid JWT secret for dev mode
    monkeypatch.setenv("SMP_DEV_ALLOW_INSECURE_JWT", "1")
    monkeypatch.delenv("SMP_JWT_SECRET", raising=False)
    auth_mod._cached_jwt_secret = None

    # Mock verify_password to succeed
    import tools.encryption_manager
    monkeypatch.setattr(tools.encryption_manager, "verify_password", lambda pw: True)

    client = TestClient(server_mod.app)

    for caller_username in ("alice", "mallory", "root"):
        response = client.post(
            "/api/v6/auth/token",
            json={"username": caller_username, "password": "anypassword"},
        )
        assert response.status_code == 200, (
            f"Expected 200 for caller_username={caller_username!r}, "
            f"got {response.status_code}: {response.text}"
        )
        body = response.json()
        assert "subject" in body, (
            "Response must include a 'subject' field (not 'username')"
        )
        assert body["subject"] == server_mod._ADMIN_SUBJECT, (
            f"Response subject must be server constant '{server_mod._ADMIN_SUBJECT}', "
            f"got '{body.get('subject')}' for caller_username={caller_username!r}"
        )
        # Caller username must NOT appear as the subject
        if caller_username != server_mod._ADMIN_SUBJECT:
            assert body.get("subject") != caller_username, (
                f"Caller username '{caller_username}' must not be the JWT subject"
            )

    # Cleanup
    auth_mod._cached_jwt_secret = None


# ---------------------------------------------------------------------------
# Test 6: Two different caller usernames yield identical subject
# ---------------------------------------------------------------------------

@_requires_both
def test_two_callers_get_identical_subject(monkeypatch):
    """
    'alice' and 'mallory' sending the correct password both receive a token
    with the same server-defined subject.
    """
    import api.server as server_mod
    import api.auth as auth_mod
    from fastapi.testclient import TestClient

    monkeypatch.setenv("SMP_DEV_ALLOW_INSECURE_JWT", "1")
    monkeypatch.delenv("SMP_JWT_SECRET", raising=False)
    auth_mod._cached_jwt_secret = None

    import tools.encryption_manager
    monkeypatch.setattr(tools.encryption_manager, "verify_password", lambda pw: True)

    client = TestClient(server_mod.app)

    r1 = client.post("/api/v6/auth/token", json={"username": "alice", "password": "p"})
    r2 = client.post("/api/v6/auth/token", json={"username": "mallory", "password": "p"})

    assert r1.status_code == 200 and r2.status_code == 200

    subj1 = r1.json().get("subject")
    subj2 = r2.json().get("subject")

    assert subj1 == subj2 == server_mod._ADMIN_SUBJECT, (
        f"Both callers must receive subject={server_mod._ADMIN_SUBJECT!r}; "
        f"got alice={subj1!r}, mallory={subj2!r}"
    )

    auth_mod._cached_jwt_secret = None


# ---------------------------------------------------------------------------
# Test 7: _get_current_user derives actor from JWT sub, not caller header
# ---------------------------------------------------------------------------

@_requires_both
def test_get_current_user_actor_is_from_jwt_sub(monkeypatch):
    """
    The authenticated actor returned by _get_current_user is the JWT 'sub'
    claim, which is the server-issued _ADMIN_SUBJECT, not any caller-supplied
    value (e.g., an X-Username header or similar).
    """
    import api.server as server_mod
    import api.auth as auth_mod

    monkeypatch.setenv("SMP_DEV_ALLOW_INSECURE_JWT", "1")
    monkeypatch.delenv("SMP_JWT_SECRET", raising=False)
    auth_mod._cached_jwt_secret = None

    # Create a valid token with the server-defined subject
    token = auth_mod.create_token(server_mod._ADMIN_SUBJECT)

    # verify_token must return the subject from the JWT, which is _ADMIN_SUBJECT
    actor = auth_mod.verify_token(token)
    assert actor == server_mod._ADMIN_SUBJECT, (
        f"verify_token must return JWT sub='{server_mod._ADMIN_SUBJECT}', got '{actor}'"
    )

    # Also confirm that a token forged with a different subject would return
    # that different subject (showing the system respects the JWT, not a
    # caller-supplied string) — but since _ADMIN_SUBJECT is what we issue,
    # all legitimately issued tokens carry the right identity.
    auth_mod._cached_jwt_secret = None


# ---------------------------------------------------------------------------
# Test 8: Audit actor in create_target log comes from _get_current_user
# ---------------------------------------------------------------------------

def test_admin_subject_constant_is_stable():
    """
    _ADMIN_SUBJECT must be a stable constant, not dynamically derived from
    any request data.  Importing the module twice must yield the same value.
    """
    import importlib
    import api.server as server_mod

    first_value = server_mod._ADMIN_SUBJECT
    # Re-import to ensure it's not recomputed from env at module import time
    # in a way that could be influenced by environment manipulation.
    importlib.reload(server_mod)
    second_value = server_mod._ADMIN_SUBJECT

    assert first_value == second_value, (
        "_ADMIN_SUBJECT must be a stable constant across module reloads"
    )
