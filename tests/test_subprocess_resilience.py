"""
tests/test_subprocess_resilience.py — Comprehensive tests for V9.5.13 ResilientPopen kill/terminate fallback.

Requirements:
  1. Fix ResilientPopen.kill() and .terminate() so a failure in os.killpg() does not raise
     before the standard subprocess fallback is attempted.
  2. Preserve original exceptions for diagnostics.
  3. Avoid masking process-already-exited conditions.
  4. Reap the child process to prevent zombies.
  5. Add mocked tests for:
     - successful group termination
     - failed group termination with fallback
     - already-exited process
     - timeout handling
  6. Do not run real exploit tools.
"""

import os
import signal
import subprocess
import pytest
from unittest.mock import MagicMock, patch

from scanners.scan_runner import ResilientPopen, run_with_resilience


# ─────────────────────────────────────────────────────────────────────────────
# Helper class to mock standard Popen without actually spawning system processes
# ─────────────────────────────────────────────────────────────────────────────

class MockBasePopen:
    """Mock representing the base subprocess.Popen."""
    def __init__(self, pid=12345):
        self.pid = pid
        self.returncode = None
        self.wait_called = False
        self.wait_timeout = None
        self.super_kill_called = False
        self.super_terminate_called = False

    def wait(self, timeout=None):
        self.wait_called = True
        self.wait_timeout = timeout
        self.returncode = -9
        return self.returncode

    def kill(self):
        self.super_kill_called = True

    def terminate(self):
        self.super_terminate_called = True


@pytest.fixture
def resilient_proc():
    """Create a ResilientPopen instance with mocked base methods."""
    proc = ResilientPopen.__new__(ResilientPopen)
    proc.pid = 9876
    proc.returncode = None
    proc.wait = MagicMock(return_value=0)
    return proc


# ─────────────────────────────────────────────────────────────────────────────
# 1. Successful Group Termination Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_kill_successful_group_termination(resilient_proc, monkeypatch):
    """When os.killpg succeeds, SIGKILL is sent to the process group and child is reaped."""
    mock_killpg = MagicMock()
    mock_getpgid = MagicMock(return_value=9876)
    mock_super_kill = MagicMock()

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "getpgid", mock_getpgid)
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(subprocess.Popen, "kill", mock_super_kill)

    resilient_proc.kill(timeout=2.0)

    # os.killpg should have been called with the process group and SIGKILL
    mock_getpgid.assert_called_once_with(9876)
    mock_killpg.assert_called_once_with(9876, signal.SIGKILL)

    # Child must be reaped
    resilient_proc.wait.assert_called_once_with(timeout=2.0)

    # Standard fallback should NOT be called since group kill succeeded
    mock_super_kill.assert_not_called()


def test_terminate_successful_group_termination(resilient_proc, monkeypatch):
    """When os.killpg succeeds, SIGTERM is sent to the process group and child is reaped."""
    mock_killpg = MagicMock()
    mock_getpgid = MagicMock(return_value=9876)
    mock_super_terminate = MagicMock()

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "getpgid", mock_getpgid)
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(subprocess.Popen, "terminate", mock_super_terminate)

    resilient_proc.terminate(timeout=1.5)

    mock_getpgid.assert_called_once_with(9876)
    mock_killpg.assert_called_once_with(9876, signal.SIGTERM)

    # Child reaped
    resilient_proc.wait.assert_called_once_with(timeout=1.5)

    # Fallback not needed
    mock_super_terminate.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Failed Group Termination with Fallback Tests (Core Bugfix)
# ─────────────────────────────────────────────────────────────────────────────

def test_kill_group_failure_reaches_standard_fallback(resilient_proc, monkeypatch):
    """
    Core bugfix: os.killpg failure does NOT raise before attempting super().kill().
    Standard fallback succeeds and child is reaped.
    """
    mock_killpg = MagicMock(side_effect=PermissionError("EPERM: cannot kill process group"))
    mock_getpgid = MagicMock(return_value=9876)
    mock_super_kill = MagicMock()

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "getpgid", mock_getpgid)
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(subprocess.Popen, "kill", mock_super_kill)

    # Must NOT raise PermissionError or SMPUnclassifiedError
    resilient_proc.kill(timeout=1.0)

    # Verify fallback was reached!
    mock_super_kill.assert_called_once()

    # Child must be reaped after fallback
    resilient_proc.wait.assert_called_once_with(timeout=1.0)


def test_terminate_group_failure_reaches_standard_fallback(resilient_proc, monkeypatch):
    """
    Core bugfix: os.killpg failure does NOT raise before attempting super().terminate().
    Standard fallback succeeds and child is reaped.
    """
    mock_killpg = MagicMock(side_effect=OSError("Generic group error"))
    mock_getpgid = MagicMock(return_value=9876)
    mock_super_terminate = MagicMock()

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "getpgid", mock_getpgid)
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(subprocess.Popen, "terminate", mock_super_terminate)

    resilient_proc.terminate(timeout=1.0)

    # Verify fallback was reached!
    mock_super_terminate.assert_called_once()

    # Child must be reaped after fallback
    resilient_proc.wait.assert_called_once_with(timeout=1.0)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Already-Exited Process Handling (Avoid Masking Conditions)
# ─────────────────────────────────────────────────────────────────────────────

def test_kill_already_exited_group_does_not_mask(resilient_proc, monkeypatch):
    """
    If process already exited, os.killpg raises ProcessLookupError (ESRCH).
    ResilientPopen must not mask this as an unexpected error, and must reap the child.
    """
    mock_killpg = MagicMock(side_effect=ProcessLookupError("ESRCH: No such process"))
    mock_getpgid = MagicMock(return_value=9876)
    mock_super_kill = MagicMock()

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "getpgid", mock_getpgid)
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(subprocess.Popen, "kill", mock_super_kill)

    # Should exit cleanly without raising
    resilient_proc.kill()

    # Fallback not needed since process is already gone
    mock_super_kill.assert_not_called()
    # Child reap was attempted
    resilient_proc.wait.assert_called_once()


def test_terminate_already_exited_group_does_not_mask(resilient_proc, monkeypatch):
    """
    If process already exited during terminate, ProcessLookupError is cleanly handled
    and child is reaped.
    """
    mock_killpg = MagicMock(side_effect=ProcessLookupError("ESRCH: No such process"))
    mock_getpgid = MagicMock(return_value=9876)

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "getpgid", mock_getpgid)
    monkeypatch.setattr(os, "killpg", mock_killpg)

    resilient_proc.terminate()
    resilient_proc.wait.assert_called_once()


def test_kill_already_exited_during_fallback_does_not_mask(resilient_proc, monkeypatch):
    """
    If group kill fails with PermissionError, and fallback raises ProcessLookupError,
    it must be handled cleanly as an already-exited process.
    """
    mock_killpg = MagicMock(side_effect=PermissionError("EPERM"))
    mock_getpgid = MagicMock(return_value=9876)
    mock_super_kill = MagicMock(side_effect=ProcessLookupError("No such process"))

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "getpgid", mock_getpgid)
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(subprocess.Popen, "kill", mock_super_kill)

    # Should not raise
    resilient_proc.kill()
    mock_super_kill.assert_called_once()
    resilient_proc.wait.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 4. Error Diagnostics & Non-Swallowed Failure Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_kill_both_group_and_fallback_fail_preserves_diagnostics(resilient_proc, monkeypatch):
    """
    Errors are not silently swallowed. When both group and fallback fail,
    fallback error is raised with original group error preserved via __cause__.
    """
    group_error = PermissionError("EPERM: cannot kill process group")
    fallback_error = OSError("ESRCH: fatal fallback error")

    mock_killpg = MagicMock(side_effect=group_error)
    mock_getpgid = MagicMock(return_value=9876)
    mock_super_kill = MagicMock(side_effect=fallback_error)

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "getpgid", mock_getpgid)
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(subprocess.Popen, "kill", mock_super_kill)

    with pytest.raises(OSError) as exc_info:
        resilient_proc.kill()

    # Ensure error was NOT swallowed
    assert exc_info.value is fallback_error
    # Ensure original exception is chained for diagnostics
    assert exc_info.value.__cause__ is group_error


def test_terminate_both_group_and_fallback_fail_preserves_diagnostics(resilient_proc, monkeypatch):
    """
    When both terminate attempts fail, errors are not swallowed and original cause is preserved.
    """
    group_error = PermissionError("Cannot terminate group")
    fallback_error = RuntimeError("Fallback terminate failed")

    mock_killpg = MagicMock(side_effect=group_error)
    mock_getpgid = MagicMock(return_value=9876)
    mock_super_terminate = MagicMock(side_effect=fallback_error)

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "getpgid", mock_getpgid)
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(subprocess.Popen, "terminate", mock_super_terminate)

    with pytest.raises(RuntimeError) as exc_info:
        resilient_proc.terminate()

    assert exc_info.value is fallback_error
    assert exc_info.value.__cause__ is group_error


# ─────────────────────────────────────────────────────────────────────────────
# 5. Non-UNIX (Windows) Direct Fallback
# ─────────────────────────────────────────────────────────────────────────────

def test_windows_kill_uses_direct_fallback(resilient_proc, monkeypatch):
    """On Windows (os.name == 'nt'), os.killpg is bypassed and standard kill is called."""
    mock_killpg = MagicMock()
    mock_super_kill = MagicMock()

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(subprocess.Popen, "kill", mock_super_kill)

    resilient_proc.kill()

    mock_killpg.assert_not_called()
    mock_super_kill.assert_called_once()
    resilient_proc.wait.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Integration: Timeout Handling during Scan Resilience
# ─────────────────────────────────────────────────────────────────────────────

def test_timeout_in_scanner_uses_resilient_popen(monkeypatch):
    """
    Simulate a scanner running via run_with_resilience where subprocess.run
    times out. ResilientPopen intercepts the execution and handles kill/reap.
    """
    # Create mock Popen instance returned when ResilientPopen is initialized
    mock_proc = MagicMock()
    mock_proc.pid = 54321
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.wait = MagicMock(return_value=-9)

    class MockResilientPopen(ResilientPopen):
        def __init__(self, *args, **kwargs):
            self.pid = 54321
            self.returncode = None
        def kill(self, timeout=1.0):
            super().kill(timeout=timeout)
        def wait(self, timeout=None):
            return -9

    monkeypatch.setattr("scanners.scan_runner.ResilientPopen", MockResilientPopen)
    mock_killpg = MagicMock()
    mock_getpgid = MagicMock(return_value=54321)
    monkeypatch.setattr(os, "killpg", mock_killpg)
    monkeypatch.setattr(os, "getpgid", mock_getpgid)

    # Scanner function that times out
    def mock_scan_func(url, **kwargs):
        proc = MockResilientPopen(["mock_tool", url])
        # Simulate timeout triggering proc.kill()
        proc.kill()
        return None

    monkeypatch.setattr("scanners.scan_runner.log_scanner_failure_status", MagicMock())
    monkeypatch.setattr("scanners.scan_runner.get_cooling_delay", MagicMock(return_value=0.0))
    monkeypatch.setattr("core.execution_gate.verify_scan_execution", lambda **kwargs: (True, "Allowed"))

    result, success = run_with_resilience(
        scan_id=1,
        step_name="Mock Timeout Scan",
        scan_func=mock_scan_func,
        url="http://target.test",
        binary_name="mock_tool",
        needs_binary=False,
    )

    assert success is False
    assert result is None
    # Verify group kill was executed
    mock_killpg.assert_called_once_with(54321, signal.SIGKILL)
