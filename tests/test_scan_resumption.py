"""
tests/test_scan_resumption.py — Comprehensive tests for V9.5.12 Scan Resumption and Terminal-State Recovery.

Requirements:
  1. Define scan terminal states centrally and exclude Cancelled along with all other terminal statuses.
  2. Resume only states explicitly classified as recoverable after an unclean shutdown.
  3. Database-backed tests for every terminal and recoverable state, including unknown/corrupt statuses.
  4. Cancelled scans remain cancelled after startup; unknown states must not trigger a scan automatically.
"""

import os
import sqlite3
import pytest
from unittest.mock import MagicMock, patch

from core.state_machine import (
    ScannerState,
    StateMachine,
    TERMINAL_SCANNER_STATES,
    TERMINAL_SCAN_STATUSES,
    RECOVERABLE_IN_FLIGHT_STATUSES,
    is_terminal_status,
    is_recoverable_status,
)
from scanners.scan_runner import resume_interrupted_scans, _active_scans, _active_urls


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures for isolated database testing
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """
    Creates an isolated SQLite test database with targets and scans schema.
    Redirects tools.db_manager.get_db_connection to this database.
    """
    db_file = str(tmp_path / "test_security.db")
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'Enabled',
            added_date TEXT NOT NULL,
            last_scan TEXT,
            company_name TEXT,
            submitted_to TEXT,
            is_deleted INTEGER DEFAULT 0,
            deleted_at TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            status TEXT NOT NULL,
            scanned_by TEXT,
            scanner_status TEXT,
            report_hash TEXT,
            FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
        );
    """)

    # Insert a standard default target
    cursor.execute(
        "INSERT INTO targets (id, url, status, added_date) VALUES (1, 'http://target.test', 'Enabled', '2026-10-18 10:00:00')"
    )
    conn.commit()
    conn.close()

    def _get_test_conn():
        c = sqlite3.connect(db_file)
        c.row_factory = sqlite3.Row
        return c

    monkeypatch.setattr("tools.db_manager.get_db_connection", _get_test_conn)
    monkeypatch.setattr("scanners.scan_runner.get_db_connection", _get_test_conn)

    # Clear active scans tracking dictionaries before/after test
    _active_scans.clear()
    _active_urls.clear()

    yield db_file

    _active_scans.clear()
    _active_urls.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Unit Tests for State Machine Central Classification
# ─────────────────────────────────────────────────────────────────────────────

ALL_TERMINAL_TEST_STATUSES = [
    "Cancelled",
    "CANCELLED",
    "Canceled",
    "CANCELED",
    "Completed",
    "COMPLETED",
    "Completed with Findings",
    "COMPLETED_WITH_FINDINGS",
    "Completed no Findings",
    "COMPLETED_NO_FINDINGS",
    "Failed",
    "FAILED",
    "Timeout",
    "TIMEOUT",
    "Blocked",
    "BLOCKED",
    "Dependency Missing",
    "DEPENDENCY_MISSING",
    "Parse Failed",
    "PARSE_FAILED",
    "Partial",
    "PARTIAL",
    "Skipped",
    "SKIPPED",
    "Report Pending",
    "REPORT PENDING",
    "REPORT_PENDING",
]

ALL_RECOVERABLE_TEST_STATUSES = [
    "Running HTTPx",
    "Running WhatWeb",
    "Running Subfinder",
    "Running Nmap",
    "Running Nuclei",
    "Running ffuf",
    "Running ZAP",
    "Running SQLMap",
    "Running Tech Fingerprint",
    "Correlating CVEs",
    "Started",
    "Running",
    "Pending",
    "STARTED",
    "RUNNING",
    "PENDING",
]

ALL_UNKNOWN_OR_CORRUPT_STATUSES = [
    "Unknown",
    "Corrupt",
    "UNKNOWN",
    "CORRUPT",
    "invalid_state",
    "error",
    "RandomString123",
    "undefined",
    "",
    "   ",
    None,
]


@pytest.mark.parametrize("status", ALL_TERMINAL_TEST_STATUSES)
def test_terminal_statuses_recognized(status):
    """Every terminal status is identified by is_terminal_status() and rejected by is_recoverable_status()."""
    assert is_terminal_status(status) is True
    assert is_recoverable_status(status) is False


@pytest.mark.parametrize("status", ALL_RECOVERABLE_TEST_STATUSES)
def test_recoverable_statuses_recognized(status):
    """Every active in-flight status is identified as recoverable and not terminal."""
    assert is_recoverable_status(status) is True
    assert is_terminal_status(status) is False


@pytest.mark.parametrize("status", ALL_UNKNOWN_OR_CORRUPT_STATUSES)
def test_unknown_corrupt_statuses_rejected(status):
    """Unknown or corrupt statuses are neither valid terminal nor recoverable (fail closed)."""
    assert is_recoverable_status(status) is False


def test_state_machine_terminal_states_consistency():
    """Verify StateMachine.is_terminal() accurately tracks TERMINAL_SCANNER_STATES."""
    for state in ScannerState:
        sm = StateMachine(state)
        if state in TERMINAL_SCANNER_STATES:
            assert sm.is_terminal() is True
        else:
            assert sm.is_terminal() is False


# ─────────────────────────────────────────────────────────────────────────────
# 2. Database-Backed Tests for Terminal States (Never Resumed)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("status", ALL_TERMINAL_TEST_STATUSES)
def test_database_terminal_state_never_resumes(test_db, monkeypatch, status):
    """
    Scans in any terminal state (including Cancelled, Completed, Failed, Report Pending)
    must never be auto-resumed on startup and must remain in their original status.
    """
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (id, target_id, start_time, status) VALUES (101, 1, '2026-10-18 10:00:00', ?)",
        (status,)
    )
    conn.commit()
    conn.close()

    mock_process = MagicMock()
    mock_process_class = MagicMock(return_value=mock_process)
    monkeypatch.setattr("multiprocessing.Process", mock_process_class)

    resumed = resume_interrupted_scans()

    # Assert: No process spawned, scan ID not returned as resumed
    assert 101 not in resumed
    mock_process_class.assert_not_called()
    mock_process.start.assert_not_called()

    # Assert: Database record was NOT modified and remains in its terminal status
    conn = sqlite3.connect(test_db)
    row = conn.execute("SELECT status FROM scans WHERE id = 101").fetchone()
    conn.close()
    assert row[0] == status


def test_cancelled_scan_specifically_remains_cancelled(test_db, monkeypatch):
    """
    Explicit regression test for Acceptance Check:
    A cancelled scan remains cancelled after startup; no background execution begins.
    """
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (id, target_id, start_time, status) VALUES (42, 1, '2026-10-18 09:30:00', 'Cancelled')"
    )
    conn.commit()
    conn.close()

    mock_process = MagicMock()
    mock_process_class = MagicMock(return_value=mock_process)
    monkeypatch.setattr("multiprocessing.Process", mock_process_class)

    resumed = resume_interrupted_scans()

    assert resumed == []
    mock_process.start.assert_not_called()

    # Verify status in database
    conn = sqlite3.connect(test_db)
    status_in_db = conn.execute("SELECT status FROM scans WHERE id = 42").fetchone()[0]
    conn.close()
    assert status_in_db == "Cancelled"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Database-Backed Tests for Unknown & Corrupt Statuses (Fail Closed)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("status", [s for s in ALL_UNKNOWN_OR_CORRUPT_STATUSES if s is not None])
def test_database_unknown_corrupt_status_never_resumes(test_db, monkeypatch, status):
    """Unknown, corrupted, or blank statuses must fail closed and never trigger a scan."""
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (id, target_id, start_time, status) VALUES (202, 1, '2026-10-18 10:00:00', ?)",
        (status,)
    )
    conn.commit()
    conn.close()

    mock_process = MagicMock()
    mock_process_class = MagicMock(return_value=mock_process)
    monkeypatch.setattr("multiprocessing.Process", mock_process_class)

    resumed = resume_interrupted_scans()

    assert 202 not in resumed
    mock_process.start.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# 4. Database-Backed Tests for Recoverable States (Resume Correctly)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("status", [
    "Running HTTPx",
    "Running Nmap",
    "Running Nuclei",
    "Correlating CVEs",
    "Started",
    "Running",
])
def test_database_recoverable_state_resumes(test_db, monkeypatch, status):
    """Scans in explicitly recoverable states resume and spawn scanner execution."""
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (id, target_id, start_time, status) VALUES (303, 1, '2026-10-18 10:00:00', ?)",
        (status,)
    )
    conn.commit()
    conn.close()

    mock_process = MagicMock()
    mock_process_class = MagicMock(return_value=mock_process)
    monkeypatch.setattr("multiprocessing.Process", mock_process_class)

    mock_thread = MagicMock()
    monkeypatch.setattr("threading.Thread", MagicMock(return_value=mock_thread))

    resumed = resume_interrupted_scans()

    assert 303 in resumed
    mock_process_class.assert_called_once()
    mock_process.start.assert_called_once()
    mock_thread.start.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 5. Startup Multi-Scan Mixed Recovery Scenario
# ─────────────────────────────────────────────────────────────────────────────

def test_startup_mixed_database_recovery_scenario(test_db, monkeypatch):
    """
    Realistic startup test with mixed database records:
      Scan 1: Cancelled by user      -> Must NOT resume (remains Cancelled)
      Scan 2: Completed normally     -> Must NOT resume (remains Completed)
      Scan 3: Failed                 -> Must NOT resume (remains Failed)
      Scan 4: Report Pending         -> Must NOT resume (remains Report Pending)
      Scan 5: Corrupt status         -> Must NOT resume (fails closed)
      Scan 6: Interrupted at Nmap    -> MUST resume
      Scan 7: Interrupted at HTTPx   -> MUST resume
    """
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()

    # Create distinct targets for each scan
    for tid in range(2, 8):
        cursor.execute(
            "INSERT INTO targets (id, url, status, added_date) VALUES (?, ?, 'Enabled', '2026-10-18 10:00:00')",
            (tid, f"http://target{tid}.test")
        )

    scans_data = [
        (1, 1, "Cancelled"),
        (2, 2, "Completed"),
        (3, 3, "Failed"),
        (4, 4, "Report Pending"),
        (5, 5, "UNKNOWN_GARBAGE"),
        (6, 6, "Running Nmap"),
        (7, 7, "Running HTTPx"),
    ]

    for sid, tid, st in scans_data:
        cursor.execute(
            "INSERT INTO scans (id, target_id, start_time, status) VALUES (?, ?, '2026-10-18 10:00:00', ?)",
            (sid, tid, st)
        )
    conn.commit()
    conn.close()

    mock_process = MagicMock()
    mock_process_class = MagicMock(return_value=mock_process)
    monkeypatch.setattr("multiprocessing.Process", mock_process_class)

    mock_thread = MagicMock()
    monkeypatch.setattr("threading.Thread", MagicMock(return_value=mock_thread))

    resumed_ids = resume_interrupted_scans()

    # Only scans 6 and 7 should be resumed
    assert sorted(resumed_ids) == [6, 7]
    assert mock_process.start.call_count == 2

    # Verify all non-resumed statuses in database remain untouched
    conn = sqlite3.connect(test_db)
    statuses = dict(conn.execute("SELECT id, status FROM scans").fetchall())
    conn.close()

    assert statuses[1] == "Cancelled"
    assert statuses[2] == "Completed"
    assert statuses[3] == "Failed"
    assert statuses[4] == "Report Pending"
    assert statuses[5] == "UNKNOWN_GARBAGE"
    assert statuses[6] == "Running Nmap"
    assert statuses[7] == "Running HTTPx"
