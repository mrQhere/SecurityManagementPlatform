"""
Baseline and Version Truth Test Suite.
Verifies canonical version configuration, Git tag state, SemVer baseline,
and scanner entry points without mutating production code.
"""

import json
import os
import subprocess
import pytest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_canonical_version_source_exists():
    """Verify config/metadata.json exists, is valid JSON, and declares a 9.5.x version."""
    meta_path = os.path.join(BASE_DIR, "config", "metadata.json")
    assert os.path.exists(meta_path), "config/metadata.json must exist as canonical version source"
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert "version" in meta
    version = meta["version"]
    # Accept 9.5.x patch releases (e.g. 9.5.4, 9.5.5, 9.5.6, 9.5.7, ...).
    # Also accept the legacy "V9.5" label from earlier releases.
    assert version == "V9.5" or (
        version.startswith("9.5.") and version[4:].isdigit()
    ), f"version must be 'V9.5' or '9.5.x'; got {version!r}"
    baseline = meta.get("semver_baseline", "")
    assert baseline.startswith("9.5.") and baseline[4:].isdigit(), (
        f"semver_baseline must be '9.5.x'; got {baseline!r}"
    )




def test_git_tags_and_semver_baseline():
    """Verify git tags presence; if tags absent, verify CHANGELOG contains highest SemVer 9.5.4."""
    tag_proc = subprocess.run(["git", "tag", "-l"], cwd=BASE_DIR, capture_output=True, text=True)
    assert tag_proc.returncode == 0
    tags = tag_proc.stdout.strip().splitlines()

    changelog_path = os.path.join(BASE_DIR, "CHANGELOG.md")
    assert os.path.exists(changelog_path)
    with open(changelog_path, "r", encoding="utf-8") as f:
        changelog_content = f.read()

    # If git tags are absent, SemVer baseline must be 9.5.4 and next planned patch 9.5.5
    if not tags or tags == [""]:
        assert "9.5.4" in changelog_content, "CHANGELOG must declare highest SemVer baseline 9.5.4"
        assert "9.5.5" in changelog_content, "CHANGELOG must plan next patch as 9.5.5"


def test_scanner_entry_points_exist():
    """Verify scanner entry point modules used by UI and API exist."""
    scan_runner_path = os.path.join(BASE_DIR, "scanners", "scan_runner.py")
    assert os.path.exists(scan_runner_path), "scanners/scan_runner.py must exist as primary scan entry point"

    with open(scan_runner_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "_run_scan_sequence" in content or "run_single_scanner" in content


def test_installer_and_manifest_exist():
    """Verify setup.sh and requirements.txt exist for dependency installation."""
    assert os.path.exists(os.path.join(BASE_DIR, "setup.sh"))
    assert os.path.exists(os.path.join(BASE_DIR, "requirements.txt"))
