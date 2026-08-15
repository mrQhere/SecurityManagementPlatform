import os
import subprocess
import pytest
from tools.troubleshoot import (
    get_error_solution,
    check_network_routes,
    auto_heal_system,
    ERROR_KNOWLEDGE_BASE,
)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_installer_error_codes_lookup():
    """Verify all 9xxx installer and pre-flight error codes resolve properly."""
    installer_codes = ["SMP-9001", "SMP-9002", "SMP-9003", "SMP-9004", "SMP-9005"]
    for code in installer_codes:
        assert code in ERROR_KNOWLEDGE_BASE
        entry = get_error_solution(code)
        assert entry["code"] == code
        assert "title" in entry
        assert "solution" in entry
        assert "cause" in entry
        assert len(entry["solution"]) > 10


def test_network_routes_diagnostic():
    """Verify check_network_routes returns structured status dictionary."""
    result = check_network_routes()
    assert isinstance(result, dict)
    assert "status" in result
    assert "reachable" in result
    assert "unreachable" in result
    assert result["status"] in ("OK", "WARNING", "ERROR")
    assert isinstance(result["reachable"], list)
    assert isinstance(result["unreachable"], list)


def test_auto_heal_system_execution():
    """Verify auto_heal_system executes without unhandled exceptions."""
    heal_report = auto_heal_system()
    assert isinstance(heal_report, dict)
    assert "healed_items" in heal_report
    assert "warnings" in heal_report
    assert "errors" in heal_report
    assert isinstance(heal_report["healed_items"], list)


def test_setup_sh_syntax_and_functions():
    """Verify setup.sh passes bash syntax check and contains required installer functions."""
    setup_path = os.path.join(BASE_DIR, "setup.sh")
    assert os.path.exists(setup_path)

    # Bash syntax validation
    res = subprocess.run(["bash", "-n", setup_path], capture_output=True, text=True)
    assert res.returncode == 0, f"Bash syntax check failed: {res.stderr}"

    # Verify presence of zero-friction helper functions
    with open(setup_path, "r") as f:
        content = f.read()

    assert "verify_network_routes" in content
    assert "report_error_with_code" in content
    assert "extract_func_source" in content
    assert "run_troubleshooter" in content
    assert "SMP-9001" in content
    assert "SMP-9002" in content
    assert "SMP-9005" in content
