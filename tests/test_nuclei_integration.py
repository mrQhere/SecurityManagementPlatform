import os
import shutil
import pytest
from tools.config_manager import BASE_DIR
from tools.tool_installer import TOOLS, _is_tool_available
import scanners.nuclei as nuclei_module

def test_nuclei_configured_as_binary_download():
    """Verify that Nuclei uses fast binary download and not slow Go source compilation."""
    nuclei_entry = [t for t in TOOLS if t[0] == "Nuclei"]
    assert len(nuclei_entry) == 1, "Nuclei should be in TOOLS registry"
    display, binary, method, arg = nuclei_entry[0]
    assert binary == "nuclei"
    assert method == "binary", "Nuclei must use 'binary' method to avoid slow 'go install' compilation"

def test_nuclei_scanner_flags(monkeypatch):
    """Verify that run_nuclei_scan includes -duc (disable update check) and -ni flags."""
    executed_cmds = []

    class DummyProcess:
        returncode = 0
        def communicate(self, timeout=None):
            return ("", "")

    def dummy_popen(cmd, **kwargs):
        executed_cmds.append(cmd)
        return DummyProcess()

    monkeypatch.setattr(nuclei_module.subprocess, "Popen", dummy_popen)
    monkeypatch.setattr(nuclei_module, "add_log_entry", lambda *args, **kwargs: None)

    nuclei_module.run_nuclei_scan("http://127.0.0.1:8000")

    assert len(executed_cmds) == 1
    cmd = executed_cmds[0]
    assert "-duc" in cmd, "Nuclei command must include -duc to disable slow update checks"
    assert "-ni" in cmd, "Nuclei command must include -ni for non-interactive mode"
    assert "-u" in cmd
    assert "http://127.0.0.1:8000" in cmd
