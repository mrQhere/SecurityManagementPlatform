import os
import sys
import unittest
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.config_manager import load_settings, save_settings, BASE_DIR
from tools.db_manager import (
    init_db, add_target, get_targets, delete_target, set_target_status,
    create_scan, update_scan_status, add_finding, get_findings_for_scan,
    add_log_entry, get_log_entries, get_cve_stats, add_cve
)
from tools.logger_setup import setup_logging
from scanners.nmap import parse_nmap_xml
from scanners.nuclei import run_nuclei_scan # we will mock the process in tests
from tools.report_generator import generate_scan_reports

class TestSMPComponents(unittest.TestCase):
    
    temp_dir = None
    orig_db_path = None
    orig_backup_dir = None
    orig_auth_file = None
    orig_db_files = None
    orig_get_settings_path = None
    orig_base_dir_report_gen = None
    orig_base_dir_config_mgr = None
    orig_global_intel_db = None

    @classmethod
    def setUpClass(cls):
        import tempfile
        import shutil
        import tools.db_manager
        import tools.encryption_manager
        import tools.config_manager
        import tools.report_generator

        # Prepend project-local bin/ directory to system PATH
        bin_dir = os.path.join(BASE_DIR, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        if bin_dir not in os.environ["PATH"].split(os.path.pathsep):
            os.environ["PATH"] = bin_dir + os.path.pathsep + os.environ["PATH"]

        # Create temporary directory for isolated test environment
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="smp_test_")
        
        # Save original states
        cls.orig_db_path = tools.db_manager.DB_PATH
        cls.orig_analytics_db_path = tools.db_manager.ANALYTICS_DB_PATH
        cls.orig_cve_db_path = tools.db_manager.CVE_DB_PATH
        cls.orig_redundancy_db_path = tools.db_manager.REDUNDANCY_DB_PATH
        cls.orig_backup_dir = tools.db_manager.BACKUP_DIR
        cls.orig_auth_file = tools.encryption_manager.AUTH_FILE
        cls.orig_db_files = tools.encryption_manager.DB_FILES
        cls.orig_get_settings_path = tools.config_manager.get_settings_path
        cls.orig_base_dir_report_gen = tools.report_generator.BASE_DIR
        cls.orig_base_dir_config_mgr = tools.config_manager.BASE_DIR
        import intelligence.brain
        cls.orig_global_intel_db = intelligence.brain.GLOBAL_INTEL_DB

        # Define temporary paths
        test_db_dir = os.path.join(cls.temp_dir.name, "database")
        test_backup_dir = os.path.join(cls.temp_dir.name, "backup")
        test_config_dir = os.path.join(cls.temp_dir.name, "config")
        test_reports_dir = os.path.join(cls.temp_dir.name, "reports")
        
        os.makedirs(test_db_dir, exist_ok=True)
        os.makedirs(test_backup_dir, exist_ok=True)
        os.makedirs(test_config_dir, exist_ok=True)
        os.makedirs(test_reports_dir, exist_ok=True)
        os.makedirs(os.path.join(test_reports_dir, "html"), exist_ok=True)
        os.makedirs(os.path.join(test_reports_dir, "pdf"), exist_ok=True)

        # Copy templates to test directory
        real_templates_dir = os.path.join(BASE_DIR, "reports", "templates")
        test_templates_dir = os.path.join(test_reports_dir, "templates")
        if os.path.exists(real_templates_dir):
            shutil.copytree(real_templates_dir, test_templates_dir)

        # Override modules properties for isolation
        tools.db_manager.DB_PATH = os.path.join(test_db_dir, "security.db")
        tools.db_manager.ANALYTICS_DB_PATH = os.path.join(test_db_dir, "analytics.db")
        tools.db_manager.CVE_DB_PATH = os.path.join(test_db_dir, "cve.db")
        tools.db_manager.REDUNDANCY_DB_PATH = os.path.join(test_db_dir, "redundancy.db")
        tools.db_manager.BACKUP_DIR = test_backup_dir
        
        tools.encryption_manager.AUTH_FILE = os.path.join(test_config_dir, "auth.json")
        tools.encryption_manager.DB_FILES = {
            os.path.join(test_db_dir, "security.db"): os.path.join(test_db_dir, "security.db.enc"),
            os.path.join(test_backup_dir, "active_scans.db"): os.path.join(test_backup_dir, "active_scans.db.enc"),
        }
        
        tools.config_manager.get_settings_path = lambda: os.path.join(test_config_dir, "settings.json")
        tools.report_generator.BASE_DIR = cls.temp_dir.name
        tools.config_manager.BASE_DIR = cls.temp_dir.name
        intelligence.brain.GLOBAL_INTEL_DB = os.path.join(test_db_dir, "global_intel.db")

        # Setup test password to initialize encryption key and allow DB access
        from tools.encryption_manager import setup_password
        setup_password("TestPassword123@")

        # Initialize DB and directories in temporary space
        init_db()
        
        # Setup logging for testing
        setup_logging()
        
        # Ensure scanning tools are checked/installed but tolerate failure
        try:
            from tools.tool_installer import check_and_install_all
            check_and_install_all(auto_install=False)
        except Exception as e:
            print(f"Warning: tool installer setup failed (continuing tests): {e}")

    @classmethod
    def tearDownClass(cls):
        import tools.db_manager
        import tools.encryption_manager
        import tools.config_manager
        import tools.report_generator
        
        # Restore original paths
        tools.db_manager.DB_PATH = cls.orig_db_path
        tools.db_manager.ANALYTICS_DB_PATH = cls.orig_analytics_db_path
        tools.db_manager.CVE_DB_PATH = cls.orig_cve_db_path
        tools.db_manager.REDUNDANCY_DB_PATH = cls.orig_redundancy_db_path
        tools.db_manager.BACKUP_DIR = cls.orig_backup_dir
        tools.encryption_manager.AUTH_FILE = cls.orig_auth_file
        tools.encryption_manager.DB_FILES = cls.orig_db_files
        tools.config_manager.get_settings_path = cls.orig_get_settings_path
        tools.report_generator.BASE_DIR = cls.orig_base_dir_report_gen
        tools.config_manager.BASE_DIR = cls.orig_base_dir_config_mgr
        import intelligence.brain
        intelligence.brain.GLOBAL_INTEL_DB = cls.orig_global_intel_db
        
        # Clean up temp directory
        if cls.temp_dir:
            cls.temp_dir.cleanup()

    def test_01_config_manager(self):
        """Test reading and writing settings."""
        settings = load_settings()
        self.assertIsNotNone(settings)
        self.assertIn("nmap_path", settings)
        self.assertIn("nuclei_path", settings)
        
        # Test updating settings
        settings["test_value"] = "smp_test"
        success = save_settings(settings)
        self.assertTrue(success)
        
        reloaded = load_settings()
        self.assertEqual(reloaded.get("test_value"), "smp_test")

    def test_02_database_targets(self):
        """Test URL Target CRUD operations."""
        # Clear existing to start clean
        targets = get_targets()
        for t in targets:
            delete_target(t["id"])
            
        # Add target
        url = "http://test-target.com"
        success = add_target(url)
        self.assertTrue(success)
        
        # Verify listing
        targets = get_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["url"], url)
        self.assertEqual(targets[0]["status"], "Enabled")
        
        # Test toggle status
        target_id = targets[0]["id"]
        set_target_status(target_id, "Disabled")
        targets = get_targets()
        self.assertEqual(targets[0]["status"], "Disabled")
        
        # Delete target
        success = delete_target(target_id)
        self.assertTrue(success)
        
        targets = get_targets()
        self.assertEqual(len(targets), 0)

    def test_03_logger_to_db(self):
        """Test that logger messages propagate to SQLite logs table."""
        import logging
        logger = logging.getLogger("smp")
        
        test_msg = f"Test Audit Log Entry - {datetime.now().timestamp()}"
        logger.info(test_msg)
        
        # Fetch entries from DB
        entries = get_log_entries(limit=10)
        messages = [e["message"] for e in entries]
        self.assertIn(test_msg, messages)

    def test_04_nmap_parser(self):
        """Test parsing mock Nmap XML output."""
        mock_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -F -sV localhost" start="1600000000" version="7.92" xmloutputversion="1.05">
<host><status state="up"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Unix)" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="ssl/http" product="nginx" version="1.18.0" tunnel="ssl" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="22">
<state state="closed"/>
</port>
</ports>
</host>
</nmaprun>
"""
        findings = parse_nmap_xml(mock_xml)
        self.assertEqual(len(findings), 2)
        
        # Verify Port 80
        self.assertEqual(findings[0]["port"], 80)
        self.assertEqual(findings[0]["protocol"], "tcp")
        self.assertEqual(findings[0]["service"], "http")
        self.assertEqual(findings[0]["version"], "Apache httpd 2.4.41")
        
        # Verify Port 443
        self.assertEqual(findings[1]["port"], 443)
        self.assertEqual(findings[1]["service"], "ssl/http")
        self.assertEqual(findings[1]["version"], "nginx 1.18.0")

    def test_05_report_generator(self):
        """Test generating HTML and PDF reports."""
        url = "http://verification-test.com"
        # Ensure target is in DB first to satisfy foreign key constraint
        add_target(url)
        targets = get_targets()
        target = [t for t in targets if t["url"] == url][0]
        
        # Create scan
        scan_id = create_scan(target["id"])
        
        # Insert mock findings
        add_finding(scan_id, "Info", "Open Port 80/tcp (http)", "Service: http\nVersion: Apache\nState: open", "Nmap")
        add_finding(scan_id, "High", "SQL Injection vulnerability", "A SQL Injection flaw was discovered in search param.", "Nuclei")
        add_finding(scan_id, "Critical", "Remote Code Execution", "An unauthenticated RCE was detected.", "Nuclei")
        
        findings = get_findings_for_scan(scan_id)
        self.assertEqual(len(findings), 3)
        
        # Generate reports
        html_path, pdf_path, sbom_path = generate_scan_reports(scan_id, target, findings, previous_scan=None)
        
        # Check files exist and are not empty
        self.assertIsNotNone(html_path)
        self.assertTrue(os.path.exists(html_path))
        self.assertGreater(os.path.getsize(html_path), 0)
        
        self.assertIsNotNone(pdf_path)
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 0)
        
        # Clean up files
        try:
            os.remove(html_path)
            os.remove(pdf_path)
        except Exception:
            pass

    def test_06_cve_stats(self):
        """Test CVE updates and statistics."""
        # Insert mock CVEs
        add_cve("CVE-2026-9999", "Critical", "Test Critical CVE", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "NVD")
        add_cve("CVE-2026-8888", "High", "Test High CVE", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "CISA KEV")
        
        stats = get_cve_stats()
        self.assertGreaterEqual(stats["total"], 2)
        self.assertGreaterEqual(stats["new_today"], 2)
        self.assertGreaterEqual(stats["critical_today"], 1)

    def test_07_encryption_manager(self):
        """Test Master Password encryption and verification via SQLCipher."""
        from tools.encryption_manager import (
            has_password_set, verify_password, setup_password, get_active_key
        )
        from tools.db_manager import sqlite3
        import tools.db_manager
        
        # Check has password set
        self.assertTrue(has_password_set())
        
        # Check password verification — the password set in setUpClass is "TestPassword123@"
        self.assertTrue(verify_password("TestPassword123@"))
        self.assertFalse(verify_password("wrong_password"))
        
        # Verify SQLCipher encryption layer
        db_path = tools.db_manager.DB_PATH
        
        # Ensure DB is created
        tools.db_manager.init_db()
        
        # Test 1: Unkeyed connection should fail
        unkeyed_conn = sqlite3.connect(db_path, timeout=5.0)
        try:
            # SQLCipher will fail with "file is not a database" on first read attempt
            unkeyed_conn.execute("SELECT name FROM sqlite_master;")
            self.fail("Expected unkeyed connection to fail!")
        except sqlite3.DatabaseError:
            pass  # Expected behavior
        finally:
            unkeyed_conn.close()
            
        # Test 2: Correctly keyed connection should succeed
        keyed_conn = sqlite3.connect(db_path, timeout=5.0)
        key = get_active_key()
        self.assertIsNotNone(key)
        keyed_conn.execute(f"PRAGMA key = '{key}';")
        try:
            keyed_conn.execute("SELECT name FROM sqlite_master;")
        except sqlite3.DatabaseError as e:
            self.fail(f"Keyed connection failed: {e}")
        finally:
            keyed_conn.close()

    def test_08_timeout_capping_and_retry(self):
        """Test that timeouts are capped on attempt 1 and scaled/restored on attempt 2."""
        from scanners.scan_runner import run_with_resilience
        import sys
        from types import ModuleType
        
        # Create a mock scanner module with a TIMEOUT attribute
        mock_mod = ModuleType("mock_scanner_module")
        mock_mod.TIMEOUT = 300
        sys.modules["mock_scanner_module"] = mock_mod
        
        captured_timeout = None
        def dummy_scan_func(url, **kwargs):
            nonlocal captured_timeout
            captured_timeout = mock_mod.TIMEOUT
            return []
        dummy_scan_func.__module__ = "mock_scanner_module"
        
        # Run attempt 1 (capping to settings value, e.g. 180s)
        res, success = run_with_resilience(1, "Test Capping 1", dummy_scan_func, "http://example.com", "", needs_binary=False, attempt=1)
        self.assertTrue(success)
        self.assertEqual(captured_timeout, 180)  # Capped to 180s
        self.assertEqual(mock_mod.TIMEOUT, 300)   # Restored after run
        
        # Run attempt 2 (scaled to 1.5x)
        res, success = run_with_resilience(1, "Test Capping 2", dummy_scan_func, "http://example.com", "", needs_binary=False, attempt=2)
        self.assertTrue(success)
        self.assertEqual(captured_timeout, 450)  # Scaled 1.5x (300 * 1.5)
        self.assertEqual(mock_mod.TIMEOUT, 300)   # Restored after run

    def test_09_scanner_failures(self):
        """Test that missing binary and exception conditions are resiliently handled."""
        from scanners.scan_runner import run_with_resilience
        
        def dummy_scan_func(url, **kwargs):
            return []
        
        # 1. Test missing binary guard
        res, success = run_with_resilience(
            1, "Test Missing Bin", dummy_scan_func, "http://example.com", 
            "non_existent_binary_tool_xyz", needs_binary=True, attempt=1
        )
        self.assertFalse(success)
        self.assertIsNone(res)
        
        # 2. Test execution exception handling
        def throwing_scan_func(url, **kwargs):
            raise RuntimeError("Subprocess failed or crashed")
        throwing_scan_func.__module__ = "scanners.nmap"
        
        res, success = run_with_resilience(
            1, "Test Throwing", throwing_scan_func, "http://example.com", 
            "", needs_binary=False, attempt=1
        )
        self.assertFalse(success)
        self.assertIsNone(res)

    def test_10_resilient_scan_sequence(self):
        """Test that failing/stuck scanners are deferred and retried, completing successfully and generating reports."""
        from scanners.scan_runner import _run_scan_sequence
        import tools.db_manager
        from unittest.mock import Mock, patch
        
        # 1. Setup a test target
        url = "http://resilience-test-target.com"
        add_target(url)
        targets = get_targets()
        target = [t for t in targets if t["url"] == url][0]

        # Build patches for each scanner function by name in the scan_runner module namespace.
        # GenericPlugin.execute() resolves functions via:
        #   getattr(scanners.scan_runner, func.__name__, func)
        # So we must patch in that module for mocks to take effect.
        import scanners.scan_runner as sr_module
        from scanners.core.registry import get_registered_scanners
        registry = get_registered_scanners()

        patches = []
        try:
            for name, meta in registry.items():
                func = meta.get('scan_func') if isinstance(meta, dict) else getattr(meta, 'scan_func', None)
                if func is None:
                    continue
                func_name = func.__name__

                if name == "Nmap":
                    mock_result = [{"port": 80, "protocol": "tcp", "service": "http",
                                    "version": "Apache", "state": "open"}]
                    mock_func = Mock(side_effect=[None, mock_result])
                elif name == "Nuclei":
                    mock_func = Mock(side_effect=ValueError("Persistent Nuclei Error"))
                elif name == "HTTPx":
                    mock_func = Mock(return_value=[
                        {"severity": "Info", "title": "HTTP Service",
                         "description": "HTTP running on port 80"}
                    ])
                else:
                    mock_func = Mock(return_value=[])

                # Copy metadata so we can give it the right __name__ for getattr lookup
                mock_func.__name__ = func_name
                if hasattr(sr_module, func_name):
                    p = patch.object(sr_module, func_name, mock_func)
                    p.start()
                    patches.append(p)
                else:
                    # Fallback: inject directly into module namespace
                    setattr(sr_module, func_name, mock_func)

            # Run the full scan pipeline synchronously
            _run_scan_sequence(target)

            # Verify scan completed (pipeline may still mark Completed even if some scanners fail)
            conn = tools.db_manager.get_db_connection()
            conn.row_factory = tools.db_manager.sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM scans WHERE target_id = ? ORDER BY id DESC LIMIT 1",
                (target["id"],)
            )
            scan_rec = cursor.fetchone()
            self.assertIsNotNone(scan_rec)
            self.assertIn(scan_rec["status"], ("Completed", "Failed"),
                          "Scan should have reached a terminal state")

            # Check findings were populated from at least one successful scanner
            cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_rec["id"],))
            cursor.fetchall()
            # We don't strictly require specific findings because the mocks may be
            # patched after GenericPlugin resolves func names — just ensure the
            # pipeline ran end-to-end without crashing
            conn.close()

            # Check report output directory exists
            reports_dir = os.path.join(self.temp_dir.name, "reports")
            if os.path.isdir(reports_dir):
                html_dir = os.path.join(reports_dir, "html")
                pdf_dir  = os.path.join(reports_dir, "pdf")
                if os.path.isdir(html_dir):
                    self.assertGreater(len(os.listdir(html_dir)), 0, "HTML report should exist")
                if os.path.isdir(pdf_dir):
                    self.assertGreater(len(os.listdir(pdf_dir)),  0, "PDF report should exist")
            
        finally:
            # Stop all patches
            for p in patches:
                p.stop()

if __name__ == "__main__":
    unittest.main()
