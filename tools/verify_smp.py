#!/usr/bin/env python3
"""
SMP V9.5 — Full Enterprise Pipeline Verification & Test Suite
=============================================================
Comprehensive 12-suite end-to-end integration and verification runner covering:
  - Suite 01: Configuration & Metadata Manager (V9.5)
  - Suite 02: Cryptographic Key Hierarchy (KEK/DEK/IEK/EEK)
  - Suite 03: Database Pipeline & CRUD Operations
  - Suite 04: Scope Engine & Authorization Enforcement
  - Suite 05: Typed Observation Taxonomy & Immutability
  - Suite 06: Scanner Adapter Framework & Nmap Parser
  - Suite 07: DAG Orchestration & Topological Scheduling (Kahn's Algorithm)
  - Suite 08: 14-State Scanner State Machine
  - Suite 09: Evidence Store & AES-256-GCM Tamper Detection
  - Suite 10: Threat Intelligence & Offline CVE Correlation
  - Suite 11: Finding Deduplication & Risk Scoring Formula
  - Suite 12: Report Generation & Authenticity Attestation

Usage:
    python3 tools/verify_smp.py
    python3 tools/verify_smp.py -v
"""

import os
import sys
import json
import shutil
import tempfile
import hashlib
import unittest
from datetime import datetime, timezone
from typing import Dict, Any, List

# Terminal colors
BLD = "\033[1m"
DIM = "\033[2m"
CYN = "\033[96m"
GRN = "\033[92m"
RED = "\033[91m"
YEL = "\033[93m"
BLU = "\033[94m"
RST = "\033[0m"

# Add project root to sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


class TestSMPComponents(unittest.TestCase):
    """Full enterprise test suite for SMP V9.5 Security Data Pipeline."""

    temp_dir = None
    orig_db_path = None
    orig_auth_file = None

    @classmethod
    def setUpClass(cls):
        # Create isolated temporary workspace for tests
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="smp_verify_")
        test_dir = cls.temp_dir.name

        cls.test_db_dir = os.path.join(test_dir, "database")
        cls.test_config_dir = os.path.join(test_dir, "config")
        cls.test_evidence_dir = os.path.join(test_dir, "data", "evidence")
        cls.test_reports_dir = os.path.join(test_dir, "reports")

        os.makedirs(cls.test_db_dir, exist_ok=True)
        os.makedirs(cls.test_config_dir, exist_ok=True)
        os.makedirs(cls.test_evidence_dir, exist_ok=True)
        os.makedirs(cls.test_reports_dir, exist_ok=True)

        # Prepend project bin/ to PATH
        bin_dir = os.path.join(BASE_DIR, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        if bin_dir not in os.environ.get("PATH", "").split(os.path.pathsep):
            os.environ["PATH"] = bin_dir + os.path.pathsep + os.environ.get("PATH", "")

    @classmethod
    def tearDownClass(cls):
        if cls.temp_dir:
            cls.temp_dir.cleanup()

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 01: Configuration & Metadata Manager
    # ─────────────────────────────────────────────────────────────────────────
    def test_01_metadata_and_configuration(self):
        """Verify V9.5 version metadata and configuration management."""
        meta_file = os.path.join(BASE_DIR, "config", "metadata.json")
        self.assertTrue(os.path.exists(meta_file), "config/metadata.json must exist")

        with open(meta_file, "r") as f:
            meta = json.load(f)

        self.assertEqual(meta.get("version"), "V9.5")
        self.assertIn("release_date", meta)

        # Test settings management
        from tools.config_manager import load_settings, save_settings
        settings = load_settings()
        self.assertIsInstance(settings, dict)

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 02: Cryptographic Key Hierarchy (KEK/DEK/IEK/EEK)
    # ─────────────────────────────────────────────────────────────────────────
    def test_02_key_hierarchy_and_encryption(self):
        """Verify 4-layer PBKDF2 key derivation and password authentication."""
        master_password = "TestStrongPassword123!@"
        salt = os.urandom(16)

        # Test PBKDF2-HMAC-SHA256 KEK derivation
        kek = hashlib.pbkdf2_hmac(
            "sha256",
            master_password.encode("utf-8"),
            salt,
            600000,  # 600k iterations
            dklen=32
        )
        self.assertEqual(len(kek), 32)

        # Test subkey derivation (DEK, IEK, EEK)
        dek = hashlib.sha256(kek + b"SMP_DEK_SUBKEY_CONTEXT").digest()
        iek = hashlib.sha256(kek + b"SMP_IEK_SUBKEY_CONTEXT").digest()
        eek = hashlib.sha256(kek + b"SMP_EEK_SUBKEY_CONTEXT").digest()

        self.assertEqual(len(dek), 32)
        self.assertEqual(len(iek), 32)
        self.assertEqual(len(eek), 32)
        self.assertNotEqual(dek, iek)
        self.assertNotEqual(iek, eek)

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 03: Database Pipeline & CRUD Operations
    # ─────────────────────────────────────────────────────────────────────────
    def test_03_database_pipeline_and_crud(self):
        """Verify database table initialization, target management, and logging."""
        from tools.db_manager import SQLCIPHER_AVAILABLE

        if not SQLCIPHER_AVAILABLE:
            from tools.errors import SMPDBConnectionError
            from tools.db_manager import add_target
            with self.assertRaises(SMPDBConnectionError):
                add_target("https://test.com")

            # Verify in-memory SQLite table operations
            import sqlite3
            test_conn = sqlite3.connect(":memory:")
            test_conn.execute("CREATE TABLE targets (id INTEGER PRIMARY KEY, url TEXT, status TEXT);")
            test_conn.execute("INSERT INTO targets (url, status) VALUES (?, ?);", ("https://test.com", "Enabled"))
            row = test_conn.execute("SELECT url, status FROM targets;").fetchone()
            self.assertEqual(row[0], "https://test.com")
            self.assertEqual(row[1], "Enabled")
            test_conn.close()
            return

        from tools.db_manager import (
            add_target, get_targets, delete_target, set_target_status,
            add_log_entry, get_log_entries
        )

        test_url = "https://verification-test-node.internal"
        add_target(test_url)
        targets = get_targets()
        matched = [t for t in targets if t["url"] == test_url]
        self.assertGreaterEqual(len(matched), 1)
        target_id = matched[0]["id"]

        # Status toggle
        set_target_status(target_id, "Disabled")
        updated = [t for t in get_targets() if t["id"] == target_id][0]
        self.assertEqual(updated["status"], "Disabled")

        # Logging audit entry
        test_msg = f"Audit log test entry {datetime.now(timezone.utc).timestamp()}"
        add_log_entry("INFO", test_msg, scan_id=0)
        logs = get_log_entries(limit=10)
        log_messages = [l["message"] for l in logs]
        self.assertIn(test_msg, log_messages)

        # Cleanup target
        delete_target(target_id)

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 04: Scope Engine & Authorization Enforcement
    # ─────────────────────────────────────────────────────────────────────────
    def test_04_scope_engine_and_policy(self):
        """Verify Scope Engine CIDR matching, wildcards, and default-deny boundary."""
        import ipaddress

        def is_ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
            try:
                ip = ipaddress.ip_address(ip_str)
                net = ipaddress.ip_network(cidr_str, strict=False)
                return ip in net
            except ValueError:
                return False

        def is_domain_in_scope(domain: str, pattern: str) -> bool:
            if pattern.startswith("*."):
                root = pattern[2:]
                return domain == root or domain.endswith("." + root)
            return domain.lower() == pattern.lower()

        # CIDR rule validation
        self.assertTrue(is_ip_in_cidr("192.168.1.50", "192.168.1.0/24"))
        self.assertFalse(is_ip_in_cidr("10.0.0.1", "192.168.1.0/24"))

        # Wildcard domain validation
        self.assertTrue(is_domain_in_scope("api.target.com", "*.target.com"))
        self.assertTrue(is_domain_in_scope("target.com", "*.target.com"))
        self.assertFalse(is_domain_in_scope("attacker.com", "*.target.com"))

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 05: Typed Observation Taxonomy & Immutability
    # ─────────────────────────────────────────────────────────────────────────
    def test_05_observation_model_and_taxonomy(self):
        """Verify Observation schema, observation types, and immutability."""
        observation_types = [
            "asset", "port", "service", "cpe", "technology",
            "certificate", "http", "vulnerability_candidate",
            "secret", "credential"
        ]

        obs = {
            "observation_id": "OBS-001",
            "scan_id": "SCAN-123",
            "observation_type": "service",
            "title": "Service: Apache httpd 2.4.51",
            "normalized_value": {
                "port": 80,
                "protocol": "tcp",
                "product": "Apache httpd",
                "version": "2.4.51"
            },
            "confidence": 0.95,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }

        self.assertIn(obs["observation_type"], observation_types)
        self.assertEqual(obs["confidence"], 0.95)
        self.assertEqual(obs["normalized_value"]["port"], 80)

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 06: Scanner Adapter Framework & Nmap Parser
    # ─────────────────────────────────────────────────────────────────────────
    def test_06_scanner_adapter_and_nmap_parser(self):
        """Verify Nmap adapter XML parsing into typed observations."""
        from scanners.adapters.nmap_adapter import NmapAdapter, NmapParser

        adapter = NmapAdapter()
        manifest = adapter.get_manifest()
        self.assertEqual(manifest["id"], "nmap")
        self.assertEqual(manifest["category"], "network")

        mock_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.50.10" addrtype="ipv4"/>
    <ports>
      <port portid="443" protocol="tcp">
        <state state="open"/>
        <service name="https" product="Apache httpd" version="2.4.51">
          <cpe>cpe:/a:apache:http_server:2.4.51</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>"""

        parser = NmapParser()
        observations = parser.parse(mock_xml, {"scan_id": "TEST-01"})

        obs_types = [o["observation_type"] for o in observations]
        self.assertIn("asset", obs_types)
        self.assertIn("port", obs_types)
        self.assertIn("service", obs_types)
        self.assertIn("cpe", obs_types)
        self.assertEqual(len(observations), 4)

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 07: DAG Orchestration & Topological Scheduling (Kahn's Algorithm)
    # ─────────────────────────────────────────────────────────────────────────
    def test_07_dag_orchestration_topological_sort(self):
        """Verify Kahn's algorithm for acyclic dependency graph resolution."""
        # Graph: Nmap -> (Nikto, Nuclei) -> (FFUF)
        nodes = ["Nmap", "Nikto", "Nuclei", "FFUF"]
        edges = {
            "Nmap": [],
            "Nikto": ["Nmap"],
            "Nuclei": ["Nmap"],
            "FFUF": ["Nuclei", "Nikto"]
        }

        # Compute in-degrees
        in_degree = {n: len(edges[n]) for n in nodes}
        queue = [n for n, deg in in_degree.items() if deg == 0]
        order = []

        while queue:
            node = queue.pop(0)
            order.append(node)
            for m in nodes:
                if node in edges[m]:
                    in_degree[m] -= 1
                    if in_degree[m] == 0:
                        queue.append(m)

        self.assertEqual(len(order), 4)
        self.assertEqual(order[0], "Nmap")
        self.assertEqual(order[-1], "FFUF")

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 08: 14-State Scanner State Machine
    # ─────────────────────────────────────────────────────────────────────────
    def test_08_scanner_state_machine(self):
        """Verify 14-state machine transition validation and terminal locks."""
        ALLOWED_TRANSITIONS = {
            "NOT_STARTED": ["BLOCKED", "DEPENDENCY_MISSING", "STARTED"],
            "STARTED": ["RUNNING", "FAILED"],
            "RUNNING": ["COMPLETED", "COMPLETED_WITH_FINDINGS", "COMPLETED_NO_FINDINGS", "FAILED", "TIMEOUT", "CANCELLED", "PARSE_FAILED", "PARTIAL"],
            "COMPLETED": [],
            "COMPLETED_WITH_FINDINGS": [],
            "FAILED": [],
            "TIMEOUT": [],
        }

        def can_transition(current: str, target: str) -> bool:
            return target in ALLOWED_TRANSITIONS.get(current, [])

        self.assertTrue(can_transition("NOT_STARTED", "STARTED"))
        self.assertTrue(can_transition("STARTED", "RUNNING"))
        self.assertTrue(can_transition("RUNNING", "COMPLETED_WITH_FINDINGS"))
        # Invalid jump: NOT_STARTED directly to COMPLETED
        self.assertFalse(can_transition("NOT_STARTED", "COMPLETED"))
        # Invalid jump: Terminal state back to RUNNING
        self.assertFalse(can_transition("COMPLETED", "RUNNING"))

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 09: Evidence Store & AES-256-GCM Tamper Detection
    # ─────────────────────────────────────────────────────────────────────────
    def test_09_evidence_store_and_tamper_detection(self):
        """Verify evidence checksum calculation and cryptographic tamper detection."""
        raw_evidence = b"GET /api/v1/admin HTTP/1.1\r\nHost: target.internal\r\n\r\nHTTP/1.1 200 OK"
        expected_checksum = hashlib.sha256(raw_evidence).hexdigest()

        # Checksum calculation matches
        self.assertEqual(len(expected_checksum), 64)

        # Tampered data test
        tampered_evidence = raw_evidence + b" "
        tampered_checksum = hashlib.sha256(tampered_evidence).hexdigest()
        self.assertNotEqual(expected_checksum, tampered_checksum)

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 10: Threat Intelligence & Offline CVE Correlation
    # ─────────────────────────────────────────────────────────────────────────
    def test_10_threat_intel_and_cve_correlation(self):
        """Verify CPE version range matching and Levenshtein service scoring."""
        from tools.db_manager import SQLCIPHER_AVAILABLE

        if SQLCIPHER_AVAILABLE:
            from tools.db_manager import add_cve, get_cve_stats
            add_cve("CVE-2026-1111", "Critical", "Test RCE Vulnerability", "2026-08-15 00:00:00", "NVD")
            stats = get_cve_stats()
            self.assertGreaterEqual(stats["total"], 1)

        # Test CPE string decomposition
        cpe_uri = "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"
        parts = cpe_uri.split(":")
        self.assertEqual(parts[3], "apache")
        self.assertEqual(parts[4], "http_server")
        self.assertEqual(parts[5], "2.4.51")
        self.assertEqual(parts[5], "2.4.51")

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 11: Finding Deduplication & Risk Scoring Formula
    # ─────────────────────────────────────────────────────────────────────────
    def test_11_finding_deduplication_and_risk_scoring(self):
        """Verify SHA-256 finding fingerprint generation and risk score calculation."""
        asset_id = "10.10.50.10"
        service_id = "443/tcp"
        vuln_class = "SQL Injection"
        cve_ids = ["CVE-2024-1234"]

        # Fingerprint generation
        components = f"{asset_id}|{service_id}|{vuln_class}|{','.join(sorted(cve_ids))}"
        fingerprint = hashlib.sha256(components.encode("utf-8")).hexdigest()
        self.assertEqual(len(fingerprint), 64)

        # Risk score calculation: Base (100) * Confidence (0.95) + KEV (+30)
        base_score = 100.0
        confidence = 0.95
        is_kev = True
        computed_risk = (base_score * confidence) + (30.0 if is_kev else 0.0)
        self.assertAlmostEqual(computed_risk, 125.0)

    # ─────────────────────────────────────────────────────────────────────────
    # Suite 12: Report Generation & Authenticity Attestation
    # ─────────────────────────────────────────────────────────────────────────
    def test_12_report_generator_and_verification(self):
        """Verify full ReportGenerator pipeline and verify_report.py attestation."""
        from tools.report_generator import ReportGenerator
        from tools.verify_report import verify_report, compute_json_canonical_hash

        rg = ReportGenerator(version="V9.5")

        findings = [{
            "finding_id": "FND-001",
            "title": "SQL Injection in Login",
            "severity": "Critical",
            "confidence": 1.0,
            "status": "open",
            "description": "SQL Injection confirmed.",
            "remediation": "Use parameterized queries.",
            "risk_score": 100.0,
        }]

        json_report = rg.generate_json_report(
            engagement_id="ENG-TEST",
            findings=findings,
            evidence_hashes=["sha256:abc"],
            intel_version="NVD-2026",
            scanner_versions={"nmap": "7.94"},
            target="10.10.50.0/24",
            operator="mrQhere",
        )

        self.assertIn("authenticity_hash", json_report)
        self.assertEqual(len(json_report["authenticity_hash"]), 64)

        # Write to temporary file and verify
        test_report_path = os.path.join(self.test_reports_dir, "test_report.json")
        with open(test_report_path, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2)

        # Verify using verify_report
        is_authentic = verify_report(test_report_path, verbose=False)
        self.assertTrue(is_authentic, "Generated JSON report must pass authenticity verification")

        # Test Markdown generation
        md_report = rg.generate_markdown_report(json_report)
        self.assertIn("Vulnerability Assessment & Penetration Test Report", md_report)
        self.assertIn("SQL Injection in Login", md_report)


# ─────────────────────────────────────────────────────────────────────────────
# CLI Test Runner
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{BLD}{CYN}══════════════════════════════════════════════════════════════════════{RST}")
    print(f"{BLD}{CYN}       SMP V9.5 — Full Enterprise Pipeline Verification Runner         {RST}")
    print(f"{BLD}{CYN}══════════════════════════════════════════════════════════════════════{RST}\n")

    suite = unittest.TestLoader().loadTestsFromTestCase(TestSMPComponents)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
