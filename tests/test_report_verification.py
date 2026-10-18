"""
Regression test suite for Markdown report verification in SMP v9.5.5.
Tests valid, one-byte modified, fabricated, missing, malformed, legacy,
and keyed HMAC reports.
"""

import os
import re
import tempfile
import pytest

from tools.report_generator import ReportGenerator
from tools.verify_report import (
    verify_report,
    verify_markdown_report,
    compute_markdown_digest,
    compute_markdown_hmac,
    get_canonical_markdown_payload,
)


@pytest.fixture
def sample_json_report():
    rg = ReportGenerator(version="v9.5.5")
    findings = [
        {
            "finding_id": "FND-001",
            "title": "SQL Injection in User Login Endpoint",
            "severity": "Critical",
            "confidence": 1.0,
            "status": "open",
            "description": "SQL injection vulnerability confirmed in /api/login parameter.",
            "remediation": "Use parameterized queries or ORM bindings.",
            "risk_score": 95.0,
        },
        {
            "finding_id": "FND-002",
            "title": "Cross-Site Scripting in Profile Bio",
            "severity": "Medium",
            "confidence": 0.9,
            "status": "open",
            "description": "Stored XSS payload executing on user profile page.",
            "remediation": "Sanitize and contextual-encode all HTML outputs.",
            "risk_score": 50.0,
        },
    ]
    return rg.generate_json_report(
        engagement_id="ENG-TEST-001",
        findings=findings,
        evidence_hashes=["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        intel_version="NVD-2026-10",
        scanner_versions={"nmap": "7.94", "nuclei": "3.3.9"},
        target="https://target.local",
        operator="TestOperator",
    )


def test_valid_generated_markdown_report_passes(sample_json_report):
    """Verify that a freshly generated Markdown report passes integrity verification."""
    rg = ReportGenerator(version="v9.5.5")
    md_content = rg.generate_markdown_report(sample_json_report)

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(md_content)
        temp_path = tf.name

    try:
        res = verify_report(temp_path, verbose=False)
        assert res.verified is True
        assert bool(res) is True
        assert res == True
        assert res.status == "INTEGRITY_VERIFIED"
        assert res.integrity == "VERIFIED"
        assert res.authenticity == "UNATTESTED"
        assert len(res.embedded_hash) == 64
        assert res.embedded_hash == res.computed_hash
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_one_byte_tampering_fails(sample_json_report):
    """Verify that any one-byte modification in report text causes verification failure."""
    rg = ReportGenerator(version="v9.5.5")
    md_content = rg.generate_markdown_report(sample_json_report)

    # Modify exactly one byte in the findings section
    tampered_content = md_content.replace("SQL Injection", "WQL Injection", 1)
    assert tampered_content != md_content

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(tampered_content)
        temp_path = tf.name

    try:
        res = verify_report(temp_path, verbose=False)
        assert res.verified is False
        assert bool(res) is False
        assert res == False
        assert res.status == "FAILED"
        assert res.integrity == "FAILED"
        assert "mismatch" in res.message.lower() or "tampering" in res.message.lower()
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_fabricated_64_hex_digest_fails(sample_json_report):
    """Verify that replacing the digest with a fabricated 64-hex string fails."""
    rg = ReportGenerator(version="v9.5.5")
    md_content = rg.generate_markdown_report(sample_json_report)

    # Extract genuine digest and replace with arbitrary 64-hex string
    m = re.search(r"SHA-256:\s*([a-f0-9]{64})", md_content)
    assert m is not None
    real_digest = m.group(1)
    fake_digest = "a" * 64
    assert fake_digest != real_digest

    fabricated_content = md_content.replace(real_digest, fake_digest)

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(fabricated_content)
        temp_path = tf.name

    try:
        res = verify_report(temp_path, verbose=False)
        assert res.verified is False
        assert bool(res) is False
        assert res == False
        assert res.status == "FAILED"
        assert res.integrity == "FAILED"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_missing_hash_fails():
    """Verify that a report missing any SHA-256 digest is rejected as MALFORMED."""
    content = "# Vulnerability Report\n\nNo attestation block provided.\n"

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(content)
        temp_path = tf.name

    try:
        res = verify_report(temp_path, verbose=False)
        assert res.verified is False
        assert res.status in ("MALFORMED", "MISSING_HASH")
        assert res.integrity == "FAILED"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_malformed_hash_fails():
    """Verify that a report with an invalid/truncated hash is rejected as MALFORMED."""
    content = """# Vulnerability Report
### D. Report Integrity Attestation
```
REPORT-ID:    123
SHA-256:      truncated_hash_12345
```
"""
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(content)
        temp_path = tf.name

    try:
        res = verify_report(temp_path, verbose=False)
        assert res.verified is False
        assert res.status == "MALFORMED"
        assert res.integrity == "FAILED"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_legacy_report_returns_unverifiable_legacy():
    """Verify that older legacy reports return UNVERIFIABLE_LEGACY, not VERIFIED."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    demo_report_path = os.path.join(base_dir, "reports", "demo_report.md")

    if os.path.exists(demo_report_path):
        res = verify_report(demo_report_path, verbose=False)
        assert res.verified is False
        assert res.status == "UNVERIFIABLE_LEGACY"
        assert res.integrity == "UNVERIFIABLE"
        assert res != True

    # Also test an explicitly constructed legacy markdown report
    legacy_content = """# Vulnerability Assessment & Penetration Test Report
**Security Management Platform V9.5**
| **Report ID** | `e49421bc-2021-4252-8030-d50e64c5b3e1` |
| **Authenticity Hash** | `3ca9522d3612d5fb250f57fef939e550...` |

### D. Report Integrity Attestation
This report was generated by the Security Management Platform (SMP) V9.5.
The authenticity hash below was computed over the canonical JSON representation of all report
data (excluding the hash field itself) using SHA-256.

```
REPORT-ID:    e49421bc-2021-4252-8030-d50e64c5b3e1
ENGAGEMENT:   ENG-2026-001
GENERATED-AT: 2026-08-14T19:15:43.745607+00:00
SHA-256:      3ca9522d3612d5fb250f57fef939e55086af9580c55cc58790e60f2f11e58a1d
```
"""
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(legacy_content)
        temp_path = tf.name

    try:
        res = verify_report(temp_path, verbose=False)
        assert res.verified is False
        assert res.status == "UNVERIFIABLE_LEGACY"
        assert res.integrity == "UNVERIFIABLE"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_keyed_hmac_authenticity(sample_json_report):
    """Verify that separate signing key produces and verifies authentic HMAC signatures."""
    signing_key = b"smp-enterprise-signing-secret-key-32b"
    wrong_key = b"wrong-attacker-secret-key-32b"

    rg = ReportGenerator(version="v9.5.5")
    signed_md = rg.generate_markdown_report(sample_json_report, signing_key=signing_key)

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(signed_md)
        temp_path = tf.name

    try:
        # 1. Verify with correct signing key
        res_ok = verify_report(temp_path, verbose=False, signing_key=signing_key)
        assert res_ok.verified is True
        assert res_ok.status == "AUTHENTICITY_VERIFIED"
        assert res_ok.integrity == "VERIFIED"
        assert res_ok.authenticity == "VERIFIED"

        # 2. Verify with wrong signing key
        res_wrong = verify_report(temp_path, verbose=False, signing_key=wrong_key)
        assert res_wrong.verified is False
        assert res_wrong.status == "AUTHENTICITY_FAILED"
        assert res_wrong.authenticity == "FAILED"

        # 3. Verify without signing key (integrity verified, authenticity unattested)
        res_nokey = verify_report(temp_path, verbose=False, signing_key=None)
        assert res_nokey.verified is True
        assert res_nokey.status == "INTEGRITY_VERIFIED"
        assert res_nokey.integrity == "VERIFIED"
        assert res_nokey.authenticity == "UNATTESTED"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_user_facing_status_distinguishes_integrity_from_authenticity(sample_json_report):
    """Verify user-facing verification output cleanly distinguishes integrity from authenticity."""
    rg = ReportGenerator(version="v9.5.5")
    md = rg.generate_markdown_report(sample_json_report)

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(md)
        temp_path = tf.name

    try:
        status, msg, details = verify_markdown_report(temp_path)
        assert status == "INTEGRITY_VERIFIED"
        assert details["integrity"] == "VERIFIED"
        assert details["authenticity"] == "UNATTESTED"
        assert "author authenticity unattested" in msg.lower() or "unkeyed" in msg.lower()
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
