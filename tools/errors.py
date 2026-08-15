"""
SMP Error Taxonomy — V9.5 Security Data Pipeline
=================================================
Hierarchical exception architecture with stable numeric error codes across:
  - 1xxx: Auth, Session & Cryptographic Key Hierarchy (KEK/DEK/IEK/EEK)
  - 2xxx: Scanner Execution, DAG Orchestration & State Machine
  - 3xxx: Database, SQLCipher & Storage Pipeline
  - 4xxx: Evidence Store, Reporting & Authenticity Verification
  - 5xxx: Threat Intelligence, CVE Correlation & Deduplication
  - 6xxx: Scope Engine & Scan Policy
  - 9xxx: Unclassified / Internal Exceptions
"""

from typing import Optional, Dict, Any


class SMPError(Exception):
    """Base exception for all SMP custom errors."""
    code: str = "SMP-9000"
    slug: str = "unclassified_error"
    category: str = "System"
    
    def __init__(self, message: str, remediation: Optional[str] = None):
        self.message = message
        self.remediation = remediation or "Consult troubleshooting/README.md or run 'python3 tools/troubleshoot.py --fix'."
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        msg = self.message
        # Sanitize sensitive exception details for 9xxx unclassified errors
        if self.code.startswith("SMP-9"):
            msg = "An unexpected internal error occurred."
        return {
            "code": self.code,
            "slug": self.slug,
            "category": self.category,
            "message": msg,
            "remediation": self.remediation,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 1xxx — Authentication, Session & Cryptographic Key Hierarchy
# ─────────────────────────────────────────────────────────────────────────────

class SMPAuthError(SMPError):
    code = "SMP-1000"
    slug = "auth_error"
    category = "Authentication"


class SMPTokenExpiredError(SMPAuthError):
    code = "SMP-1001"
    slug = "token_expired"


class SMPInvalidCredentialsError(SMPAuthError):
    code = "SMP-1002"
    slug = "invalid_credentials"


class SMPPasswordPolicyViolationError(SMPAuthError):
    code = "SMP-1003"
    slug = "password_policy_violation"


class SMPKEKDerivationError(SMPAuthError):
    code = "SMP-1004"
    slug = "kek_derivation_failed"


class SMPDEKUnavailableError(SMPAuthError):
    code = "SMP-1005"
    slug = "dek_unavailable"


class SMPIEKUnavailableError(SMPAuthError):
    code = "SMP-1006"
    slug = "iek_unavailable"


class SMPEEKUnavailableError(SMPAuthError):
    code = "SMP-1007"
    slug = "eek_unavailable"


class SMPKeyRotationError(SMPAuthError):
    code = "SMP-1008"
    slug = "key_rotation_failed"


class SMPAuthFileCorruptError(SMPAuthError):
    code = "SMP-1009"
    slug = "auth_file_corrupt"


# ─────────────────────────────────────────────────────────────────────────────
# 2xxx — Scanner Execution, DAG Orchestration & State Machine
# ─────────────────────────────────────────────────────────────────────────────

class SMPScannerError(SMPError):
    code = "SMP-2000"
    slug = "scanner_error"
    category = "Scanner Execution"


class SMPScannerTimeoutError(SMPScannerError):
    code = "SMP-2001"
    slug = "scanner_timeout"


class SMPScannerBinaryMissingError(SMPScannerError):
    code = "SMP-2002"
    slug = "scanner_binary_missing"


class SMPScannerCrashedError(SMPScannerError):
    code = "SMP-2003"
    slug = "scanner_crashed"


class SMPScannerOutputParseError(SMPScannerError):
    code = "SMP-2004"
    slug = "scanner_output_parse_error"


class SMPDAGCycleError(SMPScannerError):
    code = "SMP-2005"
    slug = "dag_cycle_detected"


class SMPInvalidStateTransitionError(SMPScannerError):
    code = "SMP-2006"
    slug = "invalid_state_transition"


class SMPSandboxIsolationError(SMPScannerError):
    code = "SMP-2007"
    slug = "sandbox_isolation_violation"


class SMPMissingDependencyToolError(SMPScannerError):
    code = "SMP-2008"
    slug = "missing_dependency_tool"


class SMPResourceLimitExceededError(SMPScannerError):
    code = "SMP-2009"
    slug = "resource_limit_exceeded"


class SMPAdapterManifestInvalidError(SMPScannerError):
    code = "SMP-2010"
    slug = "adapter_manifest_invalid"


# ─────────────────────────────────────────────────────────────────────────────
# 3xxx — Database, SQLCipher & Storage Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class SMPDatabaseError(SMPError):
    code = "SMP-3000"
    slug = "db_error"
    category = "Database"


class SMPDBConnectionError(SMPDatabaseError):
    code = "SMP-3001"
    slug = "db_connection_error"


class SMPDBEncryptionError(SMPDatabaseError):
    code = "SMP-3002"
    slug = "db_encryption_error"


class SMPDBWALModeLockedError(SMPDatabaseError):
    code = "SMP-3003"
    slug = "db_wal_locked"


class SMPDBIntegrityCheckError(SMPDatabaseError):
    code = "SMP-3004"
    slug = "db_integrity_check_failed"


class SMPDBMigrationError(SMPDatabaseError):
    code = "SMP-3005"
    slug = "db_migration_error"


class SMPRawOutputStorageError(SMPDatabaseError):
    code = "SMP-3006"
    slug = "raw_output_storage_failed"


class SMPRedundancyDBError(SMPDatabaseError):
    code = "SMP-3007"
    slug = "redundancy_db_failed"


# ─────────────────────────────────────────────────────────────────────────────
# 4xxx — Evidence Store, Reporting & Authenticity Verification
# ─────────────────────────────────────────────────────────────────────────────

class SMPValidationError(SMPError):
    code = "SMP-4000"
    slug = "validation_error"
    category = "Validation & Reporting"


class SMPInvalidTargetError(SMPValidationError):
    code = "SMP-4001"
    slug = "invalid_target"


class SMPInvalidPayloadError(SMPValidationError):
    code = "SMP-4002"
    slug = "invalid_payload"


class SMPEvidenceStorageError(SMPValidationError):
    code = "SMP-4010"
    slug = "evidence_storage_error"


class SMPEvidenceNotFoundError(SMPValidationError):
    code = "SMP-4011"
    slug = "evidence_not_found"


class SMPEvidenceTamperDetectedError(SMPValidationError):
    code = "SMP-4012"
    slug = "evidence_tamper_detected"


class SMPReportGenerationError(SMPValidationError):
    code = "SMP-4020"
    slug = "report_generation_error"


class SMPReportAuthenticityError(SMPValidationError):
    code = "SMP-4021"
    slug = "report_authenticity_failed"


class SMPWeasyprintRenderError(SMPValidationError):
    code = "SMP-4022"
    slug = "weasyprint_render_error"


class SMPExploitTimeoutError(SMPValidationError):
    code = "SMP-4040"
    slug = "exploit_timeout"


class SMPBinaryIncompatibilityError(SMPValidationError):
    code = "SMP-4041"
    slug = "binary_incompatibility"


class SMPPortCollisionError(SMPValidationError):
    code = "SMP-4042"
    slug = "port_collision"


# Enterprise Data Export Errors
class SMPExportDeniedError(SMPValidationError):
    """Raised when an export is attempted without explicit I AGREE legal gate confirmation."""
    code = "SMP-4050"
    slug = "export_gate_not_confirmed"
    category = "Evidence & Reporting"


class SMPExportPayloadError(SMPValidationError):
    """Raised when the export payload cannot be built (serialization error)."""
    code = "SMP-4051"
    slug = "export_payload_build_failed"
    category = "Evidence & Reporting"


class SMPExportAuditWriteError(SMPValidationError):
    """Raised when the export audit record cannot be persisted to the encrypted DB."""
    code = "SMP-4052"
    slug = "export_audit_write_failed"
    category = "Evidence & Reporting"


# ─────────────────────────────────────────────────────────────────────────────
# 5xxx — Threat Intelligence, CVE Correlation & Deduplication
# ─────────────────────────────────────────────────────────────────────────────


class SMPConfigError(SMPError):
    code = "SMP-5000"
    slug = "config_error"
    category = "Intelligence & Config"


class SMPConfigMissingError(SMPConfigError):
    code = "SMP-5001"
    slug = "config_missing"


class SMPIntelSyncError(SMPConfigError):
    code = "SMP-5002"
    slug = "intel_sync_error"


class SMPVulnerabilityDBMissingError(SMPConfigError):
    code = "SMP-5003"
    slug = "vulnerability_db_missing"


class SMPCPEParsingError(SMPConfigError):
    code = "SMP-5004"
    slug = "cpe_parsing_error"


class SMPDeduplicationEngineError(SMPConfigError):
    code = "SMP-5005"
    slug = "deduplication_engine_error"


class SMPMitreMappingError(SMPConfigError):
    code = "SMP-5006"
    slug = "mitre_mapping_error"


class SMPLocalOnlyViolationError(SMPConfigError):
    code = "SMP-5007"
    slug = "local_only_violation"


# ─────────────────────────────────────────────────────────────────────────────
# 6xxx — Scope Engine & Scan Policy
# ─────────────────────────────────────────────────────────────────────────────

class SMPScopeViolationError(SMPError):
    code = "SMP-6000"
    slug = "scope_violation"
    category = "Scope & Policy"


class SMPScopeRuleSyntaxError(SMPScopeViolationError):
    code = "SMP-6001"
    slug = "scope_rule_syntax_error"


class SMPScanPolicyRestrictedError(SMPScopeViolationError):
    code = "SMP-6002"
    slug = "scan_policy_restricted"


class SMPRateLimitExceededError(SMPScopeViolationError):
    code = "SMP-6003"
    slug = "rate_limit_exceeded"


class SMPIntrusiveScanDeniedError(SMPScopeViolationError):
    code = "SMP-6004"
    slug = "intrusive_scan_denied"


class SMPTimeWindowClosedError(SMPScopeViolationError):
    code = "SMP-6005"
    slug = "time_window_closed"


class SMPResponsibilityAttestationMissingError(SMPScopeViolationError):
    code = "SMP-6006"
    slug = "responsibility_attestation_missing"


# ─────────────────────────────────────────────────────────────────────────────
# 9xxx — Unclassified / Unexpected Errors
# ─────────────────────────────────────────────────────────────────────────────

class SMPUnclassifiedError(SMPError):
    code = "SMP-9999"
    slug = "unexpected_error"
    category = "System"


def handle_unclassified_error(e: Exception, logger=None) -> SMPUnclassifiedError:
    """Logs unexpected exceptions with traceback and returns an SMPUnclassifiedError instance to raise."""
    import traceback
    import logging
    log = logger or logging.getLogger("smp")
    log.error(f"Unexpected system error: {e}\n{traceback.format_exc()}")
    return SMPUnclassifiedError(str(e))
