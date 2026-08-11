"""
SMP Error Taxonomy
==================
Exception hierarchy with stable numeric codes for API, Scanner, DB, and Config failures.
"""

class SMPError(Exception):
    """Base exception for all SMP custom errors."""
    code = "SMP-9000"
    slug = "unclassified_error"
    
    def __init__(self, message: str, remediation: str = None):
        self.message = message
        self.remediation = remediation
        super().__init__(self.message)

    def to_dict(self):
        return {
            "code": self.code,
            "slug": self.slug,
            "message": self.message,
            "remediation": self.remediation or "Check troubleshooting guide."
        }

# ── 1xxx Auth/Session ──────────────────────────────────────────
class SMPAuthError(SMPError):
    code = "SMP-1000"
    slug = "auth_error"

class SMPTokenExpiredError(SMPAuthError):
    code = "SMP-1001"
    slug = "token_expired"

# ── 2xxx Scanner/Subprocess ────────────────────────────────────
class SMPScannerError(SMPError):
    code = "SMP-2000"
    slug = "scanner_error"

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

# ── 3xxx Database ─────────────────────────────────────────────
class SMPDatabaseError(SMPError):
    code = "SMP-3000"
    slug = "db_error"

class SMPDBConnectionError(SMPDatabaseError):
    code = "SMP-3001"
    slug = "db_connection_error"

class SMPDBEncryptionError(SMPDatabaseError):
    code = "SMP-3002"
    slug = "db_encryption_error"

# ── 4xxx API/Validation ───────────────────────────────────────
class SMPValidationError(SMPError):
    code = "SMP-4000"
    slug = "validation_error"

class SMPInvalidTargetError(SMPValidationError):
    code = "SMP-4001"
    slug = "invalid_target"

class SMPInvalidPayloadError(SMPValidationError):
    code = "SMP-4002"
    slug = "invalid_payload"

# ── 5xxx Config/Intelligence ──────────────────────────────────
class SMPConfigError(SMPError):
    code = "SMP-5000"
    slug = "config_error"

class SMPConfigMissingError(SMPConfigError):
    code = "SMP-5001"
    slug = "config_missing"

class SMPIntelSyncError(SMPConfigError):
    code = "SMP-5002"
    slug = "intel_sync_error"

# ── 9xxx Unclassified/Unexpected ───────────────────────────────
class SMPUnclassifiedError(SMPError):
    code = "SMP-9999"
    slug = "unexpected_error"


def handle_unclassified_error(e: Exception, logger=None) -> SMPUnclassifiedError:
    """Logs unexpected exceptions with traceback and returns an SMPUnclassifiedError instance to raise."""
    import traceback, logging
    log = logger or logging.getLogger("smp")
    log.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
    return SMPUnclassifiedError(str(e))

