"""
SMP API V9.4.3 — Secured FastAPI Backend with JWT Authentication
==============================================================
Full REST API with:
  - JWT Bearer token authentication on all endpoints
  - Rate limiting (100 req/min per IP, configurable)
  - Versioned prefix: /api/v6/
  - Auto-documented Swagger UI at /api/v6/docs

Endpoints:
  POST /api/v6/auth/token     — get JWT token (username/password)
  GET  /api/v6/health         — health check (unauthenticated)
  GET  /api/v6/target         — list all targets
  POST /api/v6/target         — add a new target
  GET  /api/v6/scan           — list scans (optionally filtered by target)
  GET  /api/v6/findings       — list findings (filtered by scan_id)
  GET  /api/v6/cve/stats      — CVE statistics
  GET  /api/v6/risk/score     — risk scores per target
  GET  /api/v6/version        — platform version info
"""
import os
import logging
import hashlib
from datetime import datetime
from typing import Optional

logger = logging.getLogger("smp.api")

try:
    from fastapi import FastAPI, HTTPException, Depends, status, Request
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, HttpUrl, field_validator, Field
    from tools.errors import SMPError, SMPInvalidTargetError, SMPInvalidPayloadError, SMPDatabaseError
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    logger.warning("[API] FastAPI not installed. API mode unavailable.")
    BaseModel = object
    def field_validator(*args, **kwargs):
        def dec(fn): return fn
        return dec
    def Field(*args, **kwargs):
        return None
    from tools.errors import SMPError, SMPInvalidTargetError, SMPInvalidPayloadError, SMPDatabaseError

from tools.db_manager import (
    add_target, get_targets, get_active_scans, get_cve_stats, get_log_entries
)

# ── Application Setup ─────────────────────────────────────────────────────────

app = None
if _FASTAPI_AVAILABLE:
    app = FastAPI(
        title="SMP API V9.5",
        description=(
            "Security Management Platform V9.5 — Secured REST API\n\n"
            "All endpoints except `/api/v6/health` and `/api/v6/auth/token` "
            "require a valid JWT Bearer token.\n\n"
            "**@mrQhere — Internal Use Only**"
        ),
        version="6.0",
        docs_url="/api/v6/docs",
        redoc_url="/api/v6/redoc",
        openapi_url="/api/v6/openapi.json",
    )

    # CORS — restrict to localhost in production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost", "http://127.0.0.1"],
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Rate limiting via slowapi (hard dependency for security)
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    @app.exception_handler(SMPError)
    async def smp_error_handler(request: Request, exc: SMPError):
        return JSONResponse(
            status_code=400 if exc.code.startswith("SMP-4") else 500,
            content=exc.to_dict(),
        )
        
    from fastapi.exceptions import RequestValidationError
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        from tools.errors import SMPValidationError, SMPInvalidTargetError, SMPInvalidPayloadError
        for err in exc.errors():
            ctx = err.get("ctx", {})
            error_obj = ctx.get("error")
            if isinstance(error_obj, SMPError):
                return JSONResponse(status_code=400, content=error_obj.to_dict())
            loc = err.get("loc", ())
            msg = err.get("msg", "")
            if "url" in loc or "target_url" in loc or "invalid_target" in str(err) or "URL" in msg:
                clean_msg = msg.split(", ", 1)[-1] if ", " in msg else msg
                return JSONResponse(status_code=400, content=SMPInvalidTargetError(clean_msg).to_dict())
            if "username" in loc or "alphanumeric" in msg:
                return JSONResponse(status_code=400, content=SMPInvalidPayloadError("Username must be alphanumeric.").to_dict())

        # Fallback to generic validation error
        return JSONResponse(
            status_code=400,
            content=SMPValidationError(f"Invalid payload: {exc.errors()}").to_dict()
        )
        
    _RATE_LIMIT = True


# ── JWT Authentication ────────────────────────────────────────────────────────

# Server-defined subject for the single-administrator model.
# The JWT `sub` claim is ALWAYS this constant, regardless of what username
# the caller supplies in the token request.  In a single-admin system, the
# only meaningful authenticated identity is "the holder of the master password".
# If SMP is ever extended to support per-account records, resolve the subject
# from the account store here instead.
_ADMIN_SUBJECT = "smp-admin"

_bearer = HTTPBearer() if _FASTAPI_AVAILABLE else None


def _get_current_user(credentials: "HTTPAuthorizationCredentials" = Depends(_bearer) if _bearer else None):
    """Verify JWT token and return username."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    from api.auth import verify_token
    username = verify_token(credentials.credentials)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return username


# ── Request / Response Models ──────────────────────────────────────────────────

class TargetCreate(BaseModel):
    url: str = Field(..., description="Target URL")
    company_name: str = ""
    submitted_to: str = ""

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        from core.url_validator import parse_and_canonicalize_url, check_destination_allowed
        from tools.errors import SMPInvalidTargetError
        parsed = parse_and_canonicalize_url(v)
        allowed, reason = check_destination_allowed(parsed)
        if not allowed:
            raise SMPInvalidTargetError(f"Forbidden destination: {reason}")
        return parsed.url

class TokenRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=1)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not v.isalnum():
            raise SMPInvalidPayloadError("Username must be alphanumeric.")
        return v

class ScanStartRequest(BaseModel):
    target_url: Optional[str] = None
    target_id: Optional[int] = None
    engagement_id: Optional[str] = "default"
    auth_id: Optional[str] = None
    activity_level: Optional[str] = None

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v):
        if v is not None:
            from core.url_validator import parse_and_canonicalize_url, check_destination_allowed
            from tools.errors import SMPInvalidTargetError
            parsed = parse_and_canonicalize_url(v)
            allowed, reason = check_destination_allowed(parsed)
            if not allowed:
                raise SMPInvalidTargetError(f"Forbidden destination: {reason}")
            return parsed.url
        return v


# ── Endpoints ─────────────────────────────────────────────────────────────────

if _FASTAPI_AVAILABLE:
    @app.get("/api/v6/health", tags=["System"])
    def health_check():
        """Health check endpoint — no authentication required."""
        return {
            "status": "ok",
            "version": "V9.5",
            "platform": "Security Management Platform",
            "organization": "mrQhere",
            "timestamp": datetime.now().isoformat(),
        }

    @app.get("/api/v6/version", tags=["System"])
    def get_version(user: str = Depends(_get_current_user)):
        """Get platform version information."""
        try:
            import json
            from tools.config_manager import BASE_DIR
            meta_path = os.path.join(BASE_DIR, "config", "metadata.json")
            with open(meta_path) as f:
                meta = json.load(f)
            return meta
        except Exception:
            return {"version": "V9.5", "platform": "SMP"}

    @app.post("/api/v6/auth/token", tags=["Authentication"])
    def get_token(request: TokenRequest):
        """
        Obtain a JWT access token.
        
        Authenticates against the SMP master password.
        Returns a Bearer token valid for 24 hours.
        """
        from tools.encryption_manager import verify_password
        if not verify_password(request.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        try:
            from api.auth import create_token
            # Subject is always the server-defined administrator constant.
            # request.username is accepted in the request body for
            # forward-compatibility but is NOT used to set the JWT subject.
            token = create_token(_ADMIN_SUBJECT)
            return {
                "access_token": token,
                "token_type": "bearer",
                "expires_in": 86400,
                "subject": _ADMIN_SUBJECT,
            }
        except Exception as e:
            logger.error(f"[API] Token creation failed: {e}")
            raise HTTPException(status_code=500, detail="Token generation failed")

    @app.get("/api/v6/target", tags=["Targets"])
    def list_targets(user: str = Depends(_get_current_user)):
        """List all configured scan targets."""
        try:
            targets = get_targets()
            return {"targets": targets, "count": len(targets)}
        except Exception as e:
            logger.error(f"[API] list_targets error: {e}")
            from tools.errors import SMPDatabaseError
            raise SMPDatabaseError("Failed to fetch targets.")

    @app.post("/api/v6/target", tags=["Targets"])
    def create_target(target: TargetCreate, user: str = Depends(_get_current_user)):
        """Add a new scan target."""
        success = add_target(str(target.url), target.company_name, target.submitted_to)
        if not success:
            raise HTTPException(status_code=400, detail="Target already exists or invalid URL.")
        logger.info(f"[API] Target added by {user}: {target.url}")
        return {"status": "success", "message": f"Target {target.url} added.", "added_by": user}

    @app.get("/api/v6/scan", tags=["Scans"])
    def list_scans(user: str = Depends(_get_current_user)):
        """List all active/recent scans."""
        try:
            scans = get_active_scans()
            return {"scans": scans, "count": len(scans)}
        except Exception as e:
            logger.error(f"[API] list_scans error: {e}")
            from tools.errors import SMPDatabaseError
            raise SMPDatabaseError("Failed to fetch scans.")

    @app.post("/api/v6/scan", tags=["Scans"])
    def start_scan_endpoint(scan_req: ScanStartRequest, user: str = Depends(_get_current_user)):
        """Start a new scan through the server-side execution gate."""
        target_url = scan_req.target_url
        target_id = scan_req.target_id
        
        if not target_url and target_id:
            from tools.db_manager import get_target
            t = get_target(target_id)
            if t:
                target_url = t.get("url")
            else:
                raise HTTPException(status_code=404, detail="Target not found")
        elif not target_url:
            raise HTTPException(status_code=400, detail="target_id or target_url required")

        # ── V9.5.10 Server-side execution gate check ──────────────────────────
        from core.execution_gate import verify_scan_execution
        allowed, reason = verify_scan_execution(
            target=target_url,
            engagement_id=scan_req.engagement_id or "default",
            auth_id=scan_req.auth_id,
            scanner_activity=scan_req.activity_level,
        )
        if not allowed:
            logger.warning(f"[API] Scan execution blocked for {target_url}: {reason}")
            raise HTTPException(status_code=403, detail=f"Execution gate rejected: {reason}")

        from scanners.scan_runner import start_scan_for_target
        target_dict = {
            "id": target_id or 0,
            "url": target_url,
            "engagement_id": scan_req.engagement_id,
            "auth_id": scan_req.auth_id,
        }
        started = start_scan_for_target(target_dict)
        if not started:
            raise HTTPException(status_code=409, detail="Scan could not be started or already active")

        return {"status": "started", "target": target_url, "started_by": user}

    @app.get("/api/v6/findings", tags=["Findings"])
    def list_findings(scan_id: int, user: str = Depends(_get_current_user)):
        """Get findings for a specific scan."""
        if scan_id <= 0:
            from tools.errors import SMPInvalidPayloadError
            raise SMPInvalidPayloadError("scan_id must be a positive integer.")
        try:
            from tools.db_manager import get_findings_for_scan
            findings = get_findings_for_scan(scan_id)
            return {"findings": list(findings), "scan_id": scan_id, "count": len(list(findings))}
        except Exception as e:
            logger.error(f"[API] list_findings error: {e}")
            from tools.errors import SMPDatabaseError
            raise SMPDatabaseError("Failed to fetch findings.")

    @app.get("/api/v6/cve/stats", tags=["Intelligence"])
    def cve_stats(user: str = Depends(_get_current_user)):
        """Get CVE statistics from the intelligence database."""
        try:
            stats = get_cve_stats()
            return stats
        except Exception as e:
            logger.error(f"[API] cve_stats error: {e}")
            from tools.errors import SMPDatabaseError
            raise SMPDatabaseError("Failed to fetch stats.")

    @app.get("/api/v6/risk/score", tags=["Risk"])
    def risk_scores(user: str = Depends(_get_current_user)):
        """Get risk scores for all targets."""
        try:
            from tools.db_manager import get_risk_scores_all_targets
            scores = get_risk_scores_all_targets()
            return {"risk_scores": scores}
        except Exception as e:
            logger.warning(f"[API] risk_scores error: {e}")
            from tools.errors import SMPDatabaseError
            raise SMPDatabaseError("Failed to fetch risk scores.")


def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Start the FastAPI server."""
    host = os.environ.get("SMP_API_HOST", host)
    if not _FASTAPI_AVAILABLE:
        logger.error("[API] Cannot start — FastAPI not installed. Run: pip install fastapi uvicorn slowapi")
        return
    try:
        import uvicorn
        logger.info(f"[API] Starting SMP API V9.5 on http://{host}:{port}/api/v6/docs")
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except ImportError:
        logger.error("[API] uvicorn not installed. Run: pip install uvicorn")
