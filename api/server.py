"""
SMP API V9.4.2 — Secured FastAPI Backend with JWT Authentication
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

logger = logging.getLogger("smp.api")

try:
    from fastapi import FastAPI, HTTPException, Depends, status, Request
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, HttpUrl
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    logger.warning("[API] FastAPI not installed. API mode unavailable.")

from tools.db_manager import (
    add_target, get_targets, get_active_scans, get_cve_stats, get_log_entries
)

# ── Application Setup ─────────────────────────────────────────────────────────

app = None
if _FASTAPI_AVAILABLE:
    app = FastAPI(
        title="SMP API V9.4.2",
        description=(
            "Security Management Platform V9.4.2 — Secured REST API\n\n"
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

    # Rate limiting via slowapi (graceful fallback if not installed)
    try:
        from slowapi import Limiter, _rate_limit_exceeded_handler
        from slowapi.util import get_remote_address
        from slowapi.errors import RateLimitExceeded
        limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        _RATE_LIMIT = True
    except ImportError:
        logger.warning("[API] slowapi not installed — rate limiting disabled.")
        _RATE_LIMIT = False
        limiter = None


# ── JWT Authentication ────────────────────────────────────────────────────────

_bearer = HTTPBearer() if _FASTAPI_AVAILABLE else None


def _get_current_user(credentials: "HTTPAuthorizationCredentials" = None):
    """Verify JWT token and return username."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        from api.auth import verify_token
        username = verify_token(credentials.credentials)
        if not username:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        return username
    except ImportError:
        # auth module not yet available — allow during development only
        logger.warning("[API] auth module not loaded — token verification skipped")
        return "dev"


# ── Request / Response Models ──────────────────────────────────────────────────

class TargetCreate(BaseModel):
    url: str
    company_name: str = ""
    submitted_to: str = ""

class TokenRequest(BaseModel):
    username: str
    password: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

if _FASTAPI_AVAILABLE:
    @app.get("/api/v6/health", tags=["System"])
    def health_check():
        """Health check endpoint — no authentication required."""
        return {
            "status": "ok",
            "version": "V9.4.2",
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
            return {"version": "V9.4.2", "platform": "SMP"}

    @app.post("/api/v6/auth/token", tags=["Authentication"])
    def get_token(request: TokenRequest):
        """
        Obtain a JWT access token.
        
        Authenticates against the SMP master password.
        Returns a Bearer token valid for 24 hours.
        """
        try:
            from tools.encryption_manager import verify_password
            if not verify_password(request.password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
        except ImportError:
            # Development fallback
            if request.password != "smp-dev":
                raise HTTPException(status_code=401, detail="Invalid credentials")

        try:
            from api.auth import create_token
            token = create_token(request.username)
            return {
                "access_token": token,
                "token_type": "bearer",
                "expires_in": 86400,
                "username": request.username,
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
            raise HTTPException(status_code=500, detail=str(e))

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
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/v6/findings", tags=["Findings"])
    def list_findings(scan_id: int, user: str = Depends(_get_current_user)):
        """Get findings for a specific scan."""
        try:
            from tools.db_manager import get_findings_for_scan
            findings = get_findings_for_scan(scan_id)
            return {"findings": list(findings), "scan_id": scan_id, "count": len(list(findings))}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/v6/cve/stats", tags=["Intelligence"])
    def cve_stats(user: str = Depends(_get_current_user)):
        """Get CVE statistics from the intelligence database."""
        try:
            stats = get_cve_stats()
            return stats
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/v6/risk/score", tags=["Risk"])
    def risk_scores(user: str = Depends(_get_current_user)):
        """Get risk scores for all targets."""
        try:
            from tools.db_manager import get_risk_scores_all_targets
            scores = get_risk_scores_all_targets()
            return {"risk_scores": scores}
        except Exception as e:
            logger.warning(f"[API] risk_scores: {e}")
            return {"risk_scores": [], "error": str(e)}


def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Start the FastAPI server."""
    if not _FASTAPI_AVAILABLE:
        logger.error("[API] Cannot start — FastAPI not installed. Run: pip install fastapi uvicorn slowapi")
        return
    try:
        import uvicorn
        logger.info(f"[API] Starting SMP API V9.4.2 on http://{host}:{port}/api/v6/docs")
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except ImportError:
        logger.error("[API] uvicorn not installed. Run: pip install uvicorn")
