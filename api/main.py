"""
api/main.py
────────────────────────────────────────────────────────────────
FastAPI application entrypoint.
Mounts all routers, configures CORS for web-UI integration,
and initialises the database on startup.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes.scan import router as scan_router
from api.routes.osint import osint_router, shadow_router
from api.routes.remediation import router as remediation_router
from api.routes.reports import router as reports_router
from db.database import init_db
from utils.config import settings
from utils.helpers import get_logger

logger = get_logger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("╔══════════════════════════════════════════╗")
    logger.info("║  Smart Security Analyzer – API starting  ║")
    logger.info("╚══════════════════════════════════════════╝")
    await init_db()
    logger.info("[startup] database ready")
    from core.scheduler import scheduler
    await scheduler.start()
    logger.info("[startup] scheduler running")
    yield
    await scheduler.stop()
    logger.info("[shutdown] goodbye")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Smart Network & Security Analyzer",
    description="""
## Intelligent Network Security Analysis Platform

### Features
- **Network Scanning** – nmap-powered host discovery, port scanning, OS/service detection, NSE vuln scripts
- **OSINT Engine** – subdomain enumeration, DNS, WHOIS, certificate analysis, technology fingerprinting
- **Shadow IT Discovery** – GitHub leak detection, cloud bucket enumeration, Pastebin/Trello hunting, AI correlation
- **AI Remediation Engine** – Claude-powered self-healing playbooks with runnable scripts for every vulnerability

### Authentication
Currently open for local deployment. Add `SECRET_KEY` to `.env` and uncomment JWT middleware for production.
    """,
    version="1.0.0",
    contact={"name": "Security Analyzer", "url": "https://github.com/your-org/smart-security-analyzer"},
    lifespan=lifespan,
)


# ── CORS ──────────────────────────────────────────────────────────────────────
# Allow the frontend web app (React/Vue/etc.) to call this API

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Restrict in production: ["http://localhost:3000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(scan_router)
app.include_router(osint_router)
app.include_router(shadow_router)
app.include_router(remediation_router)
app.include_router(reports_router)


# ── Health & Info ─────────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
async def root():
    return {
        "service": "Smart Network & Security Analyzer",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
        "endpoints": {
            "scan": "/api/scan",
            "osint": "/api/osint",
            "shadow_it": "/api/shadow-it",
            "remediation": "/api/remediation",
            "reports": "/api/reports",
            "schedule": "/api/schedule",
            "vuln_analysis": "/api/vulns",
        },
    }


@app.get("/health", tags=["System"])
async def health():
    import shutil
    nmap_ok = bool(shutil.which("nmap"))
    ai_ok = bool(settings.anthropic_api_key)
    return {
        "status": "ok",
        "nmap_available": nmap_ok,
        "ai_remediation": ai_ok,
        "shodan_enabled": bool(settings.shodan_api_key),
        "github_token": bool(settings.github_token),
    }


@app.get("/api/stats", tags=["System"])
async def get_stats():
    """Summary statistics across all scans."""
    from db.database import AsyncSessionLocal
    from db.models import Scan, OsintScan, ShadowItScan, RemediationPlaybook, Vulnerability
    from sqlalchemy import select, func

    async with AsyncSessionLocal() as db:
        scan_count = (await db.execute(select(func.count(Scan.id)))).scalar()
        osint_count = (await db.execute(select(func.count(OsintScan.id)))).scalar()
        shadow_count = (await db.execute(select(func.count(ShadowItScan.id)))).scalar()
        pb_count = (await db.execute(select(func.count(RemediationPlaybook.id)))).scalar()
        vuln_count = (await db.execute(select(func.count(Vulnerability.id)))).scalar()
        crit = (await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.severity == "CRITICAL")
        )).scalar()
        high = (await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.severity == "HIGH")
        )).scalar()

    return {
        "total_network_scans": scan_count,
        "total_osint_scans": osint_count,
        "total_shadow_it_scans": shadow_count,
        "total_playbooks_generated": pb_count,
        "total_vulnerabilities_found": vuln_count,
        "critical_vulns": crit,
        "high_vulns": high,
    }


# ── Global exception handler ──────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.exception(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc), "type": type(exc).__name__},
    )
