"""
api/routes/osint.py
────────────────────────────────────────────────────────────────
REST endpoints for OSINT and Shadow IT discovery.

POST /api/osint/full            – full passive OSINT for a domain
POST /api/osint/subdomains      – subdomain enumeration only
POST /api/osint/dns             – DNS record collection
POST /api/osint/whois           – WHOIS lookup
POST /api/osint/cert            – TLS certificate analysis
GET  /api/osint/{scan_id}       – poll / fetch OSINT results

POST /api/shadow-it/discover    – full Shadow IT / forgotten-asset discovery
GET  /api/shadow-it/{scan_id}   – poll / fetch Shadow IT results
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, field_validator

from core.osint import OSINTEngine, OsintResult
from core.shadow_it import ShadowITDiscovery
from db.database import upsert_osint, upsert_shadow_it
from utils.helpers import get_logger, is_valid_domain

logger = get_logger(__name__)

osint_router  = APIRouter(prefix="/api/osint",     tags=["OSINT"])
shadow_router = APIRouter(prefix="/api/shadow-it", tags=["Shadow IT Discovery"])

osint_engine  = OSINTEngine()
shadow_engine = ShadowITDiscovery()


# ── Request models ────────────────────────────────────────────────────────────

class DomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        if not is_valid_domain(v):
            raise ValueError(f"Invalid domain: {v!r}")
        return v


class OsintResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# ── OSINT background tasks ────────────────────────────────────────────────────

async def _run_osint(domain: str, scan_id: str):
    try:
        result: OsintResult = await osint_engine.full_osint(domain, scan_id)
        await upsert_osint({
            "scan_id": scan_id,
            "domain": domain,
            "status": result.status,
            "result_json": result.to_dict(),
            "summary_json": result.summary,
            "total_subdomains": len(result.subdomains),
            "total_emails": len(result.emails),
            "error": result.error,
        })
        logger.info(
            f"[osint] {scan_id} done: "
            f"{len(result.subdomains)} subdomains, "
            f"{len(result.emails)} emails"
        )
    except Exception as e:
        logger.exception(f"[osint] task error: {e}")
        await upsert_osint({"scan_id": scan_id, "domain": domain,
                             "status": "failed", "error": str(e)})


async def _run_shadow_it(domain: str, scan_id: str):
    try:
        result = await shadow_engine.discover(domain, scan_id)
        await upsert_shadow_it({
            "scan_id": scan_id,
            "domain": domain,
            "status": result.status,
            "result_json": result.to_dict(),
            "summary_json": result.summary,
            "risk_score": result.risk_score,
            "total_findings": len(result.forgotten_assets),
            "ai_correlation": result.ai_correlation,
            "error": result.error,
        })
        logger.info(
            f"[shadow-it] {scan_id} done: "
            f"{len(result.forgotten_assets)} assets, "
            f"risk={result.risk_score:.1f}"
        )
    except Exception as e:
        logger.exception(f"[shadow-it] task error: {e}")
        await upsert_shadow_it({"scan_id": scan_id, "domain": domain,
                                 "status": "failed", "error": str(e)})


# ── OSINT endpoints ───────────────────────────────────────────────────────────

@osint_router.post("/full", response_model=OsintResponse, status_code=202)
async def start_full_osint(req: DomainRequest,
                            background_tasks: BackgroundTasks):
    """
    Full passive OSINT: subdomains, DNS, WHOIS, certs, emails,
    Shodan, technology fingerprinting.
    """
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(_run_osint, req.domain, scan_id)
    return OsintResponse(
        scan_id=scan_id, status="queued",
        message=f"OSINT scan started for {req.domain}"
    )


@osint_router.post("/subdomains", status_code=202)
async def enumerate_subdomains(req: DomainRequest,
                                background_tasks: BackgroundTasks):
    """Subdomain enumeration only (crt.sh + DNS brute + subfinder)."""
    scan_id = str(uuid.uuid4())

    async def task():
        subs = await osint_engine._enumerate_subdomains(req.domain)
        await upsert_osint({
            "scan_id": scan_id, "domain": req.domain, "status": "completed",
            "result_json": {"subdomains": [s.to_dict() for s in subs]},
            "total_subdomains": len(subs),
        })

    background_tasks.add_task(task)
    return {"scan_id": scan_id, "status": "queued"}


@osint_router.post("/dns")
async def collect_dns(req: DomainRequest):
    """Synchronous DNS record collection (fast)."""
    records = await osint_engine._collect_dns_records(req.domain)
    return {"domain": req.domain, "records": [r.to_dict() for r in records]}


@osint_router.post("/whois")
async def whois_lookup(req: DomainRequest):
    """Synchronous WHOIS lookup."""
    w = await osint_engine._run_whois(req.domain)
    if not w:
        raise HTTPException(status_code=404, detail="WHOIS data not found")
    return w.to_dict()


@osint_router.post("/cert")
async def certificate_info(req: DomainRequest):
    """Retrieve and analyse the TLS certificate for a domain."""
    cert = await osint_engine._check_cert(req.domain, 443)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert.to_dict()


@osint_router.get("/{scan_id}")
async def get_osint_result(scan_id: str):
    """Poll status or fetch full OSINT results."""
    from db.database import AsyncSessionLocal
    from db.models import OsintScan
    async with AsyncSessionLocal() as db:
        row = await db.get(OsintScan, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="OSINT scan not found")
    return {
        "scan_id": row.id,
        "domain": row.domain,
        "status": row.status,
        "started_at": str(row.started_at),
        "finished_at": str(row.finished_at),
        "summary": row.summary_json,
        "result": row.result_json,
        "error": row.error,
    }


# ── Shadow IT endpoints ───────────────────────────────────────────────────────

@shadow_router.post("/discover", response_model=OsintResponse, status_code=202)
async def start_shadow_it_discovery(req: DomainRequest,
                                     background_tasks: BackgroundTasks):
    """
    Full Shadow IT discovery:
    GitHub leaks, cloud buckets, Pastebin, Trello, AI correlation.
    """
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(_run_shadow_it, req.domain, scan_id)
    return OsintResponse(
        scan_id=scan_id, status="queued",
        message=f"Shadow IT discovery started for {req.domain}"
    )


@shadow_router.get("/{scan_id}")
async def get_shadow_it_result(scan_id: str):
    """Poll status or fetch full Shadow IT discovery results."""
    from db.database import AsyncSessionLocal
    from db.models import ShadowItScan
    async with AsyncSessionLocal() as db:
        row = await db.get(ShadowItScan, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Shadow IT scan not found")
    return {
        "scan_id": row.id,
        "domain": row.domain,
        "status": row.status,
        "started_at": str(row.started_at),
        "finished_at": str(row.finished_at),
        "risk_score": row.risk_score,
        "ai_correlation": row.ai_correlation,
        "summary": row.summary_json,
        "result": row.result_json,
        "error": row.error,
    }
