"""
api/routes/scan.py
────────────────────────────────────────────────────────────────
REST endpoints for all nmap-based network scanning operations.

POST /api/scan/discovery       – host discovery ping sweep
POST /api/scan/basic           – basic TCP SYN + service scan
POST /api/scan/vulnerability   – full NSE vuln scan
POST /api/scan/web             – HTTP/HTTPS web-service scan
POST /api/scan/full            – comprehensive all-port scan
POST /api/scan/local           – auto-scan local network
GET  /api/scan/{scan_id}       – poll scan status / results
GET  /api/scans                – list all scans
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, field_validator

from core.scanner import NetworkScanner
from core.remediation import RemediationEngine
from db.database import upsert_scan, save_playbook, get_scan_by_id
from utils.helpers import (
    get_logger, is_valid_ip, is_valid_cidr, is_valid_domain, utcnow_str
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/scan", tags=["Network Scanning"])
scanner = NetworkScanner()
remediation = RemediationEngine()


# ── Request / Response models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    ports: str = "1-1000"
    script_group: str = "vuln_basic"
    auto_remediate: bool = False
    deployment_context: Optional[dict] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        parts = v.split()
        for p in parts:
            if not (is_valid_ip(p) or is_valid_cidr(p) or is_valid_domain(p)):
                raise ValueError(f"Invalid target: {p!r}")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# ── Background task helpers ───────────────────────────────────────────────────

async def _run_and_persist(coro, scan_id: str, auto_remediate: bool = False,
                            deployment_context: Optional[dict] = None):
    """Execute a scan coroutine and persist results to DB."""
    try:
        result = await coro
        all_vulns = []
        for host in result.hosts:
            for vuln in host.vulnerabilities:
                vuln["os"] = host.os_match
                vuln["service"] = next(
                    (p.service for p in host.ports if p.port == vuln.get("port")),
                    ""
                )
                vuln["version"] = next(
                    (p.version for p in host.ports if p.port == vuln.get("port")),
                    ""
                )
                all_vulns.append(vuln)

        await upsert_scan({
            "scan_id": scan_id,
            "target": result.target,
            "scan_type": result.scan_type,
            "status": result.status,
            "result_json": result.to_dict(),
            "summary_json": result.summary,
            "hosts_up": result.summary.get("hosts_up", 0),
            "total_ports": result.summary.get("total_open_ports", 0),
            "total_vulns": result.summary.get("total_vulnerabilities", 0),
        })

        if auto_remediate and all_vulns:
            bundle = await remediation.generate_bundle(
                scan_id, result.target, all_vulns, deployment_context
            )
            for pb in bundle.playbooks:
                await save_playbook({**pb.to_dict(), "scan_id": scan_id})

        logger.info(f"[scan] {scan_id} completed — "
                    f"{len(result.hosts)} hosts, {len(all_vulns)} vulns")
    except Exception as e:
        logger.exception(f"[scan] background task error: {e}")
        await upsert_scan({
            "scan_id": scan_id, "status": "failed",
            "target": "", "scan_type": "",
        })


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/discovery", response_model=ScanResponse, status_code=202)
async def start_discovery_scan(req: ScanRequest,
                                background_tasks: BackgroundTasks):
    """Fast ICMP/TCP ping sweep to discover live hosts."""
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_and_persist,
        scanner.discovery_scan(req.target, scan_id),
        scan_id,
    )
    return ScanResponse(scan_id=scan_id, status="queued",
                         message=f"Discovery scan started for {req.target}")


@router.post("/basic", response_model=ScanResponse, status_code=202)
async def start_basic_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """TCP SYN scan with service/version detection."""
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_and_persist,
        scanner.basic_scan(req.target, scan_id, req.ports),
        scan_id,
        req.auto_remediate,
        req.deployment_context,
    )
    return ScanResponse(scan_id=scan_id, status="queued",
                         message=f"Basic scan started for {req.target}")


@router.post("/vulnerability", response_model=ScanResponse, status_code=202)
async def start_vulnerability_scan(req: ScanRequest,
                                    background_tasks: BackgroundTasks):
    """Full NSE vulnerability scan with automated remediation option."""
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_and_persist,
        scanner.vulnerability_scan(req.target, scan_id,
                                    req.ports, req.script_group),
        scan_id,
        req.auto_remediate,
        req.deployment_context,
    )
    return ScanResponse(scan_id=scan_id, status="queued",
                         message=f"Vulnerability scan started for {req.target}")


@router.post("/web", response_model=ScanResponse, status_code=202)
async def start_web_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """HTTP/HTTPS web-service scan (ports 80, 443, 8080, 8443, …)."""
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_and_persist,
        scanner.web_scan(req.target, scan_id),
        scan_id,
        req.auto_remediate,
        req.deployment_context,
    )
    return ScanResponse(scan_id=scan_id, status="queued",
                         message=f"Web scan started for {req.target}")


@router.post("/full", response_model=ScanResponse, status_code=202)
async def start_full_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """Comprehensive all-port scan (slow – single host recommended)."""
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_and_persist,
        scanner.full_scan(req.target, scan_id),
        scan_id,
        req.auto_remediate,
        req.deployment_context,
    )
    return ScanResponse(scan_id=scan_id, status="queued",
                         message=f"Full scan started for {req.target}")


@router.post("/local", response_model=ScanResponse, status_code=202)
async def start_local_scan(background_tasks: BackgroundTasks,
                            auto_remediate: bool = False):
    """Auto-discover and scan all subnets on this machine."""
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(
        _run_and_persist,
        scanner.local_network_scan(scan_id),
        scan_id,
        auto_remediate,
    )
    return ScanResponse(scan_id=scan_id, status="queued",
                         message="Local network scan started")


@router.get("/{scan_id}")
async def get_scan_result(scan_id: str):
    """Poll scan status or fetch completed results."""
    # First check in-memory (still running)
    in_mem = scanner.get_scan(scan_id)
    if in_mem:
        return in_mem.to_dict()

    # Then DB
    db_scan = await get_scan_by_id(scan_id)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": db_scan.id,
        "target": db_scan.target,
        "scan_type": db_scan.scan_type,
        "status": db_scan.status,
        "started_at": str(db_scan.started_at),
        "finished_at": str(db_scan.finished_at),
        "summary": db_scan.summary_json,
        "result": db_scan.result_json,
        "error": db_scan.error,
    }


@router.get("")
async def list_scans(limit: int = Query(20, le=100), offset: int = 0):
    """List recent scans."""
    from sqlalchemy import select, desc
    from db.database import AsyncSessionLocal
    from db.models import Scan as ScanModel
    async with AsyncSessionLocal() as db:
        stmt = (
            select(ScanModel)
            .order_by(desc(ScanModel.started_at))
            .limit(limit)
            .offset(offset)
        )
        rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "scan_id": r.id,
            "target": r.target,
            "scan_type": r.scan_type,
            "status": r.status,
            "started_at": str(r.started_at),
            "finished_at": str(r.finished_at),
            "hosts_up": r.hosts_up,
            "total_vulns": r.total_vulns,
        }
        for r in rows
    ]
