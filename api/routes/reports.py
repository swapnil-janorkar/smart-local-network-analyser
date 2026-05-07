"""
api/routes/reports.py
────────────────────────────────────────────────────────────────
REST endpoints for report generation, vulnerability analysis,
and scheduled scan management.

POST /api/reports/generate/{scan_id}   – generate HTML + JSON + TXT report
GET  /api/reports/{scan_id}/html       – serve HTML report
GET  /api/reports/{scan_id}/json       – serve JSON report
GET  /api/reports/{scan_id}/txt        – serve text summary

POST /api/vulns/analyze/{scan_id}      – enrich and analyse scan vulns
GET  /api/vulns/{scan_id}              – get enriched vuln report

POST /api/schedule/add                 – schedule a recurring scan
GET  /api/schedule                     – list scheduled jobs
DELETE /api/schedule/{job_id}          – remove a job
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse
from pydantic import BaseModel

from core.reporter import generate_report_for_scan
from core.scheduler import scheduler
from utils.helpers import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Reports & Scheduling"])


# ── Report endpoints ──────────────────────────────────────────────────────────

@router.post("/api/reports/generate/{scan_id}")
async def generate_report(scan_id: str):
    """Generate full HTML, JSON, and TXT reports for a completed scan."""
    paths = await generate_report_for_scan(scan_id)
    if not paths:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "reports": {
            "html":  f"/api/reports/{scan_id}/html",
            "json":  f"/api/reports/{scan_id}/json",
            "txt":   f"/api/reports/{scan_id}/txt",
        },
        "file_paths": paths,
    }


@router.get("/api/reports/{scan_id}/html")
async def get_html_report(scan_id: str):
    """Download the HTML report for a scan."""
    path = Path(f"reports/{scan_id}/report.html")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not generated yet. POST /api/reports/generate/{scan_id} first.")
    return FileResponse(path=str(path), media_type="text/html",
                        filename=f"security_report_{scan_id}.html")


@router.get("/api/reports/{scan_id}/json")
async def get_json_report(scan_id: str):
    """Download the full JSON report for a scan."""
    import json
    path = Path(f"reports/{scan_id}/report.json")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not generated yet.")
    return JSONResponse(content=json.loads(path.read_text()))


@router.get("/api/reports/{scan_id}/txt")
async def get_txt_report(scan_id: str):
    """Get the plain-text executive summary."""
    path = Path(f"reports/{scan_id}/summary.txt")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not generated yet.")
    return PlainTextResponse(content=path.read_text())


# ── Vulnerability analysis endpoints ─────────────────────────────────────────

@router.post("/api/vulns/analyze/{scan_id}")
async def analyze_vulnerabilities(scan_id: str, enrich_cves: bool = True):
    """
    Enrich vulnerabilities for a scan using NVD CVE database.
    Adds CVSS scores, exploit availability, and risk prioritisation.
    """
    from db.database import AsyncSessionLocal
    from db.models import Scan
    from core.vuln_analyzer import VulnerabilityAnalyzer

    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    result_data = scan.result_json or {}
    raw_vulns = []
    for host in result_data.get("hosts", []):
        for v in host.get("vulnerabilities", []):
            v["os"] = host.get("os_match", "")
            raw_vulns.append(v)

    if not raw_vulns:
        return {"scan_id": scan_id, "message": "No vulnerabilities to analyse",
                "total": 0}

    analyzer = VulnerabilityAnalyzer()
    report = await analyzer.analyze(
        scan_id=scan_id,
        target=scan.target,
        raw_vulns=raw_vulns,
        enrich_cves=enrich_cves,
    )
    return report.to_dict()


# ── Scheduler endpoints ───────────────────────────────────────────────────────

class ScheduleRequest(BaseModel):
    job_name: str
    target: str
    scan_type: str
    interval_hours: int = 24
    auto_remediate: bool = False


@router.post("/api/schedule/add", status_code=201)
async def add_scheduled_scan(req: ScheduleRequest):
    """Schedule a recurring scan."""
    if req.scan_type not in (
        "discovery", "basic", "vulnerability", "web", "full", "osint", "shadow-it"
    ):
        raise HTTPException(status_code=400,
                             detail=f"Unknown scan type: {req.scan_type}")
    job_id = await scheduler.add_job(
        job_name=req.job_name,
        target=req.target,
        scan_type=req.scan_type,
        interval_hours=req.interval_hours,
        auto_remediate=req.auto_remediate,
    )
    return {
        "job_id": job_id,
        "message": f"Job '{req.job_name}' scheduled every {req.interval_hours}h",
    }


@router.get("/api/schedule")
async def list_scheduled_jobs():
    """List all active scheduled scan jobs."""
    return await scheduler.list_jobs()


@router.delete("/api/schedule/{job_id}")
async def remove_scheduled_job(job_id: int):
    """Remove a scheduled scan job."""
    await scheduler.remove_job(job_id)
    return {"message": f"Job {job_id} removed"}
