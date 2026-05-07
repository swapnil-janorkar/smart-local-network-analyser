"""
api/routes/remediation.py
────────────────────────────────────────────────────────────────
REST endpoints for the AI Remediation / Self-Healing Playbook engine.

POST /api/remediation/generate       – generate playbook for a vulnerability
POST /api/remediation/generate-batch – generate playbooks for all vulns in a scan
GET  /api/remediation/{playbook_id}  – fetch a single playbook
GET  /api/remediation/scan/{scan_id} – all playbooks for a scan
GET  /api/remediation/{id}/download  – download the runnable shell script
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from core.remediation import RemediationEngine, generate_remediation
from db.database import save_playbook
from utils.helpers import get_logger, cvss_to_severity

logger = get_logger(__name__)
router = APIRouter(prefix="/api/remediation", tags=["Remediation Playbooks"])
engine = RemediationEngine()


# ── Request models ────────────────────────────────────────────────────────────

class VulnPayload(BaseModel):
    ip: str
    port: int
    service: str = ""
    version: str = ""
    script: str = ""
    cves: List[str] = []
    cvss_score: float = 0.0
    description: str = ""
    os: str = "Ubuntu 22.04 LTS"
    deployment_context: Optional[Dict] = None


class BatchRemediationRequest(BaseModel):
    scan_id: str
    target: str
    vulnerabilities: List[VulnPayload]
    deployment_context: Optional[Dict] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/generate")
async def generate_single_playbook(vuln: VulnPayload):
    """
    Generate a specific remediation playbook for one vulnerability.
    Returns full steps with runnable code tailored to the environment.
    """
    playbook = await engine.generate_playbook(
        vulnerability=vuln.model_dump(),
        deployment_context=vuln.deployment_context or {},
    )
    if not playbook:
        raise HTTPException(status_code=500, detail="Playbook generation failed")

    await save_playbook({**playbook.to_dict(), "scan_id": None})
    return playbook.to_dict()


@router.post("/generate-batch")
async def generate_batch_playbooks(req: BatchRemediationRequest):
    """
    Generate remediation playbooks for all vulnerabilities in a scan.
    Sorted by severity (CRITICAL → HIGH → MEDIUM → LOW).
    """
    bundle = await generate_remediation(
        scan_id=req.scan_id,
        target=req.target,
        vulnerabilities=[v.model_dump() for v in req.vulnerabilities],
        deployment_context=req.deployment_context,
    )

    for pb in bundle.playbooks:
        await save_playbook({**pb.to_dict(), "scan_id": req.scan_id})

    return bundle.to_dict()


@router.get("/scan/{scan_id}")
async def get_playbooks_for_scan(scan_id: str):
    """Return all remediation playbooks generated for a scan."""
    from db.database import AsyncSessionLocal
    from db.models import RemediationPlaybook
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        stmt = select(RemediationPlaybook).where(
            RemediationPlaybook.scan_id == scan_id
        )
        rows = (await db.execute(stmt)).scalars().all()

    if not rows:
        raise HTTPException(status_code=404,
                             detail="No playbooks found for this scan")
    return [
        {
            "playbook_id": r.id,
            "vuln_name": r.vuln_name,
            "severity": r.severity,
            "affected_host": r.affected_host,
            "affected_port": r.affected_port,
            "cves": r.cves,
            "automation_level": r.automation_level,
            "estimated_minutes": r.estimated_minutes,
            "steps": r.steps_json,
            "ai_explanation": r.ai_explanation,
            "file_path": r.file_path,
            "is_applied": r.is_applied,
        }
        for r in rows
    ]


@router.get("/{playbook_id}")
async def get_playbook(playbook_id: str):
    """Fetch a single playbook by ID."""
    from db.database import AsyncSessionLocal
    from db.models import RemediationPlaybook

    async with AsyncSessionLocal() as db:
        row = await db.get(RemediationPlaybook, playbook_id)

    if not row:
        raise HTTPException(status_code=404, detail="Playbook not found")

    return {
        "playbook_id": row.id,
        "vuln_name": row.vuln_name,
        "severity": row.severity,
        "affected_host": row.affected_host,
        "affected_port": row.affected_port,
        "affected_service": row.affected_service,
        "cves": row.cves,
        "steps": row.steps_json,
        "rollback_script": row.rollback_script,
        "verification_command": row.verification_cmd,
        "automation_level": row.automation_level,
        "estimated_minutes": row.estimated_minutes,
        "ai_explanation": row.ai_explanation,
        "file_path": row.file_path,
        "is_applied": row.is_applied,
    }


@router.get("/{playbook_id}/download")
async def download_playbook_script(playbook_id: str):
    """Download the runnable shell script for a playbook."""
    from db.database import AsyncSessionLocal
    from db.models import RemediationPlaybook

    async with AsyncSessionLocal() as db:
        row = await db.get(RemediationPlaybook, playbook_id)

    if not row or not row.file_path:
        raise HTTPException(status_code=404, detail="Script not found")

    script_path = Path(row.file_path) / "run.sh"
    if not script_path.exists():
        raise HTTPException(status_code=404, detail="Script file missing on disk")

    return FileResponse(
        path=str(script_path),
        media_type="text/plain",
        filename=f"{playbook_id}_remediation.sh",
    )


@router.get("/{playbook_id}/rollback")
async def download_rollback_script(playbook_id: str):
    """Download the rollback script for a playbook."""
    from db.database import AsyncSessionLocal
    from db.models import RemediationPlaybook

    async with AsyncSessionLocal() as db:
        row = await db.get(RemediationPlaybook, playbook_id)

    if not row or not row.rollback_script:
        raise HTTPException(status_code=404, detail="No rollback script available")

    return PlainTextResponse(
        content=row.rollback_script,
        media_type="text/plain",
        headers={"Content-Disposition":
                 f"attachment; filename={playbook_id}_rollback.sh"},
    )
