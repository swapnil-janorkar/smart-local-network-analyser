"""
core/scheduler.py
────────────────────────────────────────────────────────────────
Periodic Scan Scheduler

Allows scheduling recurring scans (network, OSINT, Shadow IT)
at configurable intervals. State persisted in the database.

Usage:
  from core.scheduler import Scheduler
  sched = Scheduler()
  await sched.start()              # starts background loop
  await sched.add_job(...)
  await sched.stop()
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from typing import Callable, Coroutine, Dict, List, Optional

from utils.helpers import get_logger, utcnow

logger = get_logger(__name__)


# ── Job types ─────────────────────────────────────────────────────────────────

JOB_TYPES = {
    "discovery":     "Network discovery (ping sweep)",
    "basic":         "Basic network scan",
    "vulnerability": "Full vulnerability scan",
    "web":           "Web service scan",
    "osint":         "OSINT reconnaissance",
    "shadow-it":     "Shadow IT discovery",
}


# ── Scheduler ─────────────────────────────────────────────────────────────────

class Scheduler:
    """
    Simple async scheduler that runs jobs at fixed intervals.
    Persists job state to the database so restarts don't lose schedules.
    """

    def __init__(self):
        self._jobs: Dict[int, Dict] = {}
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Start the scheduler background loop."""
        if self._running:
            return
        self._running = True
        await self._load_from_db()
        self._task = asyncio.create_task(self._loop())
        logger.info("[scheduler] started")

    async def stop(self):
        """Stop the scheduler."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[scheduler] stopped")

    async def add_job(
        self,
        job_name: str,
        target: str,
        scan_type: str,
        interval_hours: int = 24,
        auto_remediate: bool = False,
    ) -> int:
        """Add a recurring scan job. Returns job DB ID."""
        from db.database import AsyncSessionLocal
        from db.models import ScheduledJob

        next_run = utcnow() + timedelta(hours=interval_hours)
        async with AsyncSessionLocal() as db:
            job = ScheduledJob(
                job_name=job_name,
                target=target,
                scan_type=scan_type,
                interval_hours=interval_hours,
                is_active=True,
                next_run_at=next_run,
            )
            db.add(job)
            await db.commit()
            await db.refresh(job)
            job_id = job.id

        self._jobs[job_id] = {
            "id": job_id,
            "name": job_name,
            "target": target,
            "scan_type": scan_type,
            "interval_hours": interval_hours,
            "auto_remediate": auto_remediate,
            "next_run": next_run,
        }
        logger.info(f"[scheduler] job {job_id} ({job_name}) added, "
                    f"runs every {interval_hours}h")
        return job_id

    async def remove_job(self, job_id: int):
        """Remove a scheduled job."""
        from db.database import AsyncSessionLocal
        from db.models import ScheduledJob

        self._jobs.pop(job_id, None)
        async with AsyncSessionLocal() as db:
            job = await db.get(ScheduledJob, job_id)
            if job:
                job.is_active = False
        logger.info(f"[scheduler] job {job_id} removed")

    async def list_jobs(self) -> List[Dict]:
        """Return all active jobs with their next-run time."""
        return [
            {
                "id": j["id"],
                "name": j["name"],
                "target": j["target"],
                "scan_type": j["scan_type"],
                "interval_hours": j["interval_hours"],
                "next_run": str(j["next_run"]),
            }
            for j in self._jobs.values()
        ]

    # ── Internal ──────────────────────────────────────────────

    async def _loop(self):
        while self._running:
            now = utcnow()
            for job_id, job in list(self._jobs.items()):
                if now >= job["next_run"]:
                    asyncio.create_task(self._run_job(job_id, job))
            await asyncio.sleep(60)   # check every minute

    async def _run_job(self, job_id: int, job: Dict):
        logger.info(f"[scheduler] running job {job_id}: "
                    f"{job['scan_type']} on {job['target']}")
        scan_id = str(uuid.uuid4())

        try:
            scan_type = job["scan_type"]

            if scan_type in ("discovery", "basic", "vulnerability", "web", "full"):
                from core.scanner import NetworkScanner
                from db.database import upsert_scan
                sc = NetworkScanner()
                scan_map = {
                    "discovery":     sc.discovery_scan,
                    "basic":         sc.basic_scan,
                    "vulnerability": sc.vulnerability_scan,
                    "web":           sc.web_scan,
                    "full":          sc.full_scan,
                }
                result = await scan_map[scan_type](job["target"], scan_id)
                await upsert_scan({
                    "scan_id": scan_id,
                    "target": job["target"],
                    "scan_type": scan_type,
                    "status": result.status,
                    "result_json": result.to_dict(),
                    "summary_json": result.summary,
                })

            elif scan_type == "osint":
                from core.osint import OSINTEngine
                from db.database import upsert_osint
                eng = OSINTEngine()
                result = await eng.full_osint(job["target"], scan_id)
                await upsert_osint({
                    "scan_id": scan_id, "domain": job["target"],
                    "status": result.status,
                    "result_json": result.to_dict(),
                    "summary_json": result.summary,
                    "total_subdomains": len(result.subdomains),
                })

            elif scan_type == "shadow-it":
                from core.shadow_it import ShadowITDiscovery
                from db.database import upsert_shadow_it
                eng = ShadowITDiscovery()
                result = await eng.discover(job["target"], scan_id)
                await upsert_shadow_it({
                    "scan_id": scan_id, "domain": job["target"],
                    "status": result.status,
                    "result_json": result.to_dict(),
                    "risk_score": result.risk_score,
                })

            logger.info(f"[scheduler] job {job_id} completed → scan {scan_id}")

        except Exception as e:
            logger.exception(f"[scheduler] job {job_id} failed: {e}")
        finally:
            # Schedule next run
            next_run = utcnow() + timedelta(hours=job["interval_hours"])
            self._jobs[job_id]["next_run"] = next_run
            await self._update_db(job_id, scan_id, next_run)

    async def _update_db(self, job_id: int, scan_id: str,
                          next_run: datetime):
        from db.database import AsyncSessionLocal
        from db.models import ScheduledJob
        async with AsyncSessionLocal() as db:
            job = await db.get(ScheduledJob, job_id)
            if job:
                job.last_run_at = utcnow()
                job.last_scan_id = scan_id
                job.next_run_at = next_run

    async def _load_from_db(self):
        """Reload active jobs from DB on startup."""
        from db.database import AsyncSessionLocal
        from db.models import ScheduledJob
        from sqlalchemy import select
        try:
            async with AsyncSessionLocal() as db:
                stmt = select(ScheduledJob).where(ScheduledJob.is_active.is_(True))
                rows = (await db.execute(stmt)).scalars().all()
                for row in rows:
                    self._jobs[row.id] = {
                        "id": row.id,
                        "name": row.job_name,
                        "target": row.target,
                        "scan_type": row.scan_type,
                        "interval_hours": row.interval_hours or 24,
                        "auto_remediate": False,
                        "next_run": row.next_run_at or utcnow(),
                    }
            logger.info(f"[scheduler] loaded {len(self._jobs)} jobs from DB")
        except Exception as e:
            logger.warning(f"[scheduler] could not load jobs from DB: {e}")


# ── Singleton ─────────────────────────────────────────────────────────────────
scheduler = Scheduler()
