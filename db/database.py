"""
db/database.py
────────────────────────────────────────────────────────────────
Async SQLAlchemy engine, session factory, and CRUD helpers.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import select, update

from db.models import Base, Scan, OsintScan, ShadowItScan, RemediationPlaybook
from utils.config import settings
from utils.helpers import get_logger

logger = get_logger(__name__)

# Convert sqlite:/// → sqlite+aiosqlite:///
_db_url = settings.database_url
if _db_url.startswith("sqlite:///") and "+aiosqlite" not in _db_url:
    _db_url = _db_url.replace("sqlite:///", "sqlite+aiosqlite:///")

engine = create_async_engine(
    _db_url,
    echo=settings.debug,
    connect_args={"check_same_thread": False} if "sqlite" in _db_url else {},
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def init_db():
    """Create all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("[db] tables created / verified")


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── CRUD helpers ──────────────────────────────────────────────────────────────

async def upsert_scan(data: dict) -> None:
    async with get_db() as db:
        existing = await db.get(Scan, data["scan_id"])
        if existing:
            for k, v in data.items():
                if hasattr(existing, k):
                    setattr(existing, k, v)
        else:
            db.add(Scan(
                id=data["scan_id"],
                target=data.get("target", ""),
                scan_type=data.get("scan_type", ""),
                status=data.get("status", "pending"),
                result_json=data.get("result_json"),
                summary_json=data.get("summary_json"),
                hosts_up=data.get("hosts_up", 0),
                total_ports=data.get("total_ports", 0),
                total_vulns=data.get("total_vulns", 0),
            ))


async def get_scan_by_id(scan_id: str) -> Optional[Scan]:
    async with get_db() as db:
        return await db.get(Scan, scan_id)


async def upsert_osint(data: dict) -> None:
    async with get_db() as db:
        existing = await db.get(OsintScan, data["scan_id"])
        if existing:
            for k, v in data.items():
                if hasattr(existing, k):
                    setattr(existing, k, v)
        else:
            db.add(OsintScan(
                id=data["scan_id"],
                domain=data.get("domain", ""),
                status=data.get("status", "pending"),
                result_json=data.get("result_json"),
                summary_json=data.get("summary_json"),
                total_subdomains=data.get("total_subdomains", 0),
                total_emails=data.get("total_emails", 0),
            ))


async def upsert_shadow_it(data: dict) -> None:
    async with get_db() as db:
        existing = await db.get(ShadowItScan, data["scan_id"])
        if existing:
            for k, v in data.items():
                if hasattr(existing, k):
                    setattr(existing, k, v)
        else:
            db.add(ShadowItScan(
                id=data["scan_id"],
                domain=data.get("domain", ""),
                status=data.get("status", "pending"),
                result_json=data.get("result_json"),
                summary_json=data.get("summary_json"),
                risk_score=data.get("risk_score", 0.0),
                total_findings=data.get("total_findings", 0),
                ai_correlation=data.get("ai_correlation", ""),
            ))


async def save_playbook(playbook_dict: dict) -> None:
    async with get_db() as db:
        existing = await db.get(RemediationPlaybook, playbook_dict["playbook_id"])
        if not existing:
            db.add(RemediationPlaybook(
                id=playbook_dict["playbook_id"],
                scan_id=playbook_dict.get("scan_id"),
                vuln_name=playbook_dict.get("vuln_name", ""),
                severity=playbook_dict.get("severity", "INFO"),
                affected_host=playbook_dict.get("affected_host", ""),
                affected_port=playbook_dict.get("affected_port", 0),
                affected_service=playbook_dict.get("affected_service", ""),
                cves=playbook_dict.get("cves", []),
                steps_json=playbook_dict.get("steps", []),
                rollback_script=playbook_dict.get("rollback_script", ""),
                verification_cmd=playbook_dict.get("verification_command", ""),
                file_path=playbook_dict.get("file_path", ""),
                automation_level=playbook_dict.get("automation_level", "semi-automated"),
                estimated_minutes=playbook_dict.get("estimated_time_minutes", 15),
                ai_explanation=playbook_dict.get("ai_explanation", ""),
            ))
