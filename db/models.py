"""
db/models.py
────────────────────────────────────────────────────────────────
SQLAlchemy ORM models for persisting scan results, OSINT data,
Shadow IT findings, and remediation playbooks.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, JSON,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ── Scan ──────────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id              = Column(String(64), primary_key=True)
    target          = Column(String(256), nullable=False, index=True)
    scan_type       = Column(String(32), nullable=False)
    status          = Column(String(32), default="pending", index=True)
    started_at      = Column(DateTime(timezone=True), default=utcnow)
    finished_at     = Column(DateTime(timezone=True), nullable=True)
    error           = Column(Text, nullable=True)
    result_json     = Column(JSON, nullable=True)     # full ScanResult dict
    summary_json    = Column(JSON, nullable=True)
    hosts_up        = Column(Integer, default=0)
    total_ports     = Column(Integer, default=0)
    total_vulns     = Column(Integer, default=0)

    # relationships
    playbooks       = relationship("RemediationPlaybook", back_populates="scan",
                                   cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan",
                                   cascade="all, delete-orphan")


# ── Vulnerability ─────────────────────────────────────────────────────────────

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    scan_id         = Column(String(64), ForeignKey("scans.id"), index=True)
    host_ip         = Column(String(64), nullable=False)
    port            = Column(Integer, nullable=False)
    protocol        = Column(String(8), default="tcp")
    service         = Column(String(64), nullable=True)
    vuln_name       = Column(String(256), nullable=False)
    cves            = Column(JSON, default=list)
    cvss_score      = Column(Float, default=0.0)
    severity        = Column(String(16), default="INFO", index=True)
    state           = Column(String(32), nullable=True)
    description     = Column(Text, nullable=True)
    raw_output      = Column(Text, nullable=True)
    script_id       = Column(String(128), nullable=True)
    discovered_at   = Column(DateTime(timezone=True), default=utcnow)
    is_remediated   = Column(Boolean, default=False)

    scan            = relationship("Scan", back_populates="vulnerabilities")


# ── OSINT Result ──────────────────────────────────────────────────────────────

class OsintScan(Base):
    __tablename__ = "osint_scans"

    id              = Column(String(64), primary_key=True)
    domain          = Column(String(256), nullable=False, index=True)
    status          = Column(String(32), default="pending")
    started_at      = Column(DateTime(timezone=True), default=utcnow)
    finished_at     = Column(DateTime(timezone=True), nullable=True)
    result_json     = Column(JSON, nullable=True)
    summary_json    = Column(JSON, nullable=True)
    total_subdomains = Column(Integer, default=0)
    total_emails    = Column(Integer, default=0)
    error           = Column(Text, nullable=True)


# ── Shadow IT Result ──────────────────────────────────────────────────────────

class ShadowItScan(Base):
    __tablename__ = "shadow_it_scans"

    id              = Column(String(64), primary_key=True)
    domain          = Column(String(256), nullable=False, index=True)
    status          = Column(String(32), default="pending")
    started_at      = Column(DateTime(timezone=True), default=utcnow)
    finished_at     = Column(DateTime(timezone=True), nullable=True)
    result_json     = Column(JSON, nullable=True)
    summary_json    = Column(JSON, nullable=True)
    risk_score      = Column(Float, default=0.0)
    total_findings  = Column(Integer, default=0)
    ai_correlation  = Column(Text, nullable=True)
    error           = Column(Text, nullable=True)


# ── Remediation Playbook ──────────────────────────────────────────────────────

class RemediationPlaybook(Base):
    __tablename__ = "remediation_playbooks"

    id              = Column(String(64), primary_key=True)   # PB-xxxxxxxx
    scan_id         = Column(String(64), ForeignKey("scans.id"), nullable=True)
    vuln_name       = Column(String(256), nullable=False)
    severity        = Column(String(16), default="INFO")
    affected_host   = Column(String(64), nullable=True)
    affected_port   = Column(Integer, nullable=True)
    affected_service = Column(String(64), nullable=True)
    cves            = Column(JSON, default=list)
    steps_json      = Column(JSON, nullable=True)
    rollback_script = Column(Text, nullable=True)
    verification_cmd = Column(String(512), nullable=True)
    file_path       = Column(String(512), nullable=True)
    automation_level = Column(String(32), default="semi-automated")
    estimated_minutes = Column(Integer, default=15)
    is_applied      = Column(Boolean, default=False)
    applied_at      = Column(DateTime(timezone=True), nullable=True)
    generated_at    = Column(DateTime(timezone=True), default=utcnow)
    ai_explanation  = Column(Text, nullable=True)

    scan            = relationship("Scan", back_populates="playbooks")


# ── Scheduled Job ─────────────────────────────────────────────────────────────

class ScheduledJob(Base):
    __tablename__ = "scheduled_jobs"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    job_name        = Column(String(256), nullable=False)
    target          = Column(String(256), nullable=False)
    scan_type       = Column(String(32), nullable=False)
    cron_expression = Column(String(64), nullable=True)
    interval_hours  = Column(Integer, nullable=True)
    is_active       = Column(Boolean, default=True)
    last_run_at     = Column(DateTime(timezone=True), nullable=True)
    next_run_at     = Column(DateTime(timezone=True), nullable=True)
    last_scan_id    = Column(String(64), nullable=True)
    created_at      = Column(DateTime(timezone=True), default=utcnow)
