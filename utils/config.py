"""
utils/config.py
────────────────────────────────────────────────────────────────
Central configuration loaded from environment / .env file.
"""

from __future__ import annotations

import os
from pathlib import Path
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    # ── Anthropic / Gemini API ───────────────────────────────
    anthropic_api_key: str = ""
    gemini_api_key: str = ""

    # ── Optional enrichment APIs ─────────────────────────────
    shodan_api_key: str = ""
    securitytrails_api_key: str = ""
    hunter_api_key: str = ""
    github_token: str = ""

    # ── API server ───────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    secret_key: str = "change_me_please"
    debug: bool = False

    # ── Database ─────────────────────────────────────────────
    database_url: str = f"sqlite:///{BASE_DIR}/smart_analyzer.db"

    # ── Scanning defaults ────────────────────────────────────
    default_scan_timeout: int = 300          # seconds
    max_concurrent_scans: int = 3
    nmap_timing_template: int = 4            # T0-T5
    enable_aggressive_scan: bool = False

    # ── OSINT defaults ───────────────────────────────────────
    max_subdomain_workers: int = 50
    dns_timeout: float = 3.0
    osint_github_max_pages: int = 5
    ct_log_max_results: int = 200

    # ── AI remediation ───────────────────────────────────────
    ai_model: str = "claude-sonnet-4-20250514"
    ai_max_tokens: int = 4096

    # ── Paths ────────────────────────────────────────────────
    reports_dir: Path = BASE_DIR / "reports"
    logs_dir: Path = BASE_DIR / "logs"
    playbooks_dir: Path = BASE_DIR / "playbooks"

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def model_post_init(self, __context):  # noqa: D401
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.playbooks_dir.mkdir(parents=True, exist_ok=True)


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
