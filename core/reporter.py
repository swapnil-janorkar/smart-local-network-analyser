"""
core/reporter.py
────────────────────────────────────────────────────────────────
Report Generator

Produces professional scan reports in:
  • HTML  – full interactive report with charts and tables
  • JSON  – machine-readable, suitable for feeding other tools
  • TXT   – plain text executive summary

Reports saved to /reports/<scan_id>/
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Template

from utils.config import settings
from utils.helpers import get_logger, utcnow_str

logger = get_logger(__name__)


# ── HTML Report Template ──────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report – {{ target }}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e;
    --red: #f85149; --orange: #d29922; --yellow: #e3b341;
    --green: #3fb950; --blue: #58a6ff; --purple: #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 2rem; color: var(--blue); margin-bottom: 4px; }
  h2 { font-size: 1.3rem; color: var(--text); margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
  h3 { font-size: 1.1rem; color: var(--muted); margin: 16px 0 8px; }
  .meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
  .stat-value { font-size: 2.5rem; font-weight: 700; line-height: 1; }
  .stat-label { color: var(--muted); font-size: 0.85rem; margin-top: 4px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .badge-critical { background: rgba(248,81,73,.2); color: var(--red); border: 1px solid var(--red); }
  .badge-high     { background: rgba(210,153,34,.2); color: var(--orange); border: 1px solid var(--orange); }
  .badge-medium   { background: rgba(227,179,65,.2); color: var(--yellow); border: 1px solid var(--yellow); }
  .badge-low      { background: rgba(63,185,80,.2); color: var(--green); border: 1px solid var(--green); }
  .badge-info     { background: rgba(88,166,255,.2); color: var(--blue); border: 1px solid var(--blue); }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; color: var(--muted); font-weight: 600; border-bottom: 2px solid var(--border); font-size: 0.8rem; text-transform: uppercase; }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: rgba(255,255,255,.02); }
  code { background: rgba(88,166,255,.1); color: var(--blue); padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 0.85em; }
  pre { background: #010409; border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; font-family: monospace; font-size: 0.8rem; color: var(--green); white-space: pre-wrap; }
  .playbook { background: #010409; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 16px; }
  .playbook-header { padding: 12px 16px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }
  .playbook-body { padding: 16px; }
  .step { border-left: 3px solid var(--blue); padding-left: 12px; margin-bottom: 12px; }
  .step-title { font-weight: 600; color: var(--blue); margin-bottom: 4px; }
  details summary { cursor: pointer; user-select: none; color: var(--blue); }
  .tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.7rem; background: rgba(88,166,255,.1); color: var(--blue); margin-right: 4px; }
  .exploit-badge { color: var(--red); font-weight: 700; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem; text-align: center; }
</style>
</head>
<body>
<div class="container">

<h1>🔐 Security Analysis Report</h1>
<div class="meta">
  Target: <strong>{{ target }}</strong> &nbsp;|&nbsp;
  Scan ID: <code>{{ scan_id }}</code> &nbsp;|&nbsp;
  Generated: {{ generated_at }} &nbsp;|&nbsp;
  Scan Type: <strong>{{ scan_type }}</strong>
</div>

<!-- ── Summary Cards ─────────────────────────────────────── -->
<div class="grid-4">
  <div class="stat-card">
    <div class="stat-value" style="color:var(--blue)">{{ summary.hosts_up }}</div>
    <div class="stat-label">Hosts Up</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:var(--purple)">{{ summary.total_open_ports }}</div>
    <div class="stat-label">Open Ports</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:var(--red)">{{ summary.total_vulnerabilities }}</div>
    <div class="stat-label">Vulnerabilities</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:var(--orange)">{{ playbooks|length }}</div>
    <div class="stat-label">Playbooks Generated</div>
  </div>
</div>

<!-- ── Risk Distribution ─────────────────────────────────── -->
{% if risk_matrix %}
<h2>Risk Distribution</h2>
<div class="card" style="display:grid;grid-template-columns:repeat(5,1fr);gap:16px;text-align:center">
  {% for level, data in risk_matrix.items() %}
  <div>
    <div style="font-size:1.8rem;font-weight:700;
      color:{% if level=='CRITICAL' %}var(--red){% elif level=='HIGH' %}var(--orange){% elif level=='MEDIUM' %}var(--yellow){% elif level=='LOW' %}var(--green){% else %}var(--blue){% endif %}">
      {{ data.count }}
    </div>
    <div class="stat-label">{{ level }}</div>
    {% if data.exploitable %}<div style="font-size:0.75rem;color:var(--red)">{{ data.exploitable }} exploitable</div>{% endif %}
  </div>
  {% endfor %}
</div>
{% endif %}

<!-- ── Hosts ─────────────────────────────────────────────── -->
{% if hosts %}
<h2>Discovered Hosts</h2>
{% for host in hosts %}
<div class="card">
  <h3>
    {{ host.ip }}
    {% if host.hostname != host.ip %}<span style="color:var(--muted)"> ({{ host.hostname }})</span>{% endif %}
    {% if host.os_match %}<span style="font-size:0.8rem;color:var(--muted);margin-left:12px">{{ host.os_match }}</span>{% endif %}
    {% if host.mac_address %}<span style="font-size:0.8rem;color:var(--muted);margin-left:8px">{{ host.mac_address }} {{ host.vendor }}</span>{% endif %}
  </h3>
  {% if host.ports %}
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>Product / Version</th><th>Risk</th><th>Vuln Scripts</th></tr></thead>
    <tbody>
    {% for port in host.ports|sort(attribute='port') %}
    <tr>
      <td><code>{{ port.port }}/{{ port.protocol }}</code></td>
      <td>{{ port.service }}</td>
      <td>{{ port.product }} {{ port.version }}</td>
      <td><span class="badge badge-{{ port.risk_level|lower }}">{{ port.risk_level }}</span></td>
      <td>{% for s in port.scripts %}<span class="tag">{{ s }}</span>{% endfor %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  {% if host.vulnerabilities %}
  <details style="margin-top:12px">
    <summary>⚠️ {{ host.vulnerabilities|length }} vulnerabilities detected</summary>
    <table style="margin-top:8px">
      <thead><tr><th>Port</th><th>Script</th><th>CVEs</th><th>CVSS</th><th>State</th></tr></thead>
      <tbody>
      {% for v in host.vulnerabilities %}
      <tr>
        <td><code>{{ v.port }}</code></td>
        <td>{{ v.script }}</td>
        <td>{{ v.cves|join(', ') or '—' }}</td>
        <td>{{ v.cvss_score or '—' }}</td>
        <td>{{ v.state }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </details>
  {% endif %}
</div>
{% endfor %}
{% endif %}

<!-- ── Remediation Playbooks ──────────────────────────────── -->
{% if playbooks %}
<h2>🤖 AI Remediation Playbooks</h2>
<p style="color:var(--muted);margin-bottom:16px">
  Auto-generated, runnable fix scripts tailored to your environment.
  Review before executing in production.
</p>
{% for pb in playbooks %}
<div class="playbook">
  <div class="playbook-header">
    <span class="badge badge-{{ pb.severity|lower }}">{{ pb.severity }}</span>
    <strong>{{ pb.vuln_name }}</strong>
    <span style="color:var(--muted)">{{ pb.affected_host }}:{{ pb.affected_port }}</span>
    <span style="margin-left:auto;color:var(--muted);font-size:0.8rem">
      {{ pb.automation_level }} · ~{{ pb.estimated_time_minutes }} min
    </span>
  </div>
  <div class="playbook-body">
    {% if pb.ai_explanation %}<p style="color:var(--muted);margin-bottom:12px">{{ pb.ai_explanation }}</p>{% endif %}
    {% if pb.cves %}<p style="margin-bottom:8px">CVEs: {% for c in pb.cves %}<code>{{ c }}</code> {% endfor %}</p>{% endif %}
    {% for step in pb.steps %}
    <div class="step">
      <div class="step-title">Step {{ step.order }}: {{ step.title }}</div>
      <div style="color:var(--muted);font-size:0.85rem;margin-bottom:6px">{{ step.description }}</div>
      <pre>{{ step.code }}</pre>
      {% if step.requires_restart %}<span style="color:var(--yellow);font-size:0.8rem">⚠ Requires service restart</span>{% endif %}
    </div>
    {% endfor %}
    {% if pb.verification_command %}
    <div style="margin-top:12px">
      <strong>Verification:</strong>
      <pre>{{ pb.verification_command }}</pre>
    </div>
    {% endif %}
    {% if pb.rollback_script %}
    <details style="margin-top:8px">
      <summary>🔄 Rollback Script</summary>
      <pre style="margin-top:8px">{{ pb.rollback_script }}</pre>
    </details>
    {% endif %}
  </div>
</div>
{% endfor %}
{% endif %}

<!-- ── OSINT Data ─────────────────────────────────────────── -->
{% if osint %}
<h2>🔍 OSINT Intelligence</h2>
<div class="grid-4" style="grid-template-columns:repeat(3,1fr)">
  <div class="stat-card">
    <div class="stat-value" style="color:var(--blue)">{{ osint.subdomains|length }}</div>
    <div class="stat-label">Subdomains</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:var(--green)">{{ osint.emails|length }}</div>
    <div class="stat-label">Emails Found</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:var(--purple)">{{ osint.technologies|length }}</div>
    <div class="stat-label">Technologies</div>
  </div>
</div>
{% if osint.subdomains %}
<details>
  <summary>Show {{ osint.subdomains|length }} subdomains</summary>
  <table style="margin-top:8px">
    <thead><tr><th>Subdomain</th><th>IPs</th><th>Status</th><th>Source</th><th>Tech</th></tr></thead>
    <tbody>
    {% for s in osint.subdomains %}
    <tr>
      <td>{{ s.subdomain }}</td>
      <td>{{ s.ip_addresses|join(', ') }}</td>
      <td>{% if s.http_status %}<code>{{ s.http_status }}</code>{% else %}—{% endif %}</td>
      <td>{{ s.source }}</td>
      <td>{{ s.technologies|join(', ') }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</details>
{% endif %}
{% endif %}

<!-- ── Shadow IT ──────────────────────────────────────────── -->
{% if shadow_it %}
<h2>🕵️ Shadow IT & Forgotten Assets</h2>
<div class="card" style="border-color:var(--red)">
  <div style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
    <span style="font-size:2rem;font-weight:700;color:var(--red)">{{ shadow_it.risk_score|round(1) }}</span>
    <div>
      <div style="font-weight:600">Overall Risk Score</div>
      <div style="color:var(--muted);font-size:0.85rem">
        {{ shadow_it.summary.github_leaks }} GitHub leaks ·
        {{ shadow_it.summary.exposed_buckets }} exposed buckets ·
        {{ shadow_it.summary.pastebin_hits }} paste hits
      </div>
    </div>
  </div>
  {% if shadow_it.ai_correlation %}
  <pre style="white-space:pre-wrap;font-family:inherit">{{ shadow_it.ai_correlation }}</pre>
  {% endif %}
</div>
{% endif %}

<footer>
  Generated by Smart Network &amp; Security Analyzer · {{ generated_at }} · For authorised use only
</footer>
</div>
</body>
</html>"""


# ── Reporter class ────────────────────────────────────────────────────────────

class ReportGenerator:

    def __init__(self):
        self.reports_dir = settings.reports_dir

    async def generate(
        self,
        scan_result: Dict,
        vuln_report: Optional[Dict] = None,
        playbooks: Optional[List[Dict]] = None,
        osint_result: Optional[Dict] = None,
        shadow_it_result: Optional[Dict] = None,
    ) -> Dict[str, Path]:
        """
        Generate all report formats and return paths.
        Returns: {"html": path, "json": path, "txt": path}
        """
        scan_id = scan_result.get("scan_id", "unknown")
        out_dir = self.reports_dir / scan_id
        out_dir.mkdir(parents=True, exist_ok=True)

        context = self._build_context(
            scan_result, vuln_report, playbooks, osint_result, shadow_it_result
        )

        html_path = out_dir / "report.html"
        json_path = out_dir / "report.json"
        txt_path  = out_dir / "summary.txt"

        # HTML
        tmpl = Template(HTML_TEMPLATE)
        html_path.write_text(tmpl.render(**context), encoding="utf-8")

        # JSON (full data dump)
        full_data = {
            "report_metadata": {
                "scan_id": scan_id,
                "generated_at": utcnow_str(),
                "target": scan_result.get("target", ""),
            },
            "scan": scan_result,
            "vulnerability_report": vuln_report,
            "playbooks": playbooks,
            "osint": osint_result,
            "shadow_it": shadow_it_result,
        }
        json_path.write_text(json.dumps(full_data, indent=2, default=str))

        # Plain text executive summary
        txt_path.write_text(self._build_text_summary(context))

        logger.info(f"[reporter] reports written to {out_dir}")
        return {"html": html_path, "json": json_path, "txt": txt_path}

    def _build_context(
        self,
        scan: Dict,
        vuln_report: Optional[Dict],
        playbooks: Optional[List[Dict]],
        osint: Optional[Dict],
        shadow_it: Optional[Dict],
    ) -> Dict:
        summary = scan.get("summary", {})
        hosts = scan.get("result", {}).get("hosts", []) if scan.get("result") else []

        risk_matrix = {}
        if vuln_report:
            risk_matrix = vuln_report.get("risk_matrix", {})
        elif summary.get("risk_distribution"):
            risk_matrix = {
                k: {"count": v, "exploitable": 0}
                for k, v in summary["risk_distribution"].items()
            }

        return {
            "target": scan.get("target", ""),
            "scan_id": scan.get("scan_id", ""),
            "scan_type": scan.get("scan_type", ""),
            "generated_at": utcnow_str(),
            "summary": summary,
            "hosts": hosts,
            "risk_matrix": risk_matrix,
            "playbooks": playbooks or [],
            "osint": osint,
            "shadow_it": shadow_it,
        }

    def _build_text_summary(self, ctx: Dict) -> str:
        s = ctx.get("summary", {})
        lines = [
            "=" * 60,
            "SECURITY ANALYSIS EXECUTIVE SUMMARY",
            "=" * 60,
            f"Target:          {ctx['target']}",
            f"Scan ID:         {ctx['scan_id']}",
            f"Generated:       {ctx['generated_at']}",
            f"Scan Type:       {ctx['scan_type']}",
            "",
            "NETWORK SCAN SUMMARY",
            "-" * 40,
            f"Hosts Discovered: {s.get('hosts_up', 0)}",
            f"Open Ports:       {s.get('total_open_ports', 0)}",
            f"Vulnerabilities:  {s.get('total_vulnerabilities', 0)}",
            "",
            "RISK DISTRIBUTION",
            "-" * 40,
        ]
        rm = ctx.get("risk_matrix", {})
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = rm.get(level, {}).get("count", 0) if isinstance(rm.get(level), dict) else rm.get(level, 0)
            lines.append(f"  {level:<10}: {count}")

        pb_count = len(ctx.get("playbooks", []))
        if pb_count:
            lines += ["", f"REMEDIATION: {pb_count} playbook(s) generated",
                      "Run scripts in: playbooks/ directory"]

        osint = ctx.get("osint")
        if osint and isinstance(osint, dict):
            summ = osint.get("summary", {})
            lines += [
                "", "OSINT SUMMARY", "-" * 40,
                f"Subdomains: {summ.get('total_subdomains', 0)}",
                f"Emails:     {summ.get('total_emails', 0)}",
            ]
            takeovers = summ.get("possible_takeovers", [])
            if takeovers:
                lines.append(f"⚠ Possible subdomain takeovers: {', '.join(takeovers)}")

        si = ctx.get("shadow_it")
        if si and isinstance(si, dict):
            lines += [
                "", "SHADOW IT SUMMARY", "-" * 40,
                f"Risk Score:     {si.get('risk_score', 0):.1f}/100",
                f"GitHub Leaks:   {si.get('summary', {}).get('github_leaks', 0)}",
                f"Exposed Buckets:{si.get('summary', {}).get('exposed_buckets', 0)}",
            ]

        lines += ["", "=" * 60,
                  "For authorised use only. Handle this report as CONFIDENTIAL.",
                  "=" * 60]
        return "\n".join(lines)


# ── API route helper ──────────────────────────────────────────────────────────

async def generate_report_for_scan(scan_id: str) -> Optional[Dict[str, str]]:
    """Fetch all data for a scan and generate reports. Returns paths as strings."""
    from db.database import AsyncSessionLocal
    from db.models import Scan, OsintScan, ShadowItScan, RemediationPlaybook
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            return None
        pbs_q = await db.execute(
            select(RemediationPlaybook).where(RemediationPlaybook.scan_id == scan_id)
        )
        pbs = pbs_q.scalars().all()

    gen = ReportGenerator()
    paths = await gen.generate(
        scan_result={
            "scan_id": scan.id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "summary": scan.summary_json or {},
            "result": scan.result_json,
        },
        playbooks=[
            {
                "playbook_id": p.id,
                "vuln_name": p.vuln_name,
                "severity": p.severity,
                "affected_host": p.affected_host,
                "affected_port": p.affected_port,
                "cves": p.cves or [],
                "steps": p.steps_json or [],
                "ai_explanation": p.ai_explanation or "",
                "automation_level": p.automation_level,
                "estimated_time_minutes": p.estimated_minutes,
                "rollback_script": p.rollback_script or "",
                "verification_command": p.verification_cmd or "",
            }
            for p in pbs
        ],
    )
    return {k: str(v) for k, v in paths.items()}
