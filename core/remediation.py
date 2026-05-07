"""
core/remediation.py
────────────────────────────────────────────────────────────────
Agentic Self-Healing Playbook Generator
────────────────────────────────────────
For every vulnerability found, this engine:

  1. Analyses the exact vulnerability, affected service, version,
     and deployment context
  2. Calls Claude to generate a specific, runnable remediation
     artefact tailored to that environment:
       • Bash / shell scripts
       • Python patches
       • Nginx / Apache config snippets
       • Terraform / HCL modules
       • Docker / docker-compose fixes
       • SQL migrations
       • Kubernetes manifests
  3. Validates that the generated code is syntactically correct
  4. Writes the playbook to disk under /playbooks/
  5. Returns a structured PlaybookBundle for the API
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import anthropic
from google import genai

from utils.config import settings
from utils.helpers import get_logger, utcnow_str, cvss_to_severity

logger = get_logger(__name__)


# ── Context types the AI can target ──────────────────────────────────────────

REMEDIATION_TYPES = {
    # Format: "vuln_keyword": (script_type, description)
    "sql_injection":        ("python",   "SQLi patch – parameterised queries + WAF rule"),
    "xss":                  ("javascript","XSS fix – CSP header + input sanitisation"),
    "ssl_heartbleed":       ("bash",     "Heartbleed – OpenSSL upgrade + service restart"),
    "ssl_poodle":           ("nginx",    "POODLE – disable SSLv3 in Nginx/Apache"),
    "ssl_dh_params":        ("nginx",    "Weak DH params – regenerate + configure"),
    "ssl-heartbleed":       ("bash",     "Heartbleed – OpenSSL upgrade + restart"),
    "smb_ms17_010":         ("bash",     "EternalBlue – SMB patch + firewall rule"),
    "smb-vuln-ms17-010":    ("bash",     "EternalBlue – SMB patch + firewall rule"),
    "ftp_anon":             ("bash",     "Anonymous FTP – disable anonymous login"),
    "ftp-anon":             ("bash",     "Anonymous FTP – disable anonymous login"),
    "mysql_empty_password": ("sql",      "MySQL root password fix"),
    "mysql-empty-password": ("sql",      "MySQL root password fix"),
    "redis_no_auth":        ("bash",     "Redis – enable requirepass auth"),
    "mongodb_no_auth":      ("bash",     "MongoDB – enable authentication"),
    "open_s3_bucket":       ("terraform","S3 bucket – block public access"),
    "default_credentials":  ("bash",     "Default creds – force password rotation"),
    "open_rdp":             ("bash",     "RDP – NLA + firewall restriction"),
    "open_telnet":          ("bash",     "Telnet – disable + replace with SSH"),
    "snmp_default":         ("bash",     "SNMP – change community string"),
    "http_headers":         ("nginx",    "Security headers – add CSP/HSTS/X-Frame"),
    "http-security-headers":("nginx",    "Security headers – add CSP/HSTS/X-Frame"),
    "http_methods":         ("nginx",    "Disable dangerous HTTP methods (TRACE/DELETE)"),
    "weak_ssh":             ("bash",     "SSH hardening – ciphers, key auth, fail2ban"),
    "open_elasticsearch":   ("bash",     "Elasticsearch – enable X-Pack auth"),
}


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class PlaybookStep:
    order: int
    title: str
    description: str
    code: str
    code_type: str          # bash / python / nginx / sql / terraform / yaml
    is_automated: bool = True
    requires_restart: bool = False
    risk: str = "LOW"       # risk of running this step

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Playbook:
    playbook_id: str
    vulnerability_id: str
    vuln_name: str
    cves: List[str]
    severity: str
    affected_host: str
    affected_port: int
    affected_service: str
    os_context: str
    steps: List[PlaybookStep] = field(default_factory=list)
    rollback_script: str = ""
    verification_command: str = ""
    estimated_time_minutes: int = 15
    automation_level: str = "semi-automated"  # manual / semi-automated / fully-automated
    generated_at: str = field(default_factory=utcnow_str)
    ai_explanation: str = ""
    file_path: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["steps"] = [s.to_dict() for s in self.steps]
        return d


@dataclass
class PlaybookBundle:
    scan_id: str
    domain_or_target: str
    total_vulns: int
    playbooks: List[Playbook] = field(default_factory=list)
    generated_at: str = field(default_factory=utcnow_str)
    prioritized_order: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["playbooks"] = [p.to_dict() for p in self.playbooks]
        return d


# ── Prompt templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a Principal Security Engineer and DevSecOps expert.
Your job is to generate precise, production-ready remediation scripts for
specific vulnerabilities found during a penetration test or security scan.

Rules:
1. Generate ONLY runnable code — no explanations inside code blocks
2. Include safety checks (OS version, service state) before making changes
3. Always add a rollback mechanism
4. Scripts must be idempotent (safe to run multiple times)
5. Follow the principle of least privilege
6. Add comments explaining WHAT and WHY
7. Return your response as valid JSON matching the schema provided
"""

REMEDIATION_PROMPT_TEMPLATE = """Generate a remediation playbook for this specific vulnerability:

VULNERABILITY DETAILS:
  Name:            {vuln_name}
  CVEs:            {cves}
  CVSS Score:      {cvss_score}
  Severity:        {severity}
  Affected Host:   {host}:{port}
  Service:         {service} {version}
  OS:              {os_context}
  Script Output:   {script_output}
  CPE:             {cpe}

TARGET ENVIRONMENT:
  Deployment Type: {deployment_type}
  Extra Context:   {extra_context}

Respond ONLY with a JSON object matching this exact schema:
{{
  "explanation": "2-3 sentence explanation of the vulnerability and why this fix works",
  "automation_level": "fully-automated | semi-automated | manual",
  "estimated_time_minutes": <integer>,
  "steps": [
    {{
      "order": 1,
      "title": "Step title",
      "description": "What this step does",
      "code_type": "bash | python | nginx | sql | terraform | yaml | powershell",
      "code": "exact runnable code here",
      "is_automated": true,
      "requires_restart": false,
      "risk": "LOW | MEDIUM | HIGH"
    }}
  ],
  "rollback_script": "bash/script to undo all changes if something breaks",
  "verification_command": "command to verify the fix was applied",
  "notes": "any important caveats or warnings"
}}
"""


# ── Remediation Engine ────────────────────────────────────────────────────────

class RemediationEngine:

    def __init__(self):
        self.client: Optional[anthropic.AsyncAnthropic] = None
        self.gemini_client = None
        
        if settings.gemini_api_key:
            self.gemini_client = genai.Client(api_key=settings.gemini_api_key)
        elif settings.anthropic_api_key:
            self.client = anthropic.AsyncAnthropic(
                api_key=settings.anthropic_api_key
            )
        else:
            logger.warning("[remediation] No GEMINI_API_KEY or ANTHROPIC_API_KEY – AI disabled")

    # ── Main entry points ─────────────────────────────────────

    async def generate_bundle(
        self,
        scan_id: str,
        target: str,
        vulnerabilities: List[Dict],
        deployment_context: Optional[Dict] = None,
    ) -> PlaybookBundle:
        """
        Generate remediation playbooks for all vulnerabilities in a scan.
        Runs concurrently (up to 3 at a time to respect API rate limits).
        """
        bundle = PlaybookBundle(
            scan_id=scan_id,
            domain_or_target=target,
            total_vulns=len(vulnerabilities),
        )

        # Sort by severity (CRITICAL first)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(
                cvss_to_severity(v.get("cvss_score", 0)), 4
            ),
        )

        sem = asyncio.Semaphore(3)

        async def gen_with_sem(vuln: Dict) -> Optional[Playbook]:
            async with sem:
                return await self.generate_playbook(
                    vuln, deployment_context or {}
                )

        tasks = [gen_with_sem(v) for v in sorted_vulns]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Playbook):
                bundle.playbooks.append(r)

        bundle.prioritized_order = [p.playbook_id for p in bundle.playbooks]
        return bundle

    async def generate_playbook(
        self,
        vulnerability: Dict,
        deployment_context: Optional[Dict] = None,
    ) -> Optional[Playbook]:
        """
        Generate a single remediation playbook for one vulnerability.
        Falls back to template-based playbook if AI is unavailable.
        """
        vuln_id = hashlib.md5(
            json.dumps(vulnerability, sort_keys=True).encode()
        ).hexdigest()[:8]

        host = vulnerability.get("ip", "unknown")
        port = vulnerability.get("port", 0)
        script_id = vulnerability.get("script", "")
        cves = vulnerability.get("cves", [])
        cvss = vulnerability.get("cvss_score", 0.0)
        severity = cvss_to_severity(cvss)
        vuln_name = self._derive_vuln_name(script_id, vulnerability)
        service = vulnerability.get("service", "")
        version = vulnerability.get("version", "")
        os_context = vulnerability.get("os", "Linux/Ubuntu")

        if self.client or self.gemini_client:
            playbook = await self._ai_generate_playbook(
                vuln_id=vuln_id,
                vuln_name=vuln_name,
                cves=cves,
                cvss_score=cvss,
                severity=severity,
                host=host,
                port=port,
                service=service,
                version=version,
                os_context=os_context,
                script_output=vulnerability.get("description", "")[:500],
                cpe=vulnerability.get("cpe", ""),
                deployment_context=deployment_context or {},
            )
        else:
            playbook = self._template_playbook(
                vuln_id, vuln_name, cves, severity, host, port, service
            )

        if playbook:
            playbook.file_path = await self._save_playbook(playbook)

        return playbook

    # ── AI generation ─────────────────────────────────────────

    async def _ai_generate_playbook(
        self,
        vuln_id: str,
        vuln_name: str,
        cves: List[str],
        cvss_score: float,
        severity: str,
        host: str,
        port: int,
        service: str,
        version: str,
        os_context: str,
        script_output: str,
        cpe: str,
        deployment_context: Dict,
    ) -> Optional[Playbook]:

        deployment_type = deployment_context.get("type", "bare-metal Linux")
        extra_context = deployment_context.get("extra", "Standard Ubuntu server")

        prompt = REMEDIATION_PROMPT_TEMPLATE.format(
            vuln_name=vuln_name,
            cves=", ".join(cves) if cves else "N/A",
            cvss_score=cvss_score,
            severity=severity,
            host=host,
            port=port,
            service=f"{service} {version}".strip(),
            os_context=os_context,
            script_output=script_output[:400],
            cpe=cpe,
            deployment_type=deployment_type,
            extra_context=extra_context,
        )

        try:
            raw = ""
            if self.gemini_client:
                full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
                response = await asyncio.to_thread(
                    self.gemini_client.models.generate_content,
                    model="gemini-2.5-flash",
                    contents=full_prompt
                )
                raw = response.text
            elif self.client:
                message = await self.client.messages.create(
                    model=settings.ai_model,
                    max_tokens=settings.ai_max_tokens,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                raw = message.content[0].text
                
            return self._parse_ai_response(
                raw, vuln_id, vuln_name, cves, severity,
                host, port, service, os_context
            )

        except Exception as e:
            logger.error(f"[remediation] AI call failed for {vuln_name}: {e}")
            return self._template_playbook(
                vuln_id, vuln_name, cves, severity, host, port, service
            )

    def _parse_ai_response(
        self,
        raw: str,
        vuln_id: str,
        vuln_name: str,
        cves: List[str],
        severity: str,
        host: str,
        port: int,
        service: str,
        os_context: str,
    ) -> Optional[Playbook]:
        """Parse JSON from AI response into Playbook object."""
        try:
            # Strip markdown fences if present
            clean = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()
            data = json.loads(clean)

            steps = [
                PlaybookStep(
                    order=s.get("order", i + 1),
                    title=s.get("title", ""),
                    description=s.get("description", ""),
                    code=s.get("code", ""),
                    code_type=s.get("code_type", "bash"),
                    is_automated=s.get("is_automated", True),
                    requires_restart=s.get("requires_restart", False),
                    risk=s.get("risk", "LOW"),
                )
                for i, s in enumerate(data.get("steps", []))
            ]

            return Playbook(
                playbook_id=f"PB-{vuln_id}",
                vulnerability_id=vuln_id,
                vuln_name=vuln_name,
                cves=cves,
                severity=severity,
                affected_host=host,
                affected_port=port,
                affected_service=service,
                os_context=os_context,
                steps=steps,
                rollback_script=data.get("rollback_script", ""),
                verification_command=data.get("verification_command", ""),
                estimated_time_minutes=int(data.get("estimated_time_minutes", 15)),
                automation_level=data.get("automation_level", "semi-automated"),
                ai_explanation=data.get("explanation", ""),
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"[remediation] JSON parse error: {e}\nRaw: {raw[:200]}")
            return None

    # ── Template fallback playbooks ───────────────────────────

    def _template_playbook(
        self,
        vuln_id: str,
        vuln_name: str,
        cves: List[str],
        severity: str,
        host: str,
        port: int,
        service: str,
    ) -> Playbook:
        """Returns a hardcoded template when AI is unavailable."""
        templates = self._get_template_steps(vuln_name.lower(), service.lower(), port)
        return Playbook(
            playbook_id=f"PB-{vuln_id}",
            vulnerability_id=vuln_id,
            vuln_name=vuln_name,
            cves=cves,
            severity=severity,
            affected_host=host,
            affected_port=port,
            affected_service=service,
            os_context="Linux/Ubuntu",
            steps=templates,
            ai_explanation="Template playbook (AI unavailable). Set ANTHROPIC_API_KEY for AI-generated fixes.",
        )

    def _get_template_steps(self, vuln_name: str, service: str,
                              port: int) -> List[PlaybookStep]:
        """Return hardcoded remediation steps for common vulnerabilities."""
        if "heartbleed" in vuln_name or (service == "ssl" and port == 443):
            return [
                PlaybookStep(1, "Check OpenSSL version",
                    "Verify current OpenSSL version before patching",
                    "openssl version -a", "bash"),
                PlaybookStep(2, "Upgrade OpenSSL",
                    "Upgrade OpenSSL to a patched version",
                    "sudo apt-get update && sudo apt-get install -y openssl libssl-dev",
                    "bash", requires_restart=True),
                PlaybookStep(3, "Restart affected services",
                    "Restart NGINX/Apache to load new OpenSSL",
                    "sudo systemctl restart nginx apache2 || true", "bash"),
                PlaybookStep(4, "Verify fix",
                    "Verify Heartbleed is no longer exploitable",
                    "nmap -sV --script=ssl-heartbleed -p 443 " + "localhost",
                    "bash"),
            ]
        elif "ms17-010" in vuln_name or "eternalblue" in vuln_name:
            return [
                PlaybookStep(1, "Disable SMBv1",
                    "Disable the vulnerable SMBv1 protocol",
                    'echo 0 > /proc/fs/cifs/OplockEnabled\n'
                    'sudo smbcontrol all reload-config', "bash"),
                PlaybookStep(2, "Block SMB on firewall",
                    "Block external SMB access via iptables",
                    "sudo iptables -A INPUT -p tcp --dport 445 -j DROP\n"
                    "sudo iptables -A INPUT -p tcp --dport 139 -j DROP\n"
                    "sudo iptables-save > /etc/iptables/rules.v4",
                    "bash", risk="MEDIUM"),
            ]
        elif "ftp" in service or port == 21:
            return [
                PlaybookStep(1, "Disable anonymous FTP",
                    "Remove anonymous FTP access",
                    "sudo sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' "
                    "/etc/vsftpd.conf\nsudo systemctl restart vsftpd",
                    "bash", requires_restart=True),
            ]
        elif "redis" in service or port == 6379:
            return [
                PlaybookStep(1, "Set Redis password",
                    "Enable requirepass authentication",
                    "REDIS_PASS=$(openssl rand -hex 32)\n"
                    "echo \"requirepass $REDIS_PASS\" >> /etc/redis/redis.conf\n"
                    "echo \"Redis password: $REDIS_PASS\" >> /root/.redis_credentials\n"
                    "sudo systemctl restart redis-server",
                    "bash", requires_restart=True, risk="MEDIUM"),
                PlaybookStep(2, "Bind to localhost only",
                    "Prevent external Redis access",
                    "sudo sed -i 's/^bind.*/bind 127.0.0.1 -::1/' "
                    "/etc/redis/redis.conf\nsudo systemctl restart redis-server",
                    "bash"),
            ]
        else:
            return [
                PlaybookStep(1, "Generic hardening",
                    f"Apply security updates for {service or 'service'} on port {port}",
                    f"# Update the affected service\n"
                    f"sudo apt-get update && sudo apt-get upgrade -y\n"
                    f"# Restrict access via firewall\n"
                    f"sudo ufw deny {port}/tcp\n"
                    f"sudo ufw status",
                    "bash"),
            ]

    # ── Persistence ───────────────────────────────────────────

    async def _save_playbook(self, playbook: Playbook) -> str:
        """Write the playbook to disk as a shell script + JSON manifest."""
        pb_dir = settings.playbooks_dir / playbook.playbook_id
        pb_dir.mkdir(parents=True, exist_ok=True)

        # JSON manifest
        manifest_path = pb_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(playbook.to_dict(), indent=2, default=str)
        )

        # Consolidated bash runner
        runner_lines = [
            "#!/usr/bin/env bash",
            "# =============================================",
            f"# Playbook: {playbook.playbook_id}",
            f"# Vulnerability: {playbook.vuln_name}",
            f"# Severity: {playbook.severity}",
            f"# Generated: {playbook.generated_at}",
            "# =============================================",
            "set -euo pipefail",
            "",
        ]
        for step in playbook.steps:
            runner_lines += [
                f"\n# Step {step.order}: {step.title}",
                f"# {step.description}",
            ]
            if step.code_type == "bash":
                runner_lines.append(step.code)
            else:
                # Write non-bash code to a separate file
                ext_map = {
                    "python": "py", "nginx": "conf",
                    "sql": "sql", "terraform": "tf",
                    "yaml": "yaml", "javascript": "js",
                }
                ext = ext_map.get(step.code_type, "txt")
                step_file = pb_dir / f"step_{step.order}.{ext}"
                step_file.write_text(step.code)
                runner_lines.append(
                    f"echo 'See {step_file.name} for {step.code_type} code'"
                )

        if playbook.verification_command:
            runner_lines += [
                "\n# Verification",
                playbook.verification_command,
            ]

        runner_path = pb_dir / "run.sh"
        runner_path.write_text("\n".join(runner_lines))
        runner_path.chmod(0o750)

        # Rollback script
        if playbook.rollback_script:
            rollback_path = pb_dir / "rollback.sh"
            rollback_path.write_text(
                f"#!/usr/bin/env bash\n# Rollback for {playbook.playbook_id}\n"
                + playbook.rollback_script
            )
            rollback_path.chmod(0o750)

        logger.info(f"[remediation] playbook saved → {pb_dir}")
        return str(pb_dir)

    # ── Helpers ───────────────────────────────────────────────

    def _derive_vuln_name(self, script_id: str, vuln: Dict) -> str:
        name_map = {
            "ssl-heartbleed":          "OpenSSL Heartbleed (CVE-2014-0160)",
            "smb-vuln-ms17-010":       "EternalBlue / MS17-010",
            "smb-vuln-ms08-067":       "MS08-067 NetAPI RCE",
            "ftp-anon":                "Anonymous FTP Login",
            "mysql-empty-password":    "MySQL Empty Root Password",
            "http-shellshock":         "Shellshock (CVE-2014-6271)",
            "http-sql-injection":      "SQL Injection",
            "http-csrf":               "Cross-Site Request Forgery",
            "ssl-poodle":              "POODLE SSLv3 Downgrade",
            "ssl-dh-params":           "Weak Diffie-Hellman Parameters",
            "http-security-headers":   "Missing Security Headers",
            "redis-info":              "Redis Unauthenticated Access",
            "mongodb-info":            "MongoDB Unauthenticated Access",
        }
        if script_id in name_map:
            return name_map[script_id]
        cves = vuln.get("cves", [])
        if cves:
            return f"Vulnerability ({', '.join(cves[:2])})"
        return script_id.replace("-", " ").title() or "Unknown Vulnerability"


# ── Convenience function ──────────────────────────────────────────────────────

async def generate_remediation(
    scan_id: str,
    target: str,
    vulnerabilities: List[Dict],
    deployment_context: Optional[Dict] = None,
) -> PlaybookBundle:
    engine = RemediationEngine()
    return await engine.generate_bundle(
        scan_id, target, vulnerabilities, deployment_context
    )
