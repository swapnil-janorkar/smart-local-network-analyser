"""
core/shadow_it.py
────────────────────────────────────────────────────────────────
Shadow IT / Forgotten Attack Surface Discovery
──────────────────────────────────────────────
Combines OSINT sources to surface assets the organization forgot
it owned or never knew were public:

  1. GitHub Leak Scanner   – searches for API keys, credentials, and
                             internal hostnames accidentally committed
  2. Expired-Subdomain Detector – identifies subdomains pointing to
                             unclaimed cloud resources (takeover risk)
  3. Forgotten Pastebin / Gist – public pastes referencing the domain
  4. Cloud Storage Exposure – open S3/GCS/Azure buckets
  5. Shodan Dork Discovery  – finds exposed services tied to the org
  6. Trello / public board leak finder
  7. AI-powered correlation – uses Claude to correlate raw OSINT
                             findings into a structured attack-surface map
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

import aiohttp

from utils.config import settings
from utils.helpers import get_logger, utcnow_str

logger = get_logger(__name__)

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class LeakFinding:
    source: str                   # github / pastebin / trello / etc.
    url: str
    snippet: str                  # redacted excerpt
    finding_type: str             # api_key / credential / hostname / etc.
    severity: str                 # CRITICAL / HIGH / MEDIUM / LOW
    repo_or_paste: str = ""
    file_path: str = ""
    raw_match: str = ""
    timestamp: str = field(default_factory=utcnow_str)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CloudBucket:
    provider: str                 # s3 / gcs / azure
    bucket_name: str
    url: str
    is_public: bool = False
    files_exposed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ShadowItResult:
    domain: str
    scan_id: str
    status: str = "running"
    started_at: str = field(default_factory=utcnow_str)
    finished_at: str = ""
    github_leaks: List[LeakFinding] = field(default_factory=list)
    cloud_buckets: List[CloudBucket] = field(default_factory=list)
    pastebin_hits: List[LeakFinding] = field(default_factory=list)
    trello_boards: List[Dict] = field(default_factory=list)
    forgotten_assets: List[Dict] = field(default_factory=list)
    ai_correlation: str = ""
    attack_surface_map: Dict = field(default_factory=dict)
    risk_score: float = 0.0
    summary: Dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d


# ── Regex patterns for secret detection ──────────────────────────────────────

SECRET_PATTERNS = {
    "aws_access_key":       (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    "aws_secret_key":       (r"(?i)aws_secret.*['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    "github_token":         (r"ghp_[0-9a-zA-Z]{36}", "CRITICAL"),
    "github_oauth":         (r"gho_[0-9a-zA-Z]{36}", "CRITICAL"),
    "google_api_key":       (r"AIza[0-9A-Za-z-_]{35}", "HIGH"),
    "stripe_secret":        (r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
    "stripe_publishable":   (r"pk_live_[0-9a-zA-Z]{24}", "HIGH"),
    "slack_token":          (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}", "HIGH"),
    "slack_webhook":        (r"https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}", "HIGH"),
    "private_key":          (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "CRITICAL"),
    "jwt_token":            (r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "MEDIUM"),
    "password_in_url":      (r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}", "HIGH"),
    "ssh_private_key":      (r"-----BEGIN OPENSSH PRIVATE KEY-----", "CRITICAL"),
    "anthropic_api_key":    (r"sk-ant-[a-zA-Z0-9-]{93}", "CRITICAL"),
    "openai_api_key":       (r"sk-[a-zA-Z0-9]{48}", "HIGH"),
    "db_connection_string": (r"(?i)(?:postgres|mysql|mongodb):\/\/[^\s\"']+", "HIGH"),
    "sendgrid_key":         (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "HIGH"),
}


# ── GitHub Leak Scanner ───────────────────────────────────────────────────────

class GitHubLeakScanner:

    BASE_URL = "https://api.github.com/search/code"

    def __init__(self, token: Optional[str] = None):
        self.token = token or settings.github_token
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    async def search(self, domain: str) -> List[LeakFinding]:
        """
        Run multiple GitHub dork queries for the domain and
        scan matching code for secrets.
        """
        company = domain.split(".")[0]
        dork_queries = [
            f'"{domain}" password',
            f'"{domain}" secret',
            f'"{domain}" api_key',
            f'"{domain}" credentials',
            f'"{company}" db_password',
            f'"{company}" connectionstring',
            f'"{company}" token',
            f'"{company}" BEGIN RSA PRIVATE',
            f'filename:.env "{domain}"',
            f'filename:config.yml "{domain}" password',
            f'filename:docker-compose.yml "{domain}"',
            f'filename:.htpasswd "{domain}"',
        ]

        all_findings: List[LeakFinding] = []
        for query in dork_queries[:settings.osint_github_max_pages]:
            try:
                findings = await self._search_query(domain, query)
                all_findings.extend(findings)
                await asyncio.sleep(1.5)   # GitHub rate limit
            except Exception as e:
                logger.debug(f"[github-leak] query error: {e}")

        # De-duplicate by URL + snippet
        seen: Set[str] = set()
        unique: List[LeakFinding] = []
        for f in all_findings:
            key = f.url + f.finding_type
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    async def _search_query(self, domain: str,
                              query: str) -> List[LeakFinding]:
        findings: List[LeakFinding] = []
        params = {"q": query, "per_page": 10}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                self.BASE_URL,
                headers=self.headers,
                params=params,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 403:
                    logger.warning("[github-leak] rate limited")
                    return []
                if resp.status != 200:
                    return []
                data = await resp.json()

            for item in data.get("items", []):
                content_url = item.get("url", "")
                html_url = item.get("html_url", "")
                repo_name = item.get("repository", {}).get("full_name", "")
                file_path = item.get("path", "")

                # Fetch raw file content
                raw_content = await self._fetch_raw_content(
                    session, item, content_url
                )
                if not raw_content:
                    continue

                # Scan for secrets
                for pattern_name, (pattern, severity) in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, raw_content)
                    for match in matches[:3]:
                        # Redact middle of match for safety
                        redacted = self._redact(match)
                        findings.append(LeakFinding(
                            source="github",
                            url=html_url,
                            snippet=redacted,
                            finding_type=pattern_name,
                            severity=severity,
                            repo_or_paste=repo_name,
                            file_path=file_path,
                            raw_match=redacted,
                        ))
        return findings

    async def _fetch_raw_content(self, session: aiohttp.ClientSession,
                                  item: Dict, content_url: str) -> str:
        try:
            async with session.get(
                content_url,
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    content = data.get("content", "")
                    encoding = data.get("encoding", "base64")
                    if encoding == "base64":
                        return base64.b64decode(
                            content.replace("\n", "")
                        ).decode("utf-8", errors="ignore")
                    return content
        except Exception:
            pass
        return ""

    @staticmethod
    def _redact(value: str) -> str:
        """Redact middle portion of a sensitive value."""
        if len(value) <= 8:
            return "***"
        keep = 4
        return value[:keep] + "***" + value[-keep:]


# ── Cloud Bucket Enumerator ───────────────────────────────────────────────────

class CloudBucketEnumerator:

    async def enumerate(self, domain: str) -> List[CloudBucket]:
        company = domain.split(".")[0]
        bucket_names = self._generate_bucket_names(company, domain)
        tasks = [self._check_bucket(name) for name in bucket_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results
                if isinstance(r, CloudBucket) and r.is_public]

    def _generate_bucket_names(self, company: str,
                                 domain: str) -> List[str]:
        return [
            company, f"{company}-prod", f"{company}-production",
            f"{company}-dev", f"{company}-staging", f"{company}-backup",
            f"{company}-assets", f"{company}-static", f"{company}-media",
            f"{company}-uploads", f"{company}-data", f"{company}-files",
            f"{company}-logs", f"{company}-archive", f"www-{company}",
            domain.replace(".", "-"), domain,
        ]

    async def _check_bucket(self, name: str) -> CloudBucket:
        """Check S3, GCS, and Azure Blob."""
        # AWS S3
        s3_url = f"https://{name}.s3.amazonaws.com"
        b = await self._http_check(name, "s3", s3_url)
        if b:
            return b

        # GCS
        gcs_url = f"https://storage.googleapis.com/{name}"
        b = await self._http_check(name, "gcs", gcs_url)
        if b:
            return b

        # Azure
        azure_url = f"https://{name}.blob.core.windows.net"
        b = await self._http_check(name, "azure", azure_url)
        if b:
            return b

        return CloudBucket(provider="none", bucket_name=name,
                           url="", is_public=False)

    async def _http_check(self, name: str, provider: str,
                           url: str) -> Optional[CloudBucket]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=6),
                    allow_redirects=False,
                ) as resp:
                    # 200 = public listing, 403 = exists but private
                    if resp.status in (200, 403):
                        files: List[str] = []
                        if resp.status == 200:
                            body = await resp.text()
                            files = re.findall(r"<Key>([^<]+)</Key>", body)[:10]
                        return CloudBucket(
                            provider=provider,
                            bucket_name=name,
                            url=url,
                            is_public=resp.status == 200,
                            files_exposed=files,
                        )
        except Exception:
            pass
        return None


# ── Pastebin / Gist Hunter ────────────────────────────────────────────────────

class PastebinHunter:

    async def search(self, domain: str) -> List[LeakFinding]:
        """Search public paste aggregators for domain mentions."""
        findings: List[LeakFinding] = []

        # Grep.app (searches public GitHub + pastes)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://grep.app/api/search",
                    params={"q": domain, "filter[lang][0]": "Text"},
                    timeout=aiohttp.ClientTimeout(total=15),
                    headers={"User-Agent": "Mozilla/5.0"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for hit in data.get("hits", {}).get("hits", [])[:10]:
                            src = hit.get("_source", {})
                            snippet = str(src.get("content", {}).get("snippet", ""))
                            if any(w in snippet.lower()
                                   for w in ["password", "secret", "token", "key"]):
                                findings.append(LeakFinding(
                                    source="grep.app",
                                    url=src.get("url", ""),
                                    snippet=snippet[:200],
                                    finding_type="credential_mention",
                                    severity="HIGH",
                                    repo_or_paste=src.get("repo", {}).get("name", ""),
                                ))
        except Exception as e:
            logger.debug(f"[pastebin] grep.app error: {e}")

        return findings


# ── Trello Public Board Finder ────────────────────────────────────────────────

class TrelloBoardFinder:

    async def search(self, domain: str) -> List[Dict]:
        """Find public Trello boards mentioning the domain."""
        company = domain.split(".")[0]
        boards: List[Dict] = []
        try:
            async with aiohttp.ClientSession() as session:
                for query in [company, domain]:
                    async with session.get(
                        "https://trello.com/search",
                        params={"q": query, "modelTypes": "boards"},
                        timeout=aiohttp.ClientTimeout(total=10),
                        headers={"User-Agent": "Mozilla/5.0"},
                    ) as resp:
                        if resp.status == 200:
                            # Trello search returns HTML; parse for board links
                            body = await resp.text()
                            matches = re.findall(
                                r'href="(/b/[a-zA-Z0-9]+/[^"]+)"', body
                            )
                            for m in set(matches):
                                boards.append({
                                    "url": f"https://trello.com{m}",
                                    "query": query,
                                    "risk": "MEDIUM",
                                    "note": "Public Trello board found",
                                })
        except Exception as e:
            logger.debug(f"[trello] error: {e}")
        return boards


# ── AI Correlation Engine ─────────────────────────────────────────────────────

class AIShadowCorrelator:
    """
    Uses Claude to correlate raw Shadow IT findings into a structured
    attack-surface narrative and prioritised risk map.
    """

    async def correlate(self, domain: str, findings: Dict) -> str:
        if not settings.anthropic_api_key:
            return "AI correlation disabled — set ANTHROPIC_API_KEY."

        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

        prompt = f"""You are an elite cybersecurity analyst performing Shadow IT
and forgotten attack surface assessment for the domain: {domain}

Here is the raw OSINT data collected:

GITHUB LEAKS ({len(findings.get('github_leaks', []))}) findings):
{json.dumps([l for l in findings.get('github_leaks', [])[:5]], indent=2)}

CLOUD BUCKETS:
{json.dumps(findings.get('cloud_buckets', []), indent=2)}

PASTEBIN HITS:
{json.dumps(findings.get('pastebin_hits', [])[:5], indent=2)}

TRELLO BOARDS:
{json.dumps(findings.get('trello_boards', []), indent=2)}

Based on this data, provide:
1. EXECUTIVE SUMMARY (3-4 sentences) of the exposed attack surface
2. TOP 5 CRITICAL FINDINGS with specific risk for each
3. ATTACK CHAIN – how an attacker could chain these findings
4. FORGOTTEN ASSETS – list of assets the org likely doesn't know are public
5. IMMEDIATE ACTIONS required (prioritised)

Be specific, technical, and actionable. Format in clear sections."""

        try:
            message = await client.messages.create(
                model=settings.ai_model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        except Exception as e:
            logger.error(f"[ai-correlator] error: {e}")
            return f"AI correlation failed: {e}"


# ── Main Shadow IT Discovery Engine ──────────────────────────────────────────

class ShadowITDiscovery:

    def __init__(self):
        self.github = GitHubLeakScanner()
        self.buckets = CloudBucketEnumerator()
        self.pastebin = PastebinHunter()
        self.trello = TrelloBoardFinder()
        self.correlator = AIShadowCorrelator()

    async def discover(self, domain: str, scan_id: str) -> ShadowItResult:
        result = ShadowItResult(domain=domain, scan_id=scan_id)
        logger.info(f"[shadow-it] starting discovery for {domain}")

        try:
            # Run all discovery tasks concurrently
            (github_leaks, cloud_buckets, pastebin_hits,
             trello_boards) = await asyncio.gather(
                self.github.search(domain),
                self.buckets.enumerate(domain),
                self.pastebin.search(domain),
                self.trello.search(domain),
                return_exceptions=True,
            )

            result.github_leaks = github_leaks if not isinstance(github_leaks, Exception) else []
            result.cloud_buckets = cloud_buckets if not isinstance(cloud_buckets, Exception) else []
            result.pastebin_hits = pastebin_hits if not isinstance(pastebin_hits, Exception) else []
            result.trello_boards = trello_boards if not isinstance(trello_boards, Exception) else []

            # Build forgotten assets list
            result.forgotten_assets = self._build_forgotten_assets(result)

            # AI correlation
            findings_dict = {
                "github_leaks": [l.to_dict() for l in result.github_leaks],
                "cloud_buckets": [b.to_dict() for b in result.cloud_buckets],
                "pastebin_hits": [p.to_dict() for p in result.pastebin_hits],
                "trello_boards": result.trello_boards,
            }
            result.ai_correlation = await self.correlator.correlate(
                domain, findings_dict
            )

            # Risk score
            result.risk_score = self._calculate_risk_score(result)
            result.attack_surface_map = self._build_surface_map(result)
            result.summary = self._build_summary(result)

            result.status = "completed"
            result.finished_at = utcnow_str()

        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.exception(f"[shadow-it] discovery failed: {exc}")

        return result

    def _build_forgotten_assets(self, result: ShadowItResult) -> List[Dict]:
        assets: List[Dict] = []

        for leak in result.github_leaks:
            if leak.severity in ("CRITICAL", "HIGH"):
                assets.append({
                    "type": "github_secret",
                    "location": leak.url,
                    "description": f"Exposed {leak.finding_type} in {leak.repo_or_paste}",
                    "severity": leak.severity,
                })

        for bucket in result.cloud_buckets:
            if bucket.is_public:
                assets.append({
                    "type": "cloud_storage",
                    "location": bucket.url,
                    "description": f"Public {bucket.provider.upper()} bucket: {bucket.bucket_name}",
                    "severity": "CRITICAL",
                    "files": bucket.files_exposed[:5],
                })

        for board in result.trello_boards:
            assets.append({
                "type": "trello_board",
                "location": board["url"],
                "description": "Public Trello board may contain sensitive info",
                "severity": "MEDIUM",
            })

        return assets

    def _calculate_risk_score(self, result: ShadowItResult) -> float:
        score = 0.0
        weights = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0}
        for leak in result.github_leaks:
            score += weights.get(leak.severity, 1.0)
        for bucket in result.cloud_buckets:
            if bucket.is_public:
                score += 10.0
        score += len(result.trello_boards) * 3.0
        score += len(result.pastebin_hits) * 5.0
        return min(score, 100.0)

    def _build_surface_map(self, result: ShadowItResult) -> Dict:
        return {
            "github_repos_with_leaks": list(set(
                l.repo_or_paste for l in result.github_leaks
            )),
            "exposed_buckets": [
                {"provider": b.provider, "name": b.bucket_name, "url": b.url}
                for b in result.cloud_buckets if b.is_public
            ],
            "secret_types_found": list(set(
                l.finding_type for l in result.github_leaks
            )),
            "risk_score": result.risk_score,
        }

    def _build_summary(self, result: ShadowItResult) -> Dict:
        return {
            "github_leaks": len(result.github_leaks),
            "critical_leaks": sum(
                1 for l in result.github_leaks if l.severity == "CRITICAL"
            ),
            "exposed_buckets": sum(
                1 for b in result.cloud_buckets if b.is_public
            ),
            "pastebin_hits": len(result.pastebin_hits),
            "trello_boards": len(result.trello_boards),
            "total_forgotten_assets": len(result.forgotten_assets),
            "risk_score": result.risk_score,
        }
