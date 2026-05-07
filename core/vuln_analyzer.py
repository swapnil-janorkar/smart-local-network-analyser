"""
core/vuln_analyzer.py
────────────────────────────────────────────────────────────────
Vulnerability Analysis & Enrichment Engine

  • CVE enrichment via NVD (NIST) API
  • CVSS v3 score normalisation
  • Vulnerability deduplication and merging
  • Risk prioritisation (asset criticality × CVSS × exploitability)
  • False-positive filtering
  • Trend analysis (new vs recurring vulns across scans)
  • Structured VulnReport output ready for remediation engine
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple

import aiohttp

from utils.helpers import get_logger, cvss_to_severity, utcnow_str

logger = get_logger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class CveDetail:
    cve_id: str
    description: str = ""
    cvss_v3_score: float = 0.0
    cvss_v3_vector: str = ""
    cvss_v2_score: float = 0.0
    severity: str = "INFO"
    published: str = ""
    modified: str = ""
    cpe_list: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    is_exploit_available: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class EnrichedVuln:
    vuln_id: str                    # SHA fingerprint
    ip: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    os: str = ""
    script_id: str = ""
    vuln_name: str = ""
    cves: List[str] = field(default_factory=list)
    cve_details: List[CveDetail] = field(default_factory=list)
    max_cvss: float = 0.0
    severity: str = "INFO"
    description: str = ""
    raw_output: str = ""
    risk_priority: int = 0          # 1 (highest) – 10 (lowest)
    is_false_positive: bool = False
    is_exploitable: bool = False
    exploitability_notes: str = ""
    first_seen: str = field(default_factory=utcnow_str)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["cve_details"] = [c.to_dict() for c in self.cve_details]
        return d


@dataclass
class VulnReport:
    scan_id: str
    target: str
    generated_at: str = field(default_factory=utcnow_str)
    total_vulns: int = 0
    enriched_vulns: List[EnrichedVuln] = field(default_factory=list)
    risk_matrix: Dict = field(default_factory=dict)
    top_risks: List[Dict] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)
    exploitable_count: int = 0
    new_vulns: List[str] = field(default_factory=list)     # IDs not seen before
    recurring_vulns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["enriched_vulns"] = [v.to_dict() for v in self.enriched_vulns]
        return d


# ── NVD CVE Fetcher ───────────────────────────────────────────────────────────

class NVDClient:
    """
    Query the NIST National Vulnerability Database REST API v2.
    Free, no key required (rate-limited to ~50 req/30s).
    """

    async def fetch_cve(self, cve_id: str) -> Optional[CveDetail]:
        url = f"{NVD_API_URL}?cveId={cve_id}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"User-Agent": "SecurityAnalyzer/1.0"},
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    vulns = data.get("vulnerabilities", [])
                    if not vulns:
                        return None
                    return self._parse(vulns[0])
        except Exception as e:
            logger.debug(f"[nvd] fetch {cve_id} error: {e}")
            return None

    async def fetch_batch(self, cve_ids: List[str]) -> Dict[str, CveDetail]:
        """Fetch multiple CVEs concurrently (with rate-limit throttle)."""
        results: Dict[str, CveDetail] = {}
        sem = asyncio.Semaphore(5)   # max 5 concurrent NVD requests

        async def fetch_one(cve: str):
            async with sem:
                detail = await self.fetch_cve(cve)
                if detail:
                    results[cve] = detail
                await asyncio.sleep(0.3)  # ~50 req/30s ≈ 1 req/0.6s per slot

        await asyncio.gather(*[fetch_one(c) for c in set(cve_ids)])
        return results

    def _parse(self, entry: Dict) -> CveDetail:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")

        # Description
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # CVSS v3
        cvss3_score = 0.0
        cvss3_vector = ""
        exploit_score = 0.0
        impact_score = 0.0
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
            cvss3_score = m.get("cvssData", {}).get("baseScore", 0.0)
            cvss3_vector = m.get("cvssData", {}).get("vectorString", "")
            exploit_score = m.get("exploitabilityScore", 0.0)
            impact_score = m.get("impactScore", 0.0)
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]
            cvss3_score = m.get("cvssData", {}).get("baseScore", 0.0)
            cvss3_vector = m.get("cvssData", {}).get("vectorString", "")

        # CVSS v2
        cvss2_score = 0.0
        if "cvssMetricV2" in metrics:
            cvss2_score = (
                metrics["cvssMetricV2"][0]
                .get("cvssData", {})
                .get("baseScore", 0.0)
            )

        # CPE
        cpe_list: List[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe_list.append(cpe_match.get("criteria", ""))

        # References
        refs = [
            r.get("url", "")
            for r in cve.get("references", [])
            if r.get("url")
        ]

        # Check if exploit is available from references
        is_exploit = any(
            any(kw in r.lower() for kw in
                ["exploit-db", "exploitdb", "metasploit", "packetstorm", "github.com/exploit"])
            for r in refs
        )

        return CveDetail(
            cve_id=cve_id,
            description=desc[:1000],
            cvss_v3_score=cvss3_score,
            cvss_v3_vector=cvss3_vector,
            cvss_v2_score=cvss2_score,
            severity=cvss_to_severity(cvss3_score or cvss2_score),
            published=cve.get("published", ""),
            modified=cve.get("lastModified", ""),
            cpe_list=cpe_list[:10],
            references=refs[:5],
            exploitability_score=exploit_score,
            impact_score=impact_score,
            is_exploit_available=is_exploit,
        )


# ── False-Positive Filter ─────────────────────────────────────────────────────

# Known false-positive patterns from common NSE scripts
FP_PATTERNS = [
    # vuln script reports "likely" but with low confidence on these services
    ("http-sql-injection", lambda v: v.get("port") in (80, 443) and
     "login" not in v.get("raw_output", "").lower()),
    # SNMP "vulnerability" reports on internal-only interfaces
    ("snmp-info", lambda v: v.get("ip", "").startswith("127.")),
]

def is_false_positive(vuln: Dict) -> Tuple[bool, str]:
    script_id = vuln.get("script", "")
    for pattern_script, check_fn in FP_PATTERNS:
        if pattern_script in script_id:
            try:
                if check_fn(vuln):
                    return True, f"FP filter: {pattern_script}"
            except Exception:
                pass
    return False, ""


# ── Risk Prioritiser ──────────────────────────────────────────────────────────

# Port-based asset criticality multiplier
ASSET_CRITICALITY = {
    3389: 1.5,    # RDP – high-value target
    22:   1.3,    # SSH
    443:  1.2,    # HTTPS web service
    80:   1.1,
    1433: 1.4,    # MSSQL
    3306: 1.4,    # MySQL
    5432: 1.4,    # PostgreSQL
    27017: 1.4,   # MongoDB
    6379: 1.4,    # Redis
    9200: 1.3,    # Elasticsearch
    5900: 1.5,    # VNC
    23:   2.0,    # Telnet – very high risk
}

def calculate_risk_priority(vuln: EnrichedVuln) -> int:
    """
    Return risk priority 1-10 (1 = most critical, 10 = lowest).
    Formula: normalised CVSS × asset criticality × exploit multiplier
    """
    base = vuln.max_cvss / 10.0
    asset_mult = ASSET_CRITICALITY.get(vuln.port, 1.0)
    exploit_mult = 1.5 if vuln.is_exploitable else 1.0
    score = base * asset_mult * exploit_mult

    # Map 0-1.5 range to 1-10 inverted priority
    priority = max(1, min(10, int(10 - (score * 6))))
    return priority


# ── Main Analyser ─────────────────────────────────────────────────────────────

class VulnerabilityAnalyzer:

    def __init__(self):
        self.nvd = NVDClient()

    async def analyze(
        self,
        scan_id: str,
        target: str,
        raw_vulns: List[Dict],
        enrich_cves: bool = True,
        previous_vuln_ids: Optional[Set[str]] = None,
    ) -> VulnReport:
        """
        Full vulnerability analysis pipeline:
          1. Deduplicate
          2. False-positive filter
          3. CVE enrichment via NVD
          4. Risk prioritisation
          5. Trend analysis (new vs recurring)
        """
        report = VulnReport(scan_id=scan_id, target=target)
        previous_ids = previous_vuln_ids or set()

        # ── Step 1: Deduplicate ────────────────────────────────
        deduped = self._deduplicate(raw_vulns)
        logger.info(f"[vuln-analyzer] {len(raw_vulns)} → {len(deduped)} after dedup")

        # ── Step 2: FP filter ──────────────────────────────────
        filtered = []
        for v in deduped:
            fp, reason = is_false_positive(v)
            if not fp:
                filtered.append(v)
            else:
                logger.debug(f"[vuln-analyzer] FP removed: {v.get('script')} – {reason}")

        # ── Step 3: Build EnrichedVuln objects ─────────────────
        enriched: List[EnrichedVuln] = []
        for v in filtered:
            ev = self._to_enriched(v)
            enriched.append(ev)

        # ── Step 4: CVE enrichment (batch NVD lookups) ─────────
        if enrich_cves:
            all_cves = [c for ev in enriched for c in ev.cves]
            if all_cves:
                cve_cache = await self.nvd.fetch_batch(all_cves[:50])  # cap at 50
                for ev in enriched:
                    for cve_id in ev.cves:
                        if cve_id in cve_cache:
                            ev.cve_details.append(cve_cache[cve_id])
                    if ev.cve_details:
                        ev.max_cvss = max(
                            c.cvss_v3_score or c.cvss_v2_score
                            for c in ev.cve_details
                        )
                        ev.severity = cvss_to_severity(ev.max_cvss)
                        ev.is_exploitable = any(
                            c.is_exploit_available for c in ev.cve_details
                        )
                        ev.exploitability_notes = ", ".join(
                            c.cve_id for c in ev.cve_details
                            if c.is_exploit_available
                        )

        # ── Step 5: Risk prioritisation ────────────────────────
        for ev in enriched:
            ev.risk_priority = calculate_risk_priority(ev)

        # Sort: lowest priority number = most critical
        enriched.sort(key=lambda x: (x.risk_priority, -x.max_cvss))

        # ── Step 6: Trend analysis ─────────────────────────────
        for ev in enriched:
            if ev.vuln_id in previous_ids:
                report.recurring_vulns.append(ev.vuln_id)
                ev.tags.append("recurring")
            else:
                report.new_vulns.append(ev.vuln_id)
                ev.tags.append("new")

        # ── Finalise report ────────────────────────────────────
        report.enriched_vulns = enriched
        report.total_vulns = len(enriched)
        report.exploitable_count = sum(1 for e in enriched if e.is_exploitable)
        report.affected_hosts = list(set(e.ip for e in enriched))
        report.risk_matrix = self._build_risk_matrix(enriched)
        report.top_risks = [
            {
                "rank": i + 1,
                "vuln_id": e.vuln_id,
                "name": e.vuln_name,
                "host": f"{e.ip}:{e.port}",
                "cvss": e.max_cvss,
                "severity": e.severity,
                "exploitable": e.is_exploitable,
                "priority": e.risk_priority,
            }
            for i, e in enumerate(enriched[:10])
        ]

        return report

    # ── Helpers ───────────────────────────────────────────────

    def _deduplicate(self, vulns: List[Dict]) -> List[Dict]:
        seen: Set[str] = set()
        unique: List[Dict] = []
        for v in vulns:
            key = hashlib.md5(
                f"{v.get('ip')}:{v.get('port')}:{v.get('script')}".encode()
            ).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique

    def _to_enriched(self, v: Dict) -> EnrichedVuln:
        vuln_id = hashlib.md5(
            f"{v.get('ip')}:{v.get('port')}:{v.get('script')}".encode()
        ).hexdigest()[:12]

        cvss = float(v.get("cvss_score", 0.0))

        return EnrichedVuln(
            vuln_id=vuln_id,
            ip=v.get("ip", ""),
            port=int(v.get("port", 0)),
            protocol=v.get("protocol", "tcp"),
            service=v.get("service", ""),
            version=v.get("version", ""),
            os=v.get("os", ""),
            script_id=v.get("script", ""),
            vuln_name=v.get("script", "").replace("-", " ").title(),
            cves=v.get("cves", []),
            max_cvss=cvss,
            severity=cvss_to_severity(cvss),
            description=v.get("description", "")[:500],
            raw_output=v.get("raw_output", "")[:1000],
        )

    def _build_risk_matrix(self, vulns: List[EnrichedVuln]) -> Dict:
        matrix: Dict[str, Dict] = {
            "CRITICAL": {"count": 0, "exploitable": 0, "hosts": []},
            "HIGH":     {"count": 0, "exploitable": 0, "hosts": []},
            "MEDIUM":   {"count": 0, "exploitable": 0, "hosts": []},
            "LOW":      {"count": 0, "exploitable": 0, "hosts": []},
            "INFO":     {"count": 0, "exploitable": 0, "hosts": []},
        }
        for v in vulns:
            s = v.severity
            if s not in matrix:
                s = "INFO"
            matrix[s]["count"] += 1
            if v.is_exploitable:
                matrix[s]["exploitable"] += 1
            if v.ip not in matrix[s]["hosts"]:
                matrix[s]["hosts"].append(v.ip)
        return matrix
