"""
core/osint.py
────────────────────────────────────────────────────────────────
OSINT Engine – passive reconnaissance covering:
  • Subdomain enumeration  (DNS brute, crt.sh, subfinder, amass)
  • DNS records (A, MX, TXT, NS, CNAME, SPF, DMARC)
  • WHOIS & registration info
  • SSL / TLS certificate analysis
  • Email harvesting via Hunter.io
  • Shodan host intelligence
  • SecurityTrails passive DNS
  • Technology fingerprinting via HTTP headers
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp
import dns.resolver
import dns.reversename
import whois as python_whois

from utils.config import settings
from utils.helpers import get_logger, utcnow_str, run_in_executor

logger = get_logger(__name__)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class SubdomainInfo:
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    source: str = ""
    is_wildcard: bool = False
    http_status: Optional[int] = None
    technologies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DNSRecord:
    record_type: str
    value: str
    ttl: int = 0

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    san_domains: List[str] = field(default_factory=list)
    valid_from: str = ""
    valid_until: str = ""
    is_expired: bool = False
    days_until_expiry: int = 0
    serial: str = ""
    signature_algorithm: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class WhoisInfo:
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    org: str = ""
    country: str = ""
    raw: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class OsintResult:
    domain: str
    scan_id: str
    status: str = "running"
    started_at: str = field(default_factory=utcnow_str)
    finished_at: str = ""
    subdomains: List[SubdomainInfo] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)
    whois: Optional[WhoisInfo] = None
    certificates: List[CertificateInfo] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    shodan_data: Dict = field(default_factory=dict)
    summary: Dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["subdomains"] = [s.to_dict() for s in self.subdomains]
        d["dns_records"] = [r.to_dict() for r in self.dns_records]
        d["whois"] = self.whois.to_dict() if self.whois else None
        d["certificates"] = [c.to_dict() for c in self.certificates]
        return d


# ── Subdomain wordlist (compact built-in; supplement with external lists) ─────

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin", "cpanel",
    "whm", "portal", "api", "api2", "dev", "dev2", "staging", "stage", "test",
    "uat", "demo", "beta", "alpha", "prod", "production", "secure", "vpn",
    "remote", "login", "dashboard", "app", "mobile", "m", "static", "cdn",
    "assets", "media", "images", "img", "upload", "download", "files", "docs",
    "wiki", "help", "support", "status", "monitor", "grafana", "kibana",
    "jenkins", "jira", "confluence", "gitlab", "git", "repo", "bitbucket",
    "ns1", "ns2", "ns3", "mx", "mx1", "mx2", "smtp1", "relay", "backup",
    "old", "new", "v1", "v2", "intranet", "internal", "corp", "private",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "s3", "storage", "cloud", "aws", "azure", "gcp", "shop", "store",
    "blog", "news", "forum", "community", "members", "user", "users",
    "account", "accounts", "auth", "sso", "oauth", "payment", "pay",
    "checkout", "billing", "invoice", "analytics", "stats", "metrics",
]


# ── OSINT Engine ──────────────────────────────────────────────────────────────

class OSINTEngine:

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = settings.dns_timeout
        self.resolver.lifetime = settings.dns_timeout * 2

    # ── Main entry point ───────────────────────────────────────

    async def full_osint(self, domain: str, scan_id: str) -> OsintResult:
        """
        Run all OSINT modules for a domain and return a combined result.
        """
        result = OsintResult(domain=domain, scan_id=scan_id)
        logger.info(f"[osint] starting full OSINT for {domain}")

        try:
            # Run all modules concurrently where possible
            tasks = [
                self._enumerate_subdomains(domain),
                self._collect_dns_records(domain),
                self._run_whois(domain),
                self._check_cert(domain, 443),
                self._harvest_emails(domain),
            ]
            (subdomains, dns_records, whois_info,
             cert_info, emails) = await asyncio.gather(*tasks,
                                                        return_exceptions=True)

            if not isinstance(subdomains, Exception):
                result.subdomains = subdomains
            if not isinstance(dns_records, Exception):
                result.dns_records = dns_records
            if not isinstance(whois_info, Exception) and whois_info:
                result.whois = whois_info
            if not isinstance(cert_info, Exception) and cert_info:
                result.certificates = [cert_info]
            if not isinstance(emails, Exception):
                result.emails = emails

            # Shodan enrichment (optional)
            if settings.shodan_api_key:
                try:
                    shodan_data = await self._shodan_lookup(domain)
                    result.shodan_data = shodan_data
                except Exception as e:
                    logger.warning(f"[osint] Shodan failed: {e}")

            result.technologies = await self._detect_technologies(domain)
            result.summary = self._build_summary(result)
            result.status = "completed"
            result.finished_at = utcnow_str()

        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.exception(f"[osint] full_osint failed: {exc}")

        return result

    # ── Subdomain enumeration ─────────────────────────────────

    async def _enumerate_subdomains(self, domain: str) -> List[SubdomainInfo]:
        """Combine crt.sh, DNS brute-force, subfinder, amass."""
        found: Dict[str, SubdomainInfo] = {}

        # Layer 1: crt.sh (certificate transparency)
        crt_subs = await self._crtsh_subdomains(domain)
        for s in crt_subs:
            found[s.subdomain] = s

        # Layer 2: SecurityTrails
        if settings.securitytrails_api_key:
            st_subs = await self._securitytrails_subdomains(domain)
            for s in st_subs:
                if s.subdomain not in found:
                    found[s.subdomain] = s

        # Layer 3: DNS brute-force
        brute_subs = await self._dns_bruteforce(domain)
        for s in brute_subs:
            if s.subdomain not in found:
                found[s.subdomain] = s

        # Layer 4: subfinder (if installed)
        sf_subs = await self._run_subfinder(domain)
        for s in sf_subs:
            if s.subdomain not in found:
                found[s.subdomain] = s

        # Resolve all IPs concurrently
        subs = list(found.values())
        resolve_tasks = [self._resolve_subdomain(s) for s in subs]
        subs = await asyncio.gather(*resolve_tasks, return_exceptions=False)

        # HTTP probe to get status codes
        probe_tasks = [self._http_probe(s) for s in subs]
        subs = await asyncio.gather(*probe_tasks, return_exceptions=False)

        logger.info(f"[osint] found {len(subs)} subdomains for {domain}")
        return subs

    async def _crtsh_subdomains(self, domain: str) -> List[SubdomainInfo]:
        """Query crt.sh certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subs: Set[str] = set()
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub.endswith(f".{domain}") or sub == domain:
                                    if "*" not in sub:
                                        subs.add(sub)
        except Exception as e:
            logger.debug(f"[osint] crt.sh error: {e}")
        return [SubdomainInfo(subdomain=s, source="crt.sh") for s in subs]

    async def _dns_bruteforce(self, domain: str) -> List[SubdomainInfo]:
        """Brute-force subdomains using built-in wordlist."""
        found: List[SubdomainInfo] = []
        sem = asyncio.Semaphore(settings.max_subdomain_workers)

        async def check(word: str):
            fqdn = f"{word}.{domain}"
            async with sem:
                try:
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        None, self.resolver.resolve, fqdn, "A"
                    )
                    ips = [str(r) for r in answers]
                    found.append(SubdomainInfo(
                        subdomain=fqdn,
                        ip_addresses=ips,
                        source="brute-force",
                    ))
                except Exception:
                    pass

        await asyncio.gather(*[check(w) for w in SUBDOMAIN_WORDLIST])
        return found

    async def _run_subfinder(self, domain: str) -> List[SubdomainInfo]:
        """Run subfinder binary if available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-silent", "-o", "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            subs = stdout.decode().strip().splitlines()
            return [SubdomainInfo(subdomain=s.strip(), source="subfinder")
                    for s in subs if s.strip()]
        except Exception:
            return []

    async def _securitytrails_subdomains(self, domain: str) -> List[SubdomainInfo]:
        """Query SecurityTrails passive DNS."""
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": settings.securitytrails_api_key}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers,
                                        timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return [
                            SubdomainInfo(
                                subdomain=f"{s}.{domain}",
                                source="securitytrails",
                            )
                            for s in data.get("subdomains", [])
                        ]
        except Exception as e:
            logger.debug(f"[osint] SecurityTrails error: {e}")
        return []

    async def _resolve_subdomain(self, s: SubdomainInfo) -> SubdomainInfo:
        """Resolve A/CNAME records for a subdomain."""
        if s.ip_addresses:
            return s
        try:
            loop = asyncio.get_event_loop()
            try:
                answers = await loop.run_in_executor(
                    None, self.resolver.resolve, s.subdomain, "A"
                )
                s.ip_addresses = [str(r) for r in answers]
            except Exception:
                pass
            try:
                cname_ans = await loop.run_in_executor(
                    None, self.resolver.resolve, s.subdomain, "CNAME"
                )
                s.cnames = [str(r) for r in cname_ans]
                # Detect dangling CNAME (potential subdomain takeover)
                for cname in s.cnames:
                    if any(p in cname for p in [
                        "github.io", "herokuapp.com", "azurewebsites.net",
                        "s3.amazonaws.com", "cloudfront.net",
                    ]):
                        s.technologies.append("possible-subdomain-takeover")
            except Exception:
                pass
        except Exception:
            pass
        return s

    async def _http_probe(self, s: SubdomainInfo) -> SubdomainInfo:
        """HTTP probe to check if subdomain is responding."""
        for scheme in ("https", "http"):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{scheme}://{s.subdomain}",
                        timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=True,
                        ssl=False,
                    ) as resp:
                        s.http_status = resp.status
                        tech = self._detect_tech_from_headers(dict(resp.headers))
                        s.technologies.extend(tech)
                        return s
            except Exception:
                pass
        return s

    # ── DNS record collection ─────────────────────────────────

    async def _collect_dns_records(self, domain: str) -> List[DNSRecord]:
        """Collect A, AAAA, MX, NS, TXT, SPF, DMARC records."""
        records: List[DNSRecord] = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]

        async def resolve_type(rtype: str):
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, self.resolver.resolve, domain, rtype
                )
                for r in answers:
                    records.append(DNSRecord(
                        record_type=rtype,
                        value=str(r),
                        ttl=answers.ttl,
                    ))
            except Exception:
                pass

        await asyncio.gather(*[resolve_type(t) for t in record_types])

        # Special: SPF
        for r in records:
            if r.record_type == "TXT" and "v=spf" in r.value.lower():
                records.append(DNSRecord("SPF", r.value, r.ttl))

        # Special: DMARC
        try:
            loop = asyncio.get_event_loop()
            dmarc = await loop.run_in_executor(
                None, self.resolver.resolve, f"_dmarc.{domain}", "TXT"
            )
            for r in dmarc:
                records.append(DNSRecord("DMARC", str(r), dmarc.ttl))
        except Exception:
            pass

        return records

    # ── WHOIS ─────────────────────────────────────────────────

    async def _run_whois(self, domain: str) -> Optional[WhoisInfo]:
        try:
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, python_whois.whois, domain)
            return WhoisInfo(
                domain=domain,
                registrar=str(w.get("registrar", "") or ""),
                creation_date=str(
                    w.get("creation_date", [None])[0]
                    if isinstance(w.get("creation_date"), list)
                    else w.get("creation_date", "")
                ),
                expiration_date=str(
                    w.get("expiration_date", [None])[0]
                    if isinstance(w.get("expiration_date"), list)
                    else w.get("expiration_date", "")
                ),
                updated_date=str(
                    w.get("updated_date", [None])[0]
                    if isinstance(w.get("updated_date"), list)
                    else w.get("updated_date", "")
                ),
                name_servers=[
                    str(ns).lower()
                    for ns in (w.get("name_servers") or [])
                ],
                emails=list(set(
                    e for e in (
                        [w.get("emails")] if isinstance(w.get("emails"), str)
                        else (w.get("emails") or [])
                    ) if e
                )),
                org=str(w.get("org", "") or ""),
                country=str(w.get("country", "") or ""),
                raw=str(w.get("text", "") or "")[:2000],
            )
        except Exception as e:
            logger.debug(f"[osint] WHOIS error: {e}")
            return None

    # ── Certificate analysis ──────────────────────────────────

    async def _check_cert(self, domain: str,
                           port: int = 443) -> Optional[CertificateInfo]:
        """Retrieve and analyse the TLS certificate."""
        try:
            loop = asyncio.get_event_loop()
            cert_dict = await loop.run_in_executor(
                None, self._get_ssl_cert, domain, port
            )
            if not cert_dict:
                return None

            subject = dict(x[0] for x in cert_dict.get("subject", []))
            issuer = dict(x[0] for x in cert_dict.get("issuer", []))

            san_domains: List[str] = []
            for san_type, san_value in cert_dict.get("subjectAltName", []):
                if san_type == "DNS":
                    san_domains.append(san_value)

            not_after_str = cert_dict.get("notAfter", "")
            not_before_str = cert_dict.get("notBefore", "")

            is_expired = False
            days_left = 0
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                delta = not_after - datetime.utcnow()
                days_left = delta.days
                is_expired = delta.days < 0
            except Exception:
                pass

            return CertificateInfo(
                subject=subject.get("commonName", ""),
                issuer=issuer.get("organizationName", ""),
                san_domains=san_domains,
                valid_from=not_before_str,
                valid_until=not_after_str,
                is_expired=is_expired,
                days_until_expiry=days_left,
                serial=str(cert_dict.get("serialNumber", "")),
                signature_algorithm=cert_dict.get("signatureAlgorithm", ""),
            )
        except Exception as e:
            logger.debug(f"[osint] cert check failed: {e}")
            return None

    def _get_ssl_cert(self, domain: str, port: int) -> Optional[Dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert()
        except Exception:
            return None

    # ── Email harvesting ──────────────────────────────────────

    async def _harvest_emails(self, domain: str) -> List[str]:
        """Collect emails from Hunter.io (if key present) + DNS."""
        emails: Set[str] = set()

        if settings.hunter_api_key:
            try:
                url = (
                    f"https://api.hunter.io/v2/domain-search"
                    f"?domain={domain}&api_key={settings.hunter_api_key}"
                )
                async with aiohttp.ClientSession() as session:
                    async with session.get(url,
                                            timeout=aiohttp.ClientTimeout(total=10)) as r:
                        if r.status == 200:
                            data = await r.json()
                            for entry in data.get("data", {}).get("emails", []):
                                emails.add(entry.get("value", ""))
            except Exception as e:
                logger.debug(f"[osint] Hunter.io error: {e}")

        return list(emails)

    # ── Shodan ────────────────────────────────────────────────

    async def _shodan_lookup(self, domain: str) -> Dict:
        """Shodan DNS + host lookup."""
        import shodan as shodan_lib
        loop = asyncio.get_event_loop()
        api = shodan_lib.Shodan(settings.shodan_api_key)

        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            host = await loop.run_in_executor(None, api.host, ip)
            return {
                "ip": ip,
                "org": host.get("org", ""),
                "isp": host.get("isp", ""),
                "asn": host.get("asn", ""),
                "country": host.get("country_name", ""),
                "city": host.get("city", ""),
                "ports": host.get("ports", []),
                "tags": host.get("tags", []),
                "vulns": list(host.get("vulns", {}).keys()),
                "hostnames": host.get("hostnames", []),
            }
        except Exception as e:
            logger.debug(f"[osint] Shodan error: {e}")
            return {}

    # ── Technology detection ──────────────────────────────────

    async def _detect_technologies(self, domain: str) -> List[str]:
        """Detect technologies by probing the domain."""
        techs: Set[str] = set()
        for scheme in ("https", "http"):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{scheme}://{domain}",
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=True,
                        ssl=False,
                    ) as resp:
                        headers = dict(resp.headers)
                        body = await resp.text(errors="ignore")
                        techs.update(self._detect_tech_from_headers(headers))
                        techs.update(self._detect_tech_from_body(body))
                        return list(techs)
            except Exception:
                pass
        return list(techs)

    def _detect_tech_from_headers(self, headers: Dict[str, str]) -> List[str]:
        techs = []
        header_map = {
            "x-powered-by": lambda v: [v],
            "server": lambda v: [v],
            "x-generator": lambda v: [v],
            "x-drupal-cache": lambda _: ["Drupal"],
            "x-wp-total": lambda _: ["WordPress"],
        }
        for h, fn in header_map.items():
            val = headers.get(h, "") or headers.get(h.capitalize(), "")
            if val:
                techs.extend(fn(val))
        return techs

    def _detect_tech_from_body(self, body: str) -> List[str]:
        techs = []
        patterns = {
            "WordPress": r"wp-content|wp-includes",
            "Drupal": r"drupal\.js|Drupal\.settings",
            "Joomla": r"/components/com_",
            "React": r"__REACT_DEVTOOLS|reactjs\.org",
            "Vue.js": r"vue\.min\.js|__vue__",
            "Angular": r"ng-version|angular\.js",
            "jQuery": r"jquery[\.-][\d\.]+\.min\.js",
            "Bootstrap": r"bootstrap\.min\.css",
            "Cloudflare": r"__cf_bm|__cfduid",
        }
        for tech, pattern in patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                techs.append(tech)
        return techs

    # ── Summary ───────────────────────────────────────────────

    def _build_summary(self, result: OsintResult) -> Dict:
        return {
            "total_subdomains": len(result.subdomains),
            "live_subdomains": sum(
                1 for s in result.subdomains if s.http_status
            ),
            "total_dns_records": len(result.dns_records),
            "total_emails": len(result.emails),
            "technologies": list(set(result.technologies)),
            "cert_expiry_days": (
                result.certificates[0].days_until_expiry
                if result.certificates else None
            ),
            "possible_takeovers": [
                s.subdomain for s in result.subdomains
                if "possible-subdomain-takeover" in s.technologies
            ],
        }
