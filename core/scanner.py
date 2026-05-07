"""
core/scanner.py
────────────────────────────────────────────────────────────────
Comprehensive Nmap-based scanning engine with:
  • Host discovery (ping sweep)
  • Port scanning (TCP SYN, UDP, full-connect)
  • Service / version detection
  • OS fingerprinting
  • NSE vulnerability scripts
  • Structured JSON output
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

import nmap

from utils.config import settings
from utils.helpers import (
    get_logger, resolve_target, is_valid_cidr, is_valid_ip,
    is_valid_domain, classify_port_risk, utcnow_str,
    get_local_networks, run_in_executor
)

logger = get_logger(__name__)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra_info: str
    cpe: str
    risk_level: str
    scripts: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class HostResult:
    ip: str
    hostname: str
    state: str                       # up / down
    os_match: str
    os_accuracy: int
    mac_address: str
    vendor: str
    uptime: str
    ports: List[PortInfo] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    scan_timestamp: str = field(default_factory=utcnow_str)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["ports"] = [p.to_dict() for p in self.ports]
        return d


@dataclass
class ScanResult:
    scan_id: str
    target: str
    scan_type: str
    status: str                       # running / completed / failed
    started_at: str
    finished_at: str = ""
    hosts: List[HostResult] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["hosts"] = [h.to_dict() for h in self.hosts]
        return d


# ── NSE script groups ─────────────────────────────────────────────────────────

NSE_SCRIPTS = {
    "vuln_basic": [
        "vuln",
        "default",
        "auth",
    ],
    "vuln_full": [
        "vuln",
        "exploit",
        "default",
        "auth",
        "broadcast",
    ],
    "web": [
        "http-headers",
        "http-methods",
        "http-title",
        "http-auth",
        "http-shellshock",
        "http-sql-injection",
        "http-csrf",
        "http-xssed",
        "http-cors",
        "http-security-headers",
    ],
    "smb": [
        "smb-vuln-ms17-010",
        "smb-vuln-ms08-067",
        "smb-vuln-cve-2020-0796",
        "smb-enum-shares",
        "smb-enum-users",
        "smb-security-mode",
    ],
    "ssl": [
        "ssl-cert",
        "ssl-enum-ciphers",
        "ssl-heartbleed",
        "ssl-poodle",
        "ssl-dh-params",
        "sslv2",
    ],
    "database": [
        "mysql-empty-password",
        "mysql-info",
        "ms-sql-empty-password",
        "ms-sql-info",
        "pgsql-brute",
        "mongodb-info",
        "redis-info",
    ],
    "network": [
        "snmp-info",
        "snmp-sysdescr",
        "ftp-anon",
        "ftp-vuln-cve2010-4221",
        "ssh-auth-methods",
        "telnet-ntlm-info",
    ],
}


# ── Scanner class ─────────────────────────────────────────────────────────────

class NetworkScanner:
    """
    Wraps python-nmap to provide high-level scanning methods
    and structures results for the REST API.
    """

    def __init__(self):
        self.nm = nmap.PortScanner()
        self._active_scans: Dict[str, ScanResult] = {}

    # ── Public API ────────────────────────────────────────────

    async def discovery_scan(self, target: str, scan_id: str) -> ScanResult:
        """
        Fast host-discovery sweep.  Finds live hosts via ICMP, TCP SYN,
        ARP (local), and UDP ping without a full port scan.
        """
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            scan_type="discovery",
            status="running",
            started_at=utcnow_str(),
        )
        self._active_scans[scan_id] = result

        try:
            # -sn = no port scan; -PE ICMP echo; -PS TCP SYN; -PP ICMP timestamp
            hosts = await run_in_executor(
                self._run_nmap,
                target,
                "-sn -PE -PS21,22,80,443,3389 -PP --open -T4",
            )
            for ip, data in hosts.items():
                h = self._parse_host(ip, data, ports_included=False)
                result.hosts.append(h)

            result.status = "completed"
            result.finished_at = utcnow_str()
            result.summary = self._build_summary(result)
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.exception(f"[scanner] discovery_scan failed: {exc}")

        return result

    async def basic_scan(self, target: str, scan_id: str,
                         ports: str = "1-1000") -> ScanResult:
        """
        Standard TCP SYN scan with service / version detection.
        """
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            scan_type="basic",
            status="running",
            started_at=utcnow_str(),
        )
        self._active_scans[scan_id] = result

        try:
            timing = f"-T{settings.nmap_timing_template}"
            args = f"-sS -sV -O --osscan-guess -p {ports} {timing} --open"
            hosts = await run_in_executor(self._run_nmap, target, args)
            for ip, data in hosts.items():
                h = self._parse_host(ip, data)
                result.hosts.append(h)

            result.status = "completed"
            result.finished_at = utcnow_str()
            result.summary = self._build_summary(result)
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.exception(f"[scanner] basic_scan failed: {exc}")

        return result

    async def vulnerability_scan(self, target: str, scan_id: str,
                                  ports: str = "1-10000",
                                  script_group: str = "vuln_basic") -> ScanResult:
        """
        Full vulnerability scan using NSE scripts.
        Includes service/version detection + OS + scripted vuln checks.
        """
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            scan_type="vulnerability",
            status="running",
            started_at=utcnow_str(),
        )
        self._active_scans[scan_id] = result

        try:
            scripts = ",".join(NSE_SCRIPTS.get(script_group, NSE_SCRIPTS["vuln_basic"]))
            timing = f"-T{settings.nmap_timing_template}"
            args = (
                f"-sS -sV -sC -O --osscan-guess "
                f"--script={scripts} "
                f"--script-args=unsafe=1 "
                f"-p {ports} {timing} --open"
            )
            hosts = await run_in_executor(self._run_nmap, target, args)
            for ip, data in hosts.items():
                h = self._parse_host(ip, data)
                result.hosts.append(h)

            result.status = "completed"
            result.finished_at = utcnow_str()
            result.summary = self._build_summary(result)
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.exception(f"[scanner] vuln_scan failed: {exc}")

        return result

    async def web_scan(self, target: str, scan_id: str) -> ScanResult:
        """
        Targeted web-service scan: HTTP/HTTPS only with web NSE scripts.
        """
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            scan_type="web",
            status="running",
            started_at=utcnow_str(),
        )
        self._active_scans[scan_id] = result

        try:
            scripts = ",".join(NSE_SCRIPTS["web"] + NSE_SCRIPTS["ssl"])
            args = (
                f"-sS -sV -sC "
                f"--script={scripts} "
                f"-p 80,443,8080,8443,8888,8000,3000,4443 "
                f"-T4 --open"
            )
            hosts = await run_in_executor(self._run_nmap, target, args)
            for ip, data in hosts.items():
                h = self._parse_host(ip, data)
                result.hosts.append(h)

            result.status = "completed"
            result.finished_at = utcnow_str()
            result.summary = self._build_summary(result)
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.exception(f"[scanner] web_scan failed: {exc}")

        return result

    async def full_scan(self, target: str, scan_id: str) -> ScanResult:
        """
        Comprehensive scan: all ports, all service probes, all vuln scripts.
        Can take several minutes. Recommended for single hosts.
        """
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            scan_type="full",
            status="running",
            started_at=utcnow_str(),
        )
        self._active_scans[scan_id] = result

        try:
            all_scripts = ",".join(
                NSE_SCRIPTS["vuln_full"]
                + NSE_SCRIPTS["web"]
                + NSE_SCRIPTS["ssl"]
                + NSE_SCRIPTS["smb"]
                + NSE_SCRIPTS["database"]
                + NSE_SCRIPTS["network"]
            )
            args = (
                f"-sS -sU -sV -sC -O --osscan-guess "
                f"--script={all_scripts} "
                f"--script-args=unsafe=1 "
                f"-p- -T4 --open --min-rate=300"
            )
            hosts = await run_in_executor(self._run_nmap, target, args)
            for ip, data in hosts.items():
                h = self._parse_host(ip, data)
                result.hosts.append(h)

            result.status = "completed"
            result.finished_at = utcnow_str()
            result.summary = self._build_summary(result)
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.exception(f"[scanner] full_scan failed: {exc}")

        return result

    async def local_network_scan(self, scan_id: str) -> ScanResult:
        """
        Automatically discover and scan all local subnets on this machine.
        """
        networks = get_local_networks()
        if not networks:
            networks = ["192.168.1.0/24"]
        target = " ".join(networks)
        return await self.basic_scan(target, scan_id, ports="1-1000")

    # ── Internal helpers ──────────────────────────────────────

    def _run_nmap(self, target: str, args: str) -> Dict:
        """Blocking nmap scan – runs in thread pool via run_in_executor."""
        logger.info(f"[nmap] scanning {target!r} with args: {args}")
        try:
            self.nm.scan(hosts=target, arguments=args)
            return dict(self.nm.all_hosts())
        except nmap.PortScannerError as e:
            raise RuntimeError(f"nmap error: {e}")

    def _parse_host(self, ip: str, raw: Any,
                    ports_included: bool = True) -> HostResult:
        """Parse python-nmap host dict into structured HostResult."""
        # hostname
        hostnames = raw.get("hostnames", [])
        hostname = hostnames[0].get("name", ip) if hostnames else ip

        # OS
        os_match = ""
        os_accuracy = 0
        osmatch = raw.get("osmatch", [])
        if osmatch:
            os_match = osmatch[0].get("name", "")
            os_accuracy = int(osmatch[0].get("accuracy", 0))

        # MAC / vendor
        mac = ""
        vendor = ""
        addresses = raw.get("addresses", {})
        if "mac" in addresses:
            mac = addresses["mac"]
            vendor_dict = raw.get("vendor", {})
            vendor = vendor_dict.get(mac, "")

        # uptime
        uptime = raw.get("uptime", {}).get("lastboot", "")

        host = HostResult(
            ip=ip,
            hostname=hostname,
            state=raw.get("status", {}).get("state", "unknown"),
            os_match=os_match,
            os_accuracy=os_accuracy,
            mac_address=mac,
            vendor=vendor,
            uptime=uptime,
        )

        if not ports_included:
            return host

        # Ports
        for proto in ("tcp", "udp"):
            proto_data = raw.get(proto, {})
            for port_num, port_data in proto_data.items():
                scripts_output: Dict[str, str] = {}
                for script_id, script_out in port_data.get("script", {}).items():
                    scripts_output[script_id] = str(script_out)

                pi = PortInfo(
                    port=int(port_num),
                    protocol=proto,
                    state=port_data.get("state", ""),
                    service=port_data.get("name", ""),
                    product=port_data.get("product", ""),
                    version=port_data.get("version", ""),
                    extra_info=port_data.get("extrainfo", ""),
                    cpe=port_data.get("cpe", ""),
                    risk_level=classify_port_risk(int(port_num)),
                    scripts=scripts_output,
                )
                host.ports.append(pi)

                # Extract vulnerabilities from script output
                vulns = self._extract_vulns_from_scripts(
                    ip, int(port_num), scripts_output
                )
                host.vulnerabilities.extend(vulns)

        return host

    def _extract_vulns_from_scripts(
        self,
        ip: str,
        port: int,
        scripts: Dict[str, str],
    ) -> List[Dict]:
        """
        Parse NSE script output for vulnerability data.
        Looks for CVE IDs, CVSS scores, and structured vuln blocks.
        """
        import re
        vulns: List[Dict] = []
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        cvss_pattern = re.compile(r"CVSS[:\s]+(\d+\.?\d*)", re.IGNORECASE)
        state_pattern = re.compile(r"State:\s*(\w+)", re.IGNORECASE)

        for script_id, output in scripts.items():
            if not output or "VULNERABLE" not in output.upper():
                continue

            cves = cve_pattern.findall(output)
            cvss_matches = cvss_pattern.findall(output)
            cvss_score = float(cvss_matches[0]) if cvss_matches else 0.0

            state_match = state_pattern.search(output)
            state = state_match.group(1).lower() if state_match else "unknown"

            # Only include likely vulnerable states
            if state in ("likely", "vulnerable", "appears"):
                vulns.append({
                    "ip": ip,
                    "port": port,
                    "script": script_id,
                    "cves": list(set(cves)),
                    "cvss_score": cvss_score,
                    "state": state,
                    "description": output[:500],
                    "raw_output": output,
                })

        return vulns

    def _build_summary(self, result: ScanResult) -> Dict:
        total_hosts = len(result.hosts)
        up_hosts = sum(1 for h in result.hosts if h.state == "up")
        total_ports = sum(len(h.ports) for h in result.hosts)
        total_vulns = sum(len(h.vulnerabilities) for h in result.hosts)

        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for h in result.hosts:
            for p in h.ports:
                risk_counts[p.risk_level] = risk_counts.get(p.risk_level, 0) + 1

        return {
            "total_hosts": total_hosts,
            "hosts_up": up_hosts,
            "hosts_down": total_hosts - up_hosts,
            "total_open_ports": total_ports,
            "total_vulnerabilities": total_vulns,
            "risk_distribution": risk_counts,
        }

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        return self._active_scans.get(scan_id)


# ── Masscan helper (for large /16 or /8 networks) ─────────────────────────────

class MasscanHelper:
    """
    Wrapper around masscan for ultra-fast port discovery on large ranges.
    Results are then fed into nmap for service detection.
    """

    @staticmethod
    async def fast_port_discovery(target: str, ports: str = "0-65535",
                                   rate: int = 10000) -> List[Dict]:
        """Run masscan, return list of {ip, port}."""
        cmd = [
            "masscan", target,
            f"--ports={ports}",
            f"--rate={rate}",
            "--output-format=json",
            "--output-file=-",
            "--wait=2",
        ]
        loop = asyncio.get_event_loop()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=300
            )
            results: List[Dict] = []
            for line in stdout.decode().splitlines():
                try:
                    obj = json.loads(line)
                    for port_info in obj.get("ports", []):
                        results.append({
                            "ip": obj.get("ip", ""),
                            "port": port_info.get("port", 0),
                            "proto": port_info.get("proto", "tcp"),
                        })
                except json.JSONDecodeError:
                    pass
            return results
        except asyncio.TimeoutError:
            return []
        except FileNotFoundError:
            logger.warning("[masscan] masscan not installed; falling back to nmap")
            return []
