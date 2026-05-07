"""
utils/helpers.py
────────────────────────────────────────────────────────────────
Shared utility functions used across modules.
"""

from __future__ import annotations

import re
import socket
import ipaddress
import hashlib
import json
import logging
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import netaddr
from rich.console import Console
from rich.logging import RichHandler

console = Console()


# ── Logging setup ────────────────────────────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=Console(stderr=True))],
    )
    return logging.getLogger(name)


logger = get_logger(__name__)


# ── Network helpers ──────────────────────────────────────────────────────────

def is_valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def resolve_target(target: str) -> Optional[str]:
    """Resolve domain → IP; return IP as-is."""
    if is_valid_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR into list of host IPs (max 1024)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(h) for h in net.hosts()]
        return hosts[:1024]
    except ValueError:
        return []


def ip_to_asn(ip: str) -> Optional[str]:
    """Quick ASN lookup via Team Cymru DNS."""
    try:
        rev = ".".join(reversed(ip.split(".")))
        answer = socket.getaddrinfo(f"{rev}.origin.asn.cymru.com", None)
        return str(answer[0][4][0]) if answer else None
    except Exception:
        return None


def get_local_networks() -> List[str]:
    """Return local network CIDRs detected on the host."""
    import subprocess
    result = subprocess.run(
        ["ip", "-o", "-f", "inet", "addr", "show"],
        capture_output=True, text=True
    )
    cidrs: List[str] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            cidr = parts[3]
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if not net.is_loopback:
                    cidrs.append(str(net))
            except ValueError:
                pass
    return list(set(cidrs))


# ── Hashing / fingerprinting ─────────────────────────────────────────────────

def fingerprint(data: Any) -> str:
    raw = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Time helpers ─────────────────────────────────────────────────────────────

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_str() -> str:
    return utcnow().isoformat()


# ── Async helpers ────────────────────────────────────────────────────────────

async def run_in_executor(func, *args):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, func, *args)


async def gather_with_limit(coros, limit: int = 10):
    """Run coroutines with max concurrency = limit."""
    sem = asyncio.Semaphore(limit)

    async def wrap(coro):
        async with sem:
            return await coro

    return await asyncio.gather(*[wrap(c) for c in coros], return_exceptions=True)


# ── CVSS severity helper ─────────────────────────────────────────────────────

def cvss_to_severity(score: float) -> str:
    if score == 0:
        return "INFO"
    elif score < 4.0:
        return "LOW"
    elif score < 7.0:
        return "MEDIUM"
    elif score < 9.0:
        return "HIGH"
    else:
        return "CRITICAL"


# ── Port / service helpers ────────────────────────────────────────────────────

RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def classify_port_risk(port: int, service: str = "") -> str:
    known = RISKY_PORTS.get(port, "")
    if port in (23, 512, 513, 514):
        return "CRITICAL"
    if port in (21, 161, 445, 1433, 3389, 5900, 6379, 9200, 27017):
        return "HIGH"
    if port in (22, 25, 110, 111, 139, 389, 1521, 2049, 3306, 5432):
        return "MEDIUM"
    return "LOW"
