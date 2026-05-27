"""
PHANTOM — WHOIS & DNS Reconnaissance Module

Performs WHOIS lookups and enumerates DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA).
Falls back to subprocess + socket when python libraries unavailable.
"""
from __future__ import annotations
import logging
import subprocess
import socket
from typing import Optional

from .base import ReconModule

logger = logging.getLogger("phantom.recon.whois_dns")


class WhoisDnsModule(ReconModule):
    """WHOIS lookup and DNS record enumeration."""

    name = "whois_dns"
    description = "WHOIS lookup + DNS record enumeration"
    depends_on = []

    def run(self, target, config=None):
        """Populates target.ips and target.notes['dns'].
        
        DNS Queries: A, AAAA, MX, NS, TXT, CNAME, SOA records.
        WHOIS: Uses 'whois' CLI command via subprocess.
        """
        domain = target.domain
        if not domain:
            logger.warning("No domain set, skipping WHOIS/DNS")
            return target
        
        logger.info("Starting WHOIS/DNS enumeration for %s", domain)
        
        # 1. Resolve domain to IPs
        ips = self._resolve_a(domain)
        if ips:
            target.ips.extend(ips)
            if not target.root_ip:
                target.root_ip = ips[0]
        
        # 2. Enumerate DNS records
        dns_records = {}
        
        aaaa = self._resolve_aaaa(domain)
        if aaaa:
            dns_records["aaaa"] = aaaa
        
        mx = self._resolve_mx(domain)
        if mx:
            dns_records["mx"] = mx
        
        ns = self._resolve_ns(domain)
        if ns:
            dns_records["ns"] = ns
        
        txt = self._resolve_txt(domain)
        if txt:
            dns_records["txt"] = txt
        
        cname = self._resolve_cname(domain)
        if cname:
            dns_records["cname"] = cname
        
        target.notes["dns"] = dns_records
        
        # 3. WHOIS lookup
        whois_data = self._whois_lookup(domain)
        if whois_data:
            target.notes["whois"] = whois_data
        
        logger.info("WHOIS/DNS: %d IPs, %d record types", len(ips), len(dns_records))
        return target

    def _resolve_a(self, domain: str) -> list[str]:
        """Resolve A records."""
        ips = []
        try:
            info = socket.getaddrinfo(domain, 0, socket.AF_INET, socket.SOCK_STREAM)
            for i in info:
                ip = i[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        return ips

    def _resolve_aaaa(self, domain: str) -> list[str]:
        """Resolve AAAA (IPv6) records."""
        ips = []
        try:
            info = socket.getaddrinfo(domain, 0, socket.AF_INET6, socket.SOCK_STREAM)
            for i in info:
                ip = i[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        return ips

    def _resolve_mx(self, domain: str) -> list[dict]:
        """Resolve MX records via subprocess + dig."""
        records = []
        try:
            result = subprocess.run(
                ["dig", "+short", "MX", domain],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        records.append({"priority": parts[0], "target": parts[1]})
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return records

    def _resolve_ns(self, domain: str) -> list[str]:
        """Resolve NS records via subprocess + dig."""
        try:
            result = subprocess.run(
                ["dig", "+short", "NS", domain],
                capture_output=True, text=True, timeout=10
            )
            return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _resolve_txt(self, domain: str) -> list[str]:
        """Resolve TXT records via subprocess + dig."""
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", domain],
                capture_output=True, text=True, timeout=10
            )
            records = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip().strip('"')
                if line:
                    records.append(line)
            return records
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _resolve_cname(self, domain: str) -> Optional[str]:
        """Resolve CNAME record."""
        try:
            result = subprocess.run(
                ["dig", "+short", "CNAME", domain],
                capture_output=True, text=True, timeout=10
            )
            cname = result.stdout.strip()
            return cname if cname else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def _whois_lookup(self, domain: str) -> Optional[str]:
        """Perform WHOIS lookup via whois CLI."""
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=30
            )
            # Truncate to first 2000 chars
            output = result.stdout[:2000]
            return output if output else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("whois CLI not available")
            return None

    def validate_target(self, target) -> bool:
        return target is not None and bool(target.domain)
