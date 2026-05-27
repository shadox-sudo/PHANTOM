"""
PHANTOM — Known CVE Matching Module

Detection:
1. Match detected tech stack against built-in CVE database
2. Check versions against affected ranges
3. Report potential CVEs with descriptions and severity
4. Built-in DB of ~25 known CVEs with affected versions
"""
from __future__ import annotations

import re

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class CVEMatcher:
    """Match discovered technology stack against known CVEs."""

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target
        self.cve_db = self._build_cve_db()

    def run(self):
        """Match tech stack against CVE database."""
        print("[*] Starting CVE matching...")
        findings = 0

        tech_stack = self.target.tech_stack
        if not tech_stack:
            print("  [!] No technology stack detected to match against CVEs")
            return

        print(f"  [*] Matching {len(tech_stack)} tech entries against CVE database...")

        # tech_stack is a list of TechInfo objects with name, version, certainty
        for tech in tech_stack:
            try:
                if self._match_cves(tech.name, tech.version):
                    findings += 1
            except Exception as e:
                print(f"  [!] CVE match error for {tech.name}: {e}")
                continue

        print(f"  [+] CVE matching complete — {findings} potential CVE(s) identified")

    # ── CVE matching ────────────────────────────────────────────────

    def _match_cves(self, software: str, version: str) -> bool:
        """Check software/version against CVE database."""
        software_lower = software.lower().strip()
        found = False

        for cve in self.cve_db:
            if cve["software"].lower() != software_lower:
                continue

            affected = cve.get("affected_versions", "")
            if not affected:
                continue

            if not version:
                continue

            if self._version_matches(version, affected):
                self.engine.findings.add(Finding(
                    name=f"CVE Match: {cve['cve_id']}",
                    severity=cve["severity"],
                    url=self.target.domain,
                    param=f"{software} {version}",
                    payload="",
                    evidence=(
                        f"{cve['cve_id']}: {cve['description']} | "
                        f"Affected: {affected} | "
                        f"CVSS: {cve.get('cvss', 'N/A')}"
                    ),
                    phase="vuln",
                ))
                print(f"  [+] {cve['cve_id']} — {software} {version} ({cve['severity']})")
                found = True

        return found

    # ── Version matching ────────────────────────────────────────────

    def _version_matches(self, current: str, affected: str) -> bool:
        """Check if current version falls within affected range."""
        # Handle wildcard
        if affected == "*":
            return True

        # Parse operators
        parts = affected.split()
        if len(parts) == 1:
            return self._compare_versions(current, parts[0]) == 0

        if len(parts) == 2:
            op, ver = parts
            cmp = self._compare_versions(current, ver)
            if op == "<":
                return cmp < 0
            elif op == "<=":
                return cmp <= 0
            elif op == ">":
                return cmp > 0
            elif op == ">=":
                return cmp >= 0
            elif op == "=":
                return cmp == 0
            return True

        if len(parts) == 3 and parts[1] == "-":
            # Range: "X - Y"
            low = self._compare_versions(current, parts[0])
            high = self._compare_versions(current, parts[2])
            return low >= 0 and high <= 0

        return True

    def _compare_versions(self, a: str, b: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        a = re.sub(r'[^0-9.]', '', a).strip(".")
        b = re.sub(r'[^0-9.]', '', b).strip(".")

        a_parts = [int(x) for x in a.split(".") if x.isdigit()]
        b_parts = [int(x) for x in b.split(".") if x.isdigit()]

        max_len = max(len(a_parts), len(b_parts))
        a_parts.extend([0] * (max_len - len(a_parts)))
        b_parts.extend([0] * (max_len - len(b_parts)))

        for i in range(max_len):
            if a_parts[i] < b_parts[i]:
                return -1
            elif a_parts[i] > b_parts[i]:
                return 1

        return 0

    # ── CVE Database ────────────────────────────────────────────────

    def _build_cve_db(self) -> list[dict]:
        """Built-in database of known CVEs."""
        return [
            # ── Log4j ──
            {"cve_id": "CVE-2021-44228", "software": "log4j",
             "affected_versions": "< 2.15.0",
             "description": "Log4j JNDI injection RCE — critical remote code execution",
             "severity": "CRITICAL", "cvss": 10.0},
            {"cve_id": "CVE-2021-45046", "software": "log4j",
             "affected_versions": ">= 2.15.0 < 2.16.0",
             "description": "Log4j denial of service and RCE bypass",
             "severity": "CRITICAL", "cvss": 9.0},
            {"cve_id": "CVE-2021-45105", "software": "log4j",
             "affected_versions": ">= 2.16.0 < 2.17.0",
             "description": "Log4j infinite recursion DoS",
             "severity": "HIGH", "cvss": 7.5},

            # ── Apache ──
            {"cve_id": "CVE-2021-41773", "software": "apache",
             "affected_versions": "= 2.4.49",
             "description": "Path traversal and file disclosure in Apache 2.4.49",
             "severity": "CRITICAL", "cvss": 7.5},
            {"cve_id": "CVE-2021-42013", "software": "apache",
             "affected_versions": "= 2.4.50",
             "description": "Path traversal and RCE in Apache 2.4.50",
             "severity": "CRITICAL", "cvss": 9.0},
            {"cve_id": "CVE-2023-25690", "software": "apache",
             "affected_versions": "< 2.4.56",
             "description": "HTTP request splitting in Apache mod_proxy",
             "severity": "HIGH", "cvss": 6.1},

            # ── Nginx ──
            {"cve_id": "CVE-2023-44487", "software": "nginx",
             "affected_versions": "< 1.24.0",
             "description": "HTTP/2 rapid reset attack (DoS)",
             "severity": "HIGH", "cvss": 7.5},
            {"cve_id": "CVE-2021-23017", "software": "nginx",
             "affected_versions": "< 1.20.1",
             "description": "DNS resolver vulnerability in nginx",
             "severity": "HIGH", "cvss": 8.1},

            # ── PHP ──
            {"cve_id": "CVE-2022-31693", "software": "php",
             "affected_versions": "< 8.0.22",
             "description": "PHPMailer RCE via email header injection",
             "severity": "CRITICAL", "cvss": 9.8},
            {"cve_id": "CVE-2019-11043", "software": "php",
             "affected_versions": "< 7.3.11",
             "description": "PHP-FPM RCE via fastcgi path_info",
             "severity": "CRITICAL", "cvss": 9.8},
            {"cve_id": "CVE-2024-4577", "software": "php",
             "affected_versions": "< 8.3.8",
             "description": "PHP CGI argument injection RCE on Windows",
             "severity": "CRITICAL", "cvss": 9.8},

            # ── WordPress ──
            {"cve_id": "CVE-2023-5360", "software": "wordpress",
             "affected_versions": "< 6.3.2",
             "description": "SQL injection in WordPress via plugin",
             "severity": "CRITICAL", "cvss": 9.8},
            {"cve_id": "CVE-2024-4400", "software": "wordpress",
             "affected_versions": "< 6.5.5",
             "description": "WordPress XSS via HTML tags in comments",
             "severity": "MEDIUM", "cvss": 6.1},

            # ── Spring / Java ──
            {"cve_id": "CVE-2022-22965", "software": "spring",
             "affected_versions": "< 5.3.18",
             "description": "Spring4Shell — RCE via data binding",
             "severity": "CRITICAL", "cvss": 9.8},
            {"cve_id": "CVE-2022-22963", "software": "spring",
             "affected_versions": "< 3.0.7",
             "description": "Spring Cloud Function SpEL injection RCE",
             "severity": "CRITICAL", "cvss": 9.8},

            # ── OpenSSH ──
            {"cve_id": "CVE-2024-3094", "software": "openssh",
             "affected_versions": "= 5.6.0",
             "description": "XZ backdoor — SSH remote code execution",
             "severity": "CRITICAL", "cvss": 10.0},

            # ── OpenSSL ──
            {"cve_id": "CVE-2023-38152", "software": "openssl",
             "affected_versions": "< 3.0.10",
             "description": "Buffer overflow in X.509 certificate verification",
             "severity": "HIGH", "cvss": 7.5},
            {"cve_id": "CVE-2022-3602", "software": "openssl",
             "affected_versions": "< 3.0.7",
             "description": "OpenSSL X.509 email address 4-byte buffer overflow",
             "severity": "HIGH", "cvss": 7.5},

            # ── MySQL / MariaDB ──
            {"cve_id": "CVE-2023-21971", "software": "mysql",
             "affected_versions": "< 8.0.33",
             "description": "MySQL Connector/J RCE via crafted SQL",
             "severity": "HIGH", "cvss": 8.3},

            # ── Tomcat ──
            {"cve_id": "CVE-2020-1938", "software": "tomcat",
             "affected_versions": "< 9.0.31",
             "description": "Ghostcat — AJP file read/inclusion vulnerability",
             "severity": "CRITICAL", "cvss": 9.8},
            {"cve_id": "CVE-2025-24813", "software": "tomcat",
             "affected_versions": "< 11.0.4",
             "description": "Apache Tomcat path equivalence RCE",
             "severity": "CRITICAL", "cvss": 9.0},

            # ── Docker ──
            {"cve_id": "CVE-2024-21626", "software": "docker",
             "affected_versions": "< 25.0.2",
             "description": "Docker runc container escape via /sys/fs/cgroup",
             "severity": "HIGH", "cvss": 8.6},

            # ── Node.js ──
            {"cve_id": "CVE-2024-27980", "software": "node.js",
             "affected_versions": "< 21.6.2",
             "description": "Node.js child_process.spawn argument injection",
             "severity": "HIGH", "cvss": 7.5},

            # ── Python ──
            {"cve_id": "CVE-2023-36632", "software": "python",
             "affected_versions": "< 3.12.0",
             "description": "Python mailcap module privilege escalation",
             "severity": "HIGH", "cvss": 7.8},
        ]
