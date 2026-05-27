"""
PHANTOM — Open Redirect Detection Module

Detection:
1. Inject external URL into redirect parameters
2. Check for 3xx redirect to injected URL in Location header
3. Parameters: url, next, redirect, redir, dest, destination, return, continue, to
4. Payloads: //evil.com, https://evil.com, //evil.com@legit, ///evil.com
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class RedirectCheck:
    """Open redirect vulnerability detection."""

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    def run(self):
        """Run open redirect checks against discovered URLs."""
        print("[*] Starting Open Redirect checks...")
        findings = 0

        redirect_params = ["url", "next", "redirect", "redir", "dest",
                           "destination", "return", "continue", "to",
                           "goto", "target", "redirect_uri", "redirect_url",
                           "out", "domain", "link", "ref"]

        urls = self._collect_urls(redirect_params)
        if not urls:
            print("  [!] No suitable URLs found for redirect testing")
            return

        base_domain = self._extract_base_domain()

        for url, param in urls:
            try:
                if self._test_redirect(url, param, base_domain):
                    findings += 1
            except Exception as e:
                print(f"  [!] Redirect test failed for {url}: {e}")
                continue

        print(f"  [+] Open Redirect checks complete — {findings} finding(s)")

    # ── URL collection ──────────────────────────────────────────────

    def _collect_urls(self, target_params: list[str]) -> list[tuple[str, str]]:
        """Find URLs with redirect-prone parameters."""
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

    def _extract_base_domain(self) -> str:
        """Extract base domain from target for comparison."""
        domain = self.target.domain
        if domain.startswith("http://") or domain.startswith("https://"):
            return urlparse(domain).netloc
        return domain

    # ── Redirect testing ────────────────────────────────────────────

    def _test_redirect(self, url: str, param: str, base_domain: str) -> bool:
        """Inject external URLs and check Location header."""
        payloads = [
            "//evil.com",
            "https://evil.com",
            "http://evil.com",
            "//evil.com%2f@",
            "//example.com@evil.com",
            "///evil.com",
            "https://evil.com:443",
            "/\\evil.com",
            "https://evil.com%2f@legit.com",
        ]

        for payload in payloads:
            test_url = self._inject(url, param, payload)
            try:
                resp = request(test_url, timeout=10)
                if not resp:
                    continue

                # Check Location header
                location = ""
                for hdr_key in ["location", "Location", "location"]:
                    location = resp.headers.get(hdr_key, "")
                    if location:
                        break

                if not location:
                    continue

                # Check if redirected to our malicious URL
                if "evil.com" in location and base_domain not in location:
                    self.engine.findings.add(Finding(
                        name="Open Redirect",
                        severity="MEDIUM",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=f"Location header: {location}",
                        phase="vuln",
                    ))
                    print(f"  [+] Open Redirect @ {url} ?{param} -> {location}")
                    return True

                # Also check for 3xx status codes
                if resp.status in (301, 302, 303, 307, 308):
                    loc_lower = location.lower()
                    if "evil.com" in loc_lower:
                        self.engine.findings.add(Finding(
                            name="Open Redirect",
                            severity="MEDIUM",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence=f"HTTP {resp.status} -> {location}",
                            phase="vuln",
                        ))
                        print(f"  [+] Open Redirect ({resp.status}) @ {url}")
                        return True

            except Exception:
                continue

        return False

    # ── Helpers ─────────────────────────────────────────────────────

    def _inject(self, url: str, param: str, payload: str) -> str:
        """Replace parameter value with redirect URL payload."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_qs = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_qs))
