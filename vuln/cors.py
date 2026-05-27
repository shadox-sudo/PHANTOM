"""
PHANTOM — CORS Misconfiguration Detection Module

Detection:
1. Send request with Origin: https://evil.com
2. Check if Access-Control-Allow-Origin reflects our origin
3. Check if Access-Control-Allow-Credentials: true
4. Report if both ACAO reflects origin AND credentials true (vulnerable)
5. Also check with Origin: null
"""
from __future__ import annotations

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class CORSCheck:
    """CORS misconfiguration detection — origin reflection and wildcard."""

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    def run(self):
        """Run CORS tests against discovered endpoints."""
        print("[*] Starting CORS misconfiguration checks...")
        findings = 0

        urls = self._collect_base_urls()
        if not urls:
            print("  [!] No URLs found for CORS testing")
            return

        for url in urls:
            try:
                if self._test_origin_reflection(url):
                    findings += 1
                    continue
                if self._test_wildcard_origin(url):
                    findings += 1
            except Exception as e:
                print(f"  [!] CORS test failed for {url}: {e}")
                continue

        print(f"  [+] CORS checks complete — {findings} finding(s)")

    # ── URL collection ──────────────────────────────────────────────

    def _collect_base_urls(self) -> list[str]:
        """Collect base URLs (no query params stripped) for CORS testing."""
        urls = []
        seen = set()

        for d in self.target.directories:
            base = d.split("?")[0]
            if base not in seen:
                seen.add(base)
                urls.append(base)

        for js in self.target.js_endpoints:
            base = js.split("?")[0]
            if base not in seen:
                seen.add(base)
                urls.append(base)

        # If nothing found, use the domain itself
        if not urls and self.target.domain:
            urls.append(
                f"https://{self.target.domain}"
                if not self.target.domain.startswith("http")
                else self.target.domain
            )

        return urls

    # ── Origin reflection test ──────────────────────────────────────

    def _test_origin_reflection(self, url: str) -> bool:
        """Check if server reflects arbitrary Origin in ACAO header."""
        test_origins = [
            "https://evil.com",
            "null",
            "https://attacker.com",
            "https://evil.com.evil.com",
        ]

        for origin in test_origins:
            try:
                resp = request(
                    url,
                    headers={"Origin": origin},
                    timeout=10,
                )
                if not resp:
                    continue

                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")
                acam = resp.headers.get("access-control-allow-methods", "")
                acah = resp.headers.get("access-control-allow-headers", "")

                if not acao:
                    continue

                # Vulnerable if ACAO reflects our origin
                if origin in acao and origin != "*":
                    severity = "HIGH" if acac == "true" else "MEDIUM"
                    evidence = f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}"
                    if acam:
                        evidence += f", ACAM: {acam}"
                    if acah:
                        evidence += f", ACAH: {acah}"

                    self.engine.findings.add(Finding(
                        name="CORS Misconfiguration (Origin Reflection)",
                        severity=severity,
                        url=url,
                        param="Origin header",
                        payload=origin,
                        evidence=evidence,
                        phase="vuln",
                    ))
                    print(f"  [+] CORS origin reflection @ {url} (Origin: {origin})")
                    return True

            except Exception:
                continue

        return False

    # ── Wildcard origin test ────────────────────────────────────────

    def _test_wildcard_origin(self, url: str) -> bool:
        """Check for wildcard ACAO with credentials (most dangerous)."""
        try:
            resp = request(
                url,
                headers={"Origin": "https://example.com"},
                timeout=10,
            )
            if not resp:
                return False

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            acam = resp.headers.get("access-control-allow-methods", "")
            acah = resp.headers.get("access-control-allow-headers", "")

            # CORS spec: wildcard + credentials = TRUE is invalid
            # but some servers still do it
            if acao == "*" and acac == "true":
                evidence = "ACAO: *, ACAC: true — credentials accessible to any origin"
                if acam:
                    evidence += f", ACAM: {acam}"
                if acah:
                    evidence += f", ACAH: {acah}"

                self.engine.findings.add(Finding(
                    name="CORS Misconfiguration (Wildcard + Credentials)",
                    severity="HIGH",
                    url=url,
                    param="Origin header",
                    payload="*",
                    evidence=evidence,
                    phase="vuln",
                ))
                print(f"  [+] CORS wildcard+credentials @ {url}")
                return True

        except Exception:
            pass

        return False
