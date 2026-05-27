"""
PHANTOM — Rate Limiting Detection Module

Detection:
1. Send 20+ rapid requests to login/auth pages
2. Check if all return 200 (no rate limit) vs 429/403 after some attempts
3. Uses discovered login paths from recon
"""
from __future__ import annotations

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class RateLimitCheck:
    """Rate limiting absence detection — tests auth endpoints for brute-force protection."""

    # Keywords that indicate an auth/login endpoint
    AUTH_KEYWORDS = ["login", "admin", "auth", "signin", "sign-in",
                     "log-in", "wp-login", "administrator", "panel",
                     "dashboard", "user", "account", "api/auth"]

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    def run(self):
        """Test discovered auth endpoints for rate limiting."""
        print("[*] Starting Rate Limit checks...")
        findings = 0

        auth_urls = self._find_auth_urls()
        if not auth_urls:
            print("  [!] No auth/login URLs found to test")
            return

        for url in auth_urls:
            try:
                if self._test_rate_limit(url):
                    findings += 1
            except Exception as e:
                print(f"  [!] Rate limit test failed for {url}: {e}")
                continue

        print(f"  [+] Rate limit checks complete — {findings} finding(s)")

    # ── Find auth endpoints ─────────────────────────────────────────

    def _find_auth_urls(self) -> list[str]:
        """Find login/auth endpoints from discovered directories."""
        auth_urls = []
        seen = set()

        sources = list(set(
            self.target.directories + self.target.js_endpoints
        ))

        for url in sources:
            lower = url.lower()
            for keyword in self.AUTH_KEYWORDS:
                if keyword in lower:
                    base = url.split("?")[0]
                    if base not in seen:
                        seen.add(base)
                        auth_urls.append(base)
                    break

        # If no auth URLs found, use the first few directories
        if not auth_urls and self.target.directories:
            for d in self.target.directories[:3]:
                base = d.split("?")[0]
                if base not in seen:
                    seen.add(base)
                    auth_urls.append(base)

        return auth_urls

    # ── Rate limit testing ──────────────────────────────────────────

    def _test_rate_limit(self, url: str) -> bool:
        """Send multiple rapid requests and check for rate limiting."""
        total_requests = 25
        responses = []
        status_counts = {}

        print(f"  [*] Sending {total_requests} rapid requests to {url}...")

        for i in range(total_requests):
            try:
                resp = request(url, timeout=5)
                if resp:
                    responses.append(resp.status)
                    status_counts[resp.status] = status_counts.get(resp.status, 0) + 1
            except Exception:
                responses.append(0)
                status_counts[0] = status_counts.get(0, 0) + 1

        # Check if any were rate-limited
        rate_limited = any(s == 429 for s in responses)
        blocked = any(s in (403, 503) for s in responses)

        if rate_limited:
            print(f"  [+] Rate limiting ACTIVE @ {url} (HTTP 429 detected)")
            return False

        if blocked:
            print(f"  [*] Possible rate limiting (HTTP 403/503) @ {url}")
            return False

        # If all requests succeeded without any 429, rate limiting is absent
        success_count = sum(1 for s in responses if s == 200)
        if success_count >= total_requests * 0.8:
            status_summary = ", ".join(
                f"{code}: {count}"
                for code, count in sorted(status_counts.items())
            )

            self.engine.findings.add(Finding(
                name="Missing Rate Limiting",
                severity="MEDIUM",
                url=url,
                param="",
                payload=f"{total_requests} rapid requests",
                evidence=(
                    f"No rate limiting detected — "
                    f"{total_requests} requests, 0 blocked (429). "
                    f"Statuses: {status_summary}"
                ),
                phase="vuln",
            ))
            print(f"  [+] No rate limiting @ {url} ({success_count}/{total_requests} returned 200)")
            return True

        print(f"  [*] Inconclusive @ {url} ({success_count}/{total_requests} OK)")
        return False
