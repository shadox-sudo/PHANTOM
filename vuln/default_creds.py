"""
PHANTOM — Default Credentials Testing Module

Detection:
1. Try common default credentials on discovered login pages
2. Pairs: admin:admin, admin:password, admin:123456, root:root, etc.
3. Only test if login pages were discovered in recon
4. Look for "login", "admin", "wp-login", "signin" in paths
"""
from __future__ import annotations

import base64
from urllib.parse import urlparse

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class DefaultCredsCheck:
    """Default credentials testing against discovered auth endpoints."""

    # Built-in database of common default credentials
    CREDENTIALS = {
        "generic": [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", "root"), ("root", "root"), ("root", "admin"),
            ("root", "toor"), ("test", "test"), ("user", "user"),
            ("guest", "guest"), ("demo", "demo"), ("admin", "12345"),
            ("admin", "pass"), ("admin", "1234"), ("admin", "qwerty"),
            ("admin", "changeme"), ("admin", "administrator"),
        ],
        "wordpress": [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("wp", "wp"), ("admin", "wordpress"),
        ],
        "tomcat": [
            ("admin", "admin"), ("tomcat", "tomcat"), ("admin", "tomcat"),
            ("role1", "role1"), ("role1", "tomcat"), ("both", "tomcat"),
        ],
        "phpmyadmin": [
            ("root", ""), ("root", "root"), ("admin", "admin"),
            ("pma", "pma"), ("phpmyadmin", "phpmyadmin"),
        ],
        "mysql": [
            ("root", ""), ("root", "root"), ("admin", "admin"),
        ],
        "postgres": [
            ("postgres", ""), ("postgres", "postgres"),
            ("admin", "admin"),
        ],
    }

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    def run(self):
        """Test default credentials against discovered login endpoints."""
        print("[*] Starting Default Credentials checks...")
        findings = 0

        login_urls = self._find_login_urls()
        if not login_urls:
            print("  [!] No login/auth pages found to test")
            return

        print(f"  [*] Found {len(login_urls)} login URL(s) to test")

        for url, service_type in login_urls:
            try:
                if self._test_creds(url, service_type):
                    findings += 1
            except Exception as e:
                print(f"  [!] Default creds test failed for {url}: {e}")
                continue

        print(f"  [+] Default credentials checks complete — {findings} finding(s)")

    # ── Find login URLs ─────────────────────────────────────────────

    def _find_login_urls(self) -> list[tuple[str, str]]:
        """Identify login/admin URLs and their likely service type."""
        results = []
        seen = set()

        sources = list(set(
            self.target.directories + self.target.js_endpoints
        ))

        for url in sources:
            lower = url.lower()
            service_type = self._detect_service(lower)

            keywords = ["login", "admin", "auth", "signin", "sign-in",
                        "log-in", "wp-login", "administrator", "panel",
                        "dashboard", "manager", "console", "cpanel"]
            for keyword in keywords:
                if keyword in lower:
                    base = url.split("?")[0]
                    if base not in seen:
                        seen.add(base)
                        results.append((base, service_type))
                    break

        return results

    def _detect_service(self, url: str) -> str:
        """Detect service type from URL patterns."""
        if "wp-" in url or "wordpress" in url:
            return "wordpress"
        if "tomcat" in url or "manager/html" in url:
            return "tomcat"
        if "phpmyadmin" in url or "pma" in url:
            return "phpmyadmin"
        if "mysql" in url or "phpmyadmin" in url:
            return "mysql"
        return "generic"

    # ── Credential testing ──────────────────────────────────────────

    def _test_creds(self, url: str, service_type: str) -> bool:
        """Try default credentials against an endpoint."""
        creds = self.CREDENTIALS.get(service_type, self.CREDENTIALS["generic"])
        # Also add generic creds
        all_creds = list(set(creds + self.CREDENTIALS["generic"]))
        found = False

        for username, password in all_creds:
            try:
                # Try HTTP Basic Auth
                auth_str = f"{username}:{password}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                resp = request(
                    url,
                    headers={"Authorization": f"Basic {auth_b64}"},
                    timeout=8,
                )

                if resp and resp.status == 200:
                    self.engine.findings.add(Finding(
                        name="Default Credentials",
                        severity="CRITICAL",
                        url=url,
                        param="Basic Auth",
                        payload=f"{username}:{password}",
                        evidence=f"HTTP {resp.status} with {username}:{password}",
                        phase="vuln",
                    ))
                    print(f"  [+] Default creds WORK @ {url} ({username}:{password})")
                    found = True
                    break

                # Try POST form-based login
                if resp and resp.status in (302, 301):
                    # Redirect after login = might have worked
                    # Check for session cookie in response
                    set_cookie = resp.headers.get("set-cookie", "")
                    if set_cookie:
                        self.engine.findings.add(Finding(
                            name="Default Credentials (Form-based)",
                            severity="CRITICAL",
                            url=url,
                            param="POST form",
                            payload=f"{username}:{password}",
                            evidence=f"HTTP {resp.status} with Set-Cookie: {set_cookie[:80]}",
                            phase="vuln",
                        ))
                        print(f"  [+] Default creds (form) @ {url} ({username}:{password})")
                        found = True
                        break

            except Exception:
                continue

        return found
