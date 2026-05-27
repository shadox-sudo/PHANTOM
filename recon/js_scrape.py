"""
PHANTOM — JavaScript Scraper Module
Extracts <script> URLs from pages, downloads JS files, hunts for endpoints & secrets.
"""
import re
from urllib.parse import urljoin

from utils.http_client import request


class JSScraper:
    """JavaScript scraping for API endpoints, API keys, and secrets."""

    name = "js_scrape"
    description = "JavaScript scraping for endpoints and secrets"

    # URL/endpoint patterns to find in JS
    ENDPOINT_PATTERNS = [
        r'["\'`](/api/[^"\'`\s]*)["\'`]',
        r'["\'`](/v[1-9]/[^"\'`\s]{3,})["\'`]',
        r'["\'`](/rest/[^"\'`\s]{3,})["\'`]',
        r'["\'`](/graphql)["\'`]',
        r'["\'`](/rpc/[^"\'`\s]{3,})["\'`]',
        r'["\'`](/ws/|[^"\'`]*/ws[^"\'`]*)["\'`]',
        r'["\'`](https?://[^"\'`\s]{10,200})["\'`]',
        r'["\'`](/socket\.io/)["\'`]',
        r'["\'`](/sockjs/)["\'`]',
        r'["\'`](/signalr/)["\'`]',
        r'["\'`](wss?://[^"\'`\s]+)["\'`]',
    ]

    # Secret patterns to find in JS
    SECRET_PATTERNS = [
        # High-value secrets
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key", 95),
        (r'(?i)aws[_-]?(secret|access)[_-]?key\s*[:=]\s*["\'][A-Za-z0-9/+=]{20,}["\']', "AWS Secret Key", 95),
        (r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{10,}', "Stripe API Key", 95),
        (r'gh[pousr]_[A-Za-z0-9_]{10,}', "GitHub Token", 95),
        (r'xox[baprs]-[0-9a-zA-Z\-]{10,}', "Slack Token", 95),
        (r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT Token", 90),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key", 100),
        (r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}', "MongoDB URI", 95),
        (r'postgresql?://[^\s"\'<>]{10,}', "PostgreSQL URI", 95),
        (r'mysql://[^\s"\'<>]{10,}', "MySQL URI", 95),
        (r'redis://[^\s"\'<>]{10,}', "Redis URI", 95),
        (r'[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com', "Google OAuth ID", 90),

        # Firebase URLs
        (r'https://[a-zA-Z0-9_-]+\.firebaseio\.com', "Firebase URL", 85),
        (r'https://[a-zA-Z0-9_-]+\.firebasedatabase\.app', "Firebase DB URL", 85),

        # API keys / tokens
        (r'(?i)api[_-]?key\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,64}["\']', "API Key", 75),
        (r'(?i)secret\s*[:=]\s*["\'][A-Za-z0-9_\-/+=]{16,64}["\']', "Secret Token", 70),
        (r'(?i)auth_token\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "Auth Token", 70),
        (r'(?i)bearer\s+[A-Za-z0-9_\-]{20,}', "Bearer Token", 80),

        # Password / credential patterns
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{6,}["\']', "Password", 65),
        (r'(?i)(db_?password|db_?secret)\s*[:=]\s*["\'][^"\']+["\']', "DB Password", 75),

        # Telegram bot tokens
        (r'[1-9]\d{8,9}:AA[a-zA-Z0-9_\-]{32,40}', "Telegram Bot Token", 95),

        # SendGrid / Mailgun
        (r'SG\.[A-Za-z0-9_\-]{20,}', "SendGrid API Key", 90),
        (r'key-[A-Za-z0-9]{32}', "Mailgun API Key", 85),

        # Generic hex tokens
        (r'(?i)(?:token|secret)\s*[:=]\s*["\'][a-fA-F0-9]{32,64}["\']', "Hex Token/Secret", 60),
    ]

    def __init__(self, engine):
        self.engine = engine
        self.target = engine.target
        self.config = engine.config

    def run(self):
        domain = self.target.domain
        if not domain:
            print("  [!] JSScraper: no domain set")
            return

        # Determine URLs to fetch
        urls = self._get_target_urls()
        if not urls:
            print("  [!] JSScraper: no target URLs")
            return

        print(f"[*] JS scraping on {domain}")

        all_js_urls = set()
        endpoints = []
        secrets = []

        # Phase 1: Fetch pages and extract JS URLs
        for url in urls:
            print(f"  [*] Fetching {url}")
            js_urls = self._extract_js_urls(url)
            all_js_urls.update(js_urls)
            if js_urls:
                print(f"  [+] Found {len(js_urls)} JS files on {url}")

        if not all_js_urls:
            print("  [!] No JS files found")
            return

        # Phase 2: Download and scan each JS file
        print(f"  [*] Scanning {len(all_js_urls)} JS files...")
        for js_url in all_js_urls:
            eps, secs = self._scan_js_file(js_url)
            endpoints.extend(eps)
            secrets.extend(secs)

        # Deduplicate endpoints
        unique_endpoints = list(set(endpoints))
        self.target.js_endpoints = unique_endpoints

        self.target.add_timeline("recon", "js_scrape",
                                 f"{len(unique_endpoints)} endpoints, "
                                 f"{len(secrets)} secrets")
        print(f"  [*] JS scraping done: {len(unique_endpoints)} endpoints, "
              f"{len(secrets)} potential secrets")

        # Print findings
        if unique_endpoints:
            print("  [+] Found endpoints:")
            for ep in sorted(unique_endpoints)[:30]:
                print(f"      {ep}")
            if len(unique_endpoints) > 30:
                print(f"      ... and {len(unique_endpoints) - 30} more")

        if secrets:
            print("  [!] POTENTIAL SECRETS:")
            for s in secrets:
                print(f"      [{s['type']}] {s['match'][:80]}")

    def _get_target_urls(self) -> list:
        """Build list of URLs to fetch for JS extraction."""
        urls = []
        domain = self.target.domain

        if self.target.ports:
            for p in self.target.ports:
                if p.state == "open" and p.port in (80, 443, 8080, 8443):
                    scheme = "https" if p.port in (443, 8443) else "http"
                    ip = self.target.ip or domain
                    if p.port in (80, 443):
                        urls.append(f"{scheme}://{ip}/")
                    else:
                        urls.append(f"{scheme}://{ip}:{p.port}/")

        if not urls:
            urls = [f"https://{domain}/", f"http://{domain}/"]

        return urls

    def _extract_js_urls(self, page_url: str) -> set:
        """Fetch a page and extract all <script src='...'> URLs."""
        js_urls = set()
        try:
            resp = request(
                page_url, method="GET",
                timeout=self.config.timeout,
                headers={"User-Agent": self.config.user_agent},
            )
            if not resp.status:
                return js_urls

            html = resp.body or ""

            # Extract script src attributes
            for m in re.finditer(
                r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
                html, re.I
            ):
                src = m.group(1)
                # Resolve relative URLs
                absolute = urljoin(page_url, src)
                if absolute not in js_urls:
                    js_urls.add(absolute)

            # Also check for import() / require() patterns
            for m in re.finditer(
                r'(?:import|require)\s*\(?\s*["\']([^"\']+\.js[^"\']*)["\']',
                html
            ):
                src = m.group(1)
                absolute = urljoin(page_url, src)
                if absolute not in js_urls:
                    js_urls.add(absolute)

        except Exception:
            pass

        return js_urls

    def _scan_js_file(self, js_url: str) -> tuple:
        """Download a JS file and scan for endpoints and secrets."""
        endpoints = []
        secrets = []
        try:
            resp = request(
                js_url, method="GET",
                timeout=self.config.timeout,
                headers={"User-Agent": self.config.user_agent},
            )
            if not resp.status or not resp.body:
                return endpoints, secrets

            body = resp.body
            if len(body) > 2 * 1024 * 1024:  # Skip files > 2MB
                return endpoints, secrets

            # Scan for endpoints
            for pattern in self.ENDPOINT_PATTERNS:
                for m in re.finditer(pattern, body):
                    ep = m.group(1)
                    if ep and len(ep) > 2:
                        endpoints.append(ep)

            # Scan for secrets
            for pattern, name, confidence in self.SECRET_PATTERNS:
                for m in re.finditer(pattern, body):
                    match_text = m.group(0)
                    secrets.append({
                        "url": js_url,
                        "type": name,
                        "match": match_text[:120],
                        "confidence": confidence,
                    })
                    print(f"    [!] [{name}] found in {js_url.split('/')[-1]}")
                    print(f"        {match_text[:100]}")

        except Exception:
            pass

        return endpoints, secrets
