"""
PHANTOM — JavaScript Scraper Module

Scrapes JS files from discovered pages and extracts:
- API endpoints (/api/v1/, /graphql)
- Secrets (API keys, tokens, AWS keys)
- Internal URLs and paths
- Firebase URLs
- Hardcoded credentials
"""
from __future__ import annotations
import logging
import re
import urllib.parse
from typing import Optional

import requests

from .base import ReconModule
from core.target import JsSecret
from utils.http import HttpClient

logger = logging.getLogger("phantom.recon.jsscraper")


class JsScraper(ReconModule):
    """JavaScript scraping for endpoints and secrets."""

    name = "js_scraper"
    description = "JavaScript scraping for endpoints, API keys, and secrets"
    depends_on = ["tech_detect"]

    def run(self, target, config=None):
        """Populates target.js_endpoints and target.js_secrets.
        
        1. Extracts <script src="..."> URLs from discovered pages
        2. Downloads each JS file
        3. Regex scans for endpoints, secrets, and sensitive patterns
        """
        http = HttpClient(config)
        
        if not target.endpoints:
            logger.warning("No endpoints to scrape JS from")
            return target
        
        js_urls: set[str] = set()
        secrets: list[JsSecret] = []
        endpoints: list[str] = []
        
        # Phase 1: Find JS URLs from pages
        for url in target.endpoints:
            found = self._extract_js_urls(http, url)
            js_urls.update(found)
        
        logger.info("Found %d JS files to analyze", len(js_urls))
        
        # Phase 2: Download and scan each JS file
        for js_url in js_urls:
            content = self._download_js(http, js_url)
            if not content:
                continue
            
            js_eps, js_secs = self._scan_js(content, js_url)
            endpoints.extend(js_eps)
            secrets.extend(js_secs)
        
        target.js_endpoints = list(set(endpoints))
        target.js_secrets = secrets
        
        logger.info("JS scraper: %d endpoints, %d secrets", len(endpoints), len(secrets))
        return target

    def _extract_js_urls(self, http, url: str) -> set[str]:
        """Extract script source URLs from HTML page."""
        js_urls: set[str] = set()
        try:
            resp = http.get(url, timeout=10)
            html = resp.text
            
            # Match <script src="...">
            for match in re.finditer(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', html, re.I):
                src = match.group(1)
                absolute = urllib.parse.urljoin(url, src)
                js_urls.add(absolute)
            
        except requests.RequestException:
            pass
        
        return js_urls

    def _download_js(self, http, js_url: str) -> Optional[str]:
        """Download JavaScript file content."""
        try:
            resp = http.get(js_url, timeout=10)
            if resp.status_code == 200 and len(resp.content) < 5 * 1024 * 1024:
                return resp.text
        except requests.RequestException:
            pass
        return None

    def _scan_js(self, content: str, url: str) -> tuple[list[str], list[JsSecret]]:
        """Scan JS content for endpoints and secrets.
        
        Returns:
            Tuple of (endpoints_list, secrets_list).
        """
        endpoints: list[str] = []
        secrets_list: list[JsSecret] = []
        
        # ── Endpoint detection ──
        # Match: /api/, /v1/, /graphql, /rest, /rpc
        api_patterns = [
            r'["\'`](/api/[^"\'`\s]*)["\'`]',
            r'["\'`](/v\d+/[^"\'`\s]*)["\'`]',
            r'["\'`](/rest/[^"\'`\s]*)["\'`]',
            r'["\'`](/graphql)[^"\'`\s]*["\'`]',
            r'["\'`](/rpc/[^"\'`\s]*)["\'`]',
            r'["\'`](/[a-zA-Z]+/[a-zA-Z]+/[a-zA-Z]+)[^"\'`\s]*["\'`]',  # /x/y/z
        ]
        
        for pattern in api_patterns:
            for match in re.finditer(pattern, content, re.I):
                endpoint = match.group(1)
                # Filter out noise (short paths, extensions)
                if len(endpoint) > 3 and not endpoint.endswith(('.js', '.css', '.png', '.jpg')):
                    endpoints.append(endpoint)
        
        # ── Secret detection ──
        secret_patterns: list[tuple[str, str, float]] = [
            # AWS keys
            (r'AKIA[0-9A-Z]{16}', 'aws_key', 0.9),
            (r'(?i)aws[_\.]?(access|secret|key)\s*[:=]\s*["\'][A-Za-z0-9/+=]{20,}["\']', 'aws_secret', 0.8),
            # API keys (generic hex patterns)
            (r'api[_-]?key\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,64}["\']', 'api_key', 0.7),
            (r'apikey\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,64}["\']', 'api_key', 0.7),
            # JWT tokens
            (r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', 'jwt', 0.8),
            # Firebase URLs
            (r'https://[a-zA-Z0-9_-]+\.firebaseio\.com', 'firebase', 0.7),
            # Slack tokens
            (r'xox[baprs]-[0-9a-zA-Z\-]{10,}', 'slack_token', 0.8),
            # Stripe keys
            (r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{10,}', 'stripe_key', 0.8),
            # GitHub tokens
            (r'gh[pousr]_[A-Za-z0-9_]{10,}', 'github_token', 0.8),
            # Generic password/token patterns
            (r'(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*["\'][^"\']{8,}["\']', 'credential', 0.5),
            # MongoDB connection strings
            (r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}', 'mongodb_uri', 0.9),
            # Private keys (inline)
            (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'private_key', 1.0),
            # Google OAuth
            (r'[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com', 'google_oauth', 0.9),
        ]
        
        for pattern, secret_type, confidence in secret_patterns:
            for match in re.finditer(pattern, content):
                value = match.group(0)
                # Get context (chars around the match)
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                context = content[start:end].replace('\n', ' ')
                
                secret = JsSecret(
                    url=url,
                    secret_type=secret_type,
                    value=value[:100],  # truncate long values
                    context=context,
                    confidence=confidence,
                )
                secrets_list.append(secret)
        
        return endpoints, secrets_list

    def validate_target(self, target) -> bool:
        return target is not None and len(target.endpoints) > 0
