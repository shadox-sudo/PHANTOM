"""
PHANTOM — Technology Detection Module

Identifies web technologies via:
- Response headers (Server, X-Powered-By, etc.)
- Cookie patterns
- HTML content signatures
- Common path checks
"""
from __future__ import annotations
import logging
import re
from typing import Optional

import requests

from .base import ReconModule
from utils.http import HttpClient, build_url, is_web_port

logger = logging.getLogger("phantom.recon.tech")


class TechDetect(ReconModule):
    """Technology stack fingerprinting via HTTP analysis."""

    name = "tech_detect"
    description = "Web technology detection via HTTP headers + content analysis"
    depends_on = ["port_scanner"]

    def run(self, target, config=None):
        """Populates target.tech_stack and target.endpoints.
        
        For each open web port, sends HTTP requests and analyzes responses.
        Detects: web servers, frameworks, CMS, JS libraries, analytics.
        """
        http = HttpClient(config)
        
        # Collect web ports
        web_ports = [p for p in target.open_ports if is_web_port(p.port)]
        if not web_ports:
            logger.info("No web ports found, trying default ports")
            # Try common web ports anyway
            for ip in target.ips:
                for port in [80, 443, 8080, 8443]:
                    web_ports.append(type('obj', (object,), {'port': port, 'service': '?'}))
        
        tech: dict[str, str] = {}
        endpoints: list[str] = []
        
        for port_info in web_ports:
            port = port_info.port
            for ip in target.ips[:1]:  # Check first IP for tech
                for use_ssl in ([False, True] if port != 443 else [True]):
                    url = build_url(ip, port, use_ssl)
                    try:
                        resp = http.get(url, timeout=5)
                        page_tech = self._fingerprint(resp)
                        tech.update(page_tech)
                        
                        # Add base endpoint
                        endpoints.append(url)
                        
                        # Check common paths
                        common = ["/robots.txt", "/sitemap.xml", "/favicon.ico",
                                  "/admin", "/login", "/api", "/.well-known/"]
                        for path in common:
                            try:
                                r2 = http.get(f"{url}{path}", timeout=3)
                                if r2.status_code != 404:
                                    endpoints.append(f"{url}{path}")
                            except requests.RequestException:
                                pass
                        
                        break  # Found a working port
                    except requests.RequestException:
                        continue
        
        target.tech_stack = tech
        target.endpoints = list(set(endpoints))
        
        logger.info("Tech detect: %d technologies, %d endpoints", len(tech), len(endpoints))
        return target

    def _fingerprint(self, response) -> dict[str, str]:
        """Extract tech stack information from HTTP response.
        
        Returns:
            Dict mapping technology name to version (or 'detected').
        """
        tech: dict[str, str] = {}
        headers = response.headers
        body = response.text
        
        # Server header
        server = headers.get("Server", "")
        if server:
            tech["server"] = server
        
        # X-Powered-By
        powered = headers.get("X-Powered-By", "")
        if powered:
            tech["powered_by"] = powered
        
        # Cookies
        set_cookie = headers.get("Set-Cookie", "")
        if "PHPSESSID" in set_cookie:
            tech["php"] = "detected"
        if "JSESSIONID" in set_cookie:
            tech["java"] = "detected"
        if "ASP.NET" in set_cookie or "ASPSESSIONID" in set_cookie:
            tech["asp.net"] = "detected"
        if "laravel_session" in set_cookie:
            tech["laravel"] = "detected"
        
        # HTML meta / content
        if 'wp-content' in body or 'wp-includes' in body:
            tech["wordpress"] = "detected"
        if 'Drupal' in body or 'drupal' in body:
            tech["drupal"] = "detected"
        if 'Joomla' in body or 'joomla' in body:
            tech["joomla"] = "detected"
        if 'csrf-token' in body and 'laravel' in body.lower():
            tech["laravel"] = "detected"
        
        # Generator tag
        gen_match = re.search(r'<meta\s+name="generator"[^>]+content="([^"]+)"', body, re.I)
        if gen_match:
            tech["generator"] = gen_match.group(1)
        
        # Cloudflare
        if "cf-ray" in headers or "CF-RAY" in headers:
            tech["cloudflare"] = "detected"
        
        # Nginx
        if "nginx" in server.lower():
            # Extract version from Server header
            v_match = re.search(r'nginx/([\d.]+)', server)
            if v_match:
                tech["nginx"] = v_match.group(1)
        
        # Apache
        if "apache" in server.lower():
            v_match = re.search(r'Apache/([\d.]+)', server, re.I)
            if v_match:
                tech["apache"] = v_match.group(1)
        
        return tech

    def validate_target(self, target) -> bool:
        return target is not None and (bool(target.ips) or bool(target.domain))
