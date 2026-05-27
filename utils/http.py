"""
PHANTOM — HTTP Client Wrapper

Thin wrapper around `requests` with:
- User-agent rotation
- Proxy support (HTTP/HTTPS/SOCKS5)
- Rate limiting
- Retry with backoff
- Response analysis helpers
"""
from __future__ import annotations
import random
import time
import logging
from typing import Optional

import requests

logger = logging.getLogger("phantom.http")


# Realistic user agents for rotation
_USER_AGENTS = [
    # Chrome 120 on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox 121 on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Chrome 120 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Safari 17 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Chrome 120 on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Edge 120 on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# Common ports for web services
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}


class HttpClient:
    """HTTP client with built-in rotation, proxy, and rate limiting."""

    def __init__(self, config=None) -> None:
        self.config = config
        self.session = requests.Session()
        self._last_request: float = 0.0
        self._min_delay: float = 0.1  # seconds between requests
        
        # Extract proxy config
        self.proxies: dict[str, str] = {}
        if config and hasattr(config, 'proxy'):
            if config.proxy.http:
                self.proxies["http"] = config.proxy.http
            if config.proxy.https:
                self.proxies["https"] = config.proxy.https
        
        # Rate limit from config
        if config and hasattr(config, 'rate_limit'):
            self._min_delay = 1.0 / config.rate_limit.max_requests_per_second
        
        # Set default headers
        self._rotate_user_agent()

    def _rotate_user_agent(self) -> None:
        """Set a random user agent on the session."""
        self.session.headers.update({
            "User-Agent": random.choice(_USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

    def _rate_limit_wait(self) -> None:
        """Enforce minimum delay between requests."""
        elapsed = time.time() - self._last_request
        if elapsed < self._min_delay:
            time.sleep(self._min_delay - elapsed)

    def get(self, url: str, **kwargs) -> requests.Response:
        """Send GET request with rate limiting and proxy.
        
        Args:
            url: Target URL.
            **kwargs: Passed to requests.Session.get().
        
        Returns:
            Response object.
        """
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Send POST request with rate limiting and proxy.
        
        Args:
            url: Target URL.
            **kwargs: Passed to requests.Session.post().
        
        Returns:
            Response object.
        """
        return self.request("POST", url, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Send HTTP request with rate limiting and proxy.
        
        Args:
            method: HTTP method (GET, POST, PUT, etc.).
            url: Target URL.
            **kwargs: Passed to requests.Session.request().
        
        Returns:
            Response object.
        """
        self._rate_limit_wait()
        
        if "proxies" not in kwargs and self.proxies:
            kwargs["proxies"] = self.proxies
        
        if "timeout" not in kwargs:
            kwargs["timeout"] = 10
        
        # Rotate UA every 10 requests
        if random.randint(1, 10) == 1:
            self._rotate_user_agent()
        
        try:
            resp = self.session.request(method, url, **kwargs)
            self._last_request = time.time()
            return resp
        except requests.exceptions.ConnectionError as e:
            logger.debug("Connection error: %s -> %s", url, e)
            raise
        except requests.exceptions.Timeout as e:
            logger.debug("Timeout: %s -> %s", url, e)
            raise
        except requests.exceptions.RequestException as e:
            logger.debug("Request failed: %s -> %s", url, e)
            raise

    def close(self) -> None:
        """Close the underlying session."""
        self.session.close()


# ── Response Analysis Helpers ──────────────────────────────────

def extract_headers_info(response: requests.Response) -> dict:
    """Extract security-relevant headers from response.
    
    Args:
        response: HTTP response object.
    
    Returns:
        Dict of header analysis results.
    """
    headers = response.headers
    info = {
        "server": headers.get("Server"),
        "powered_by": headers.get("X-Powered-By"),
        "content_type": headers.get("Content-Type"),
        "cors_origin": headers.get("Access-Control-Allow-Origin"),
        "cors_methods": headers.get("Access-Control-Allow-Methods"),
        "security_headers": {
            "strict_transport_security": headers.get("Strict-Traffic-Security"),
            "x_frame_options": headers.get("X-Frame-Options"),
            "x_content_type_options": headers.get("X-Content-Type-Options"),
            "x_xss_protection": headers.get("X-XSS-Protection"),
            "content_security_policy": headers.get("Content-Security-Policy"),
            "referrer_policy": headers.get("Referrer-Policy"),
            "permissions_policy": headers.get("Permissions-Policy"),
        },
        "set_cookie": headers.get("Set-Cookie"),
        "www_authenticate": headers.get("WWW-Authenticate"),
    }
    return info


def is_web_port(port: int) -> bool:
    """Check if a port commonly serves HTTP/HTTPS.
    
    Args:
        port: Port number.
    
    Returns:
        True if port commonly serves web traffic.
    """
    return port in WEB_PORTS


def build_url(domain: str, port: int, use_ssl: bool = False,
              path: str = "/") -> str:
    """Build HTTP URL from components.
    
    Args:
        domain: Domain or IP.
        port: Port number.
        use_ssl: True for https://.
        path: URL path.
    
    Returns:
        Full URL string.
    """
    protocol = "https" if use_ssl or port == 443 else "http"
    return f"{protocol}://{domain}:{port}{path}"
