"""
PHANTOM — Technology Detection Module
Identifies web servers, CMS, frameworks, libraries from HTTP responses.
"""
import re
from urllib.parse import urljoin

from core.target import TechInfo
from utils.http_client import request


class TechDetect:
    """Web technology detection via HTTP headers and HTML analysis."""

    name = "tech"
    description = "Web technology detection"

    # Cookie-to-tech mappings
    COOKIE_PATTERNS = {
        "PHPSESSID": ("PHP", "session cookie"),
        "laravel_session": ("Laravel", "session cookie"),
        "Laravel_session": ("Laravel", "session cookie"),
        "JSESSIONID": ("Java/J2EE", "session cookie"),
        "JSESSIONIDSSO": ("Java/J2EE", "SSO session"),
        "ASP.NET_SessionId": ("ASP.NET", "session cookie"),
        "ASPSESSIONID": ("ASP.NET", "session cookie (legacy)"),
        "CAKEPHP": ("CakePHP", "session cookie"),
        "symfony": ("Symfony", "session cookie"),
        "wordpress_logged_in": ("WordPress", "auth cookie"),
        "wp-settings": ("WordPress", "settings cookie"),
        "drupal": ("Drupal", "session cookie"),
        "SESS": ("Drupal", "session cookie prefix"),
        "SHOPPING_CART": ("Magento", "cart cookie"),
        "frontend": ("Magento", "frontend cookie"),
        "adminhtml": ("Magento", "admin cookie"),
        "ci_session": ("CodeIgniter", "session cookie"),
        "XSRF-TOKEN": ("Laravel/Spring", "CSRF token cookie"),
    }

    # Header-to-tech mappings
    HEADER_PATTERNS = {
        "server": [
            (r"nginx/([\d.]+)", "Nginx", "server header"),
            (r"Apache/([\d.]+)", "Apache", "server header"),
            (r"Microsoft-IIS/([\d.]+)", "IIS", "server header"),
            (r"CloudFront", "AWS CloudFront", "server header"),
            (r"openresty/([\d.]+)", "OpenResty", "server header"),
            (r"Caddy", "Caddy", "server header"),
            (r"lighttpd/([\d.]+)", "Lighttpd", "server header"),
            (r"GSE", "Google Search Appliance", "server header"),
        ],
        "x-powered-by": [
            (r"PHP/([\d.]+)", "PHP", "X-Powered-By"),
            (r"ASP\.NET", "ASP.NET", "X-Powered-By"),
            (r"Express", "Express.js", "X-Powered-By"),
            (r"Railo", "Railo", "X-Powered-By"),
            (r"Servlet", "Java Servlet", "X-Powered-By"),
        ],
        "x-generator": [
            (r"Drupal ([\d.]+)", "Drupal", "X-Generator"),
        ],
        "x-aspnet-version": [
            (r".+", "ASP.NET", "X-AspNet-Version"),
        ],
        "x-aspnetmvc-version": [
            (r".+", "ASP.NET MVC", "X-AspNetMvc-Version"),
        ],
    }

    def __init__(self, engine):
        self.engine = engine
        self.target = engine.target
        self.config = engine.config

    def run(self):
        domain = self.target.domain
        if not domain:
            print("  [!] TechDetect: no domain set")
            return

        # Determine URLs to check
        urls = []
        if self.target.ports:
            for p in self.target.ports:
                if p.state == "open" and p.port in (80, 443, 8080, 8443, 8000, 8888):
                    scheme = "https" if p.port in (443, 8443) else "http"
                    ip = self.target.ip or domain
                    urls.append(f"{scheme}://{ip}:{p.port}/")
        if not urls:
            urls = [f"https://{domain}/", f"http://{domain}/"]

        print(f"[*] Tech detection on {domain} ({len(urls)} URLs)")

        for url in urls:
            print(f"  [*] Checking {url}")
            try:
                resp = request(url, timeout=self.config.timeout,
                               headers={"User-Agent": self.config.user_agent})
                if resp.status:
                    self._analyze(resp, url)
                    break  # One successful response is enough
            except Exception:
                continue

        self.target.add_timeline("recon", "tech_detect",
                                 f"{len(self.target.tech_stack)} technologies")
        print(f"  [*] Tech detection done: {len(self.target.tech_stack)} technologies found")

    def _analyze(self, resp, url: str):
        """Analyze HTTP response for technology fingerprints."""
        headers = resp.headers or {}
        body = resp.body or ""

        # Server header
        server = headers.get("server", "")
        if server:
            self._add_tech("Web Server", server, 100)

        # Known header patterns
        self._check_headers(headers)

        # Cookie patterns
        set_cookie = headers.get("set-cookie", "")
        for pattern, (tech, context) in self.COOKIE_PATTERNS.items():
            if pattern.lower() in set_cookie.lower():
                self._add_tech(tech, context, 80)

        # HTML meta generator
        gen_match = re.search(
            r'<meta\s+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body, re.I
        )
        if gen_match:
            self._add_tech("CMS/Generator", gen_match.group(1), 90)

        # WordPress detection
        if any(x in body for x in ["wp-content", "wp-includes", "wp-json"]):
            self._add_tech("WordPress", "detected via content paths", 85)
        if re.search(r'/wp-json/', body, re.I):
            self._add_tech("WordPress REST API", "wp-json endpoint", 90)

        # Drupal detection
        if "drupal" in body.lower() and "drupal" in body.lower():
            if re.search(r'Drupal\.(settings|ajax|behavior)', body):
                self._add_tech("Drupal", "detected via JS", 80)

        # Joomla detection
        if re.search(r'/components/|/modules/|/templates/', body):
            if re.search(r'joomla', body, re.I):
                self._add_tech("Joomla", "detected via paths", 75)

        # JavaScript libraries
        self._detect_js_libs(body)

        # Cloudflare
        cf_ray = headers.get("cf-ray", "")
        if cf_ray:
            self._add_tech("Cloudflare", f"CF-Ray: {cf_ray[:20]}...", 95)

        # Analytics
        analytics_map = {
            "google-analytics.com": ("Google Analytics", "UA script"),
            "googletagmanager.com": ("Google Tag Manager", "GTM script"),
            "facebook.net": ("Facebook SDK", "FB pixel"),
            "fbq(": ("Facebook Pixel", "tracking code"),
        }
        for pattern, (tech, ctx) in analytics_map.items():
            if pattern in body:
                self._add_tech(tech, ctx, 80)

        # Security headers
        security_headers = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "x-xss-protection": "X-XSS-Protection",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }
        for hdr, name in security_headers.items():
            if hdr in headers:
                self._add_tech(name, "security header present", 70)

        # CDN detection
        via = headers.get("via", "")
        if "cloudfront" in via.lower():
            self._add_tech("AWS CloudFront CDN", via[:60], 90)
        if "cloudflare" in via.lower():
            self._add_tech("Cloudflare CDN", via[:60], 90)
        if "akamai" in via.lower():
            self._add_tech("Akamai CDN", via[:60], 90)
        if "fastly" in via.lower():
            self._add_tech("Fastly CDN", via[:60], 90)

    def _check_headers(self, headers: dict):
        """Check HTTP headers against known patterns."""
        for header_name, patterns in self.HEADER_PATTERNS.items():
            val = headers.get(header_name, "")
            if not val:
                # Try case variations
                for k, v in headers.items():
                    if k.lower() == header_name:
                        val = v
                        break
            if not val:
                continue
            for regex, tech, ctx in patterns:
                m = re.search(regex, val, re.I)
                if m:
                    ver = m.group(1) if m.lastindex else ""
                    label = f"{tech} {ver}" if ver else tech
                    self._add_tech(label, ctx, 90)

    def _detect_js_libs(self, body: str):
        """Detect JavaScript libraries from script sources or inline code."""
        libs = [
            (r'jquery[.-]?([\d.]+)?', "jQuery", "JS library"),
            (r'react(?:\.min)?\.js', "React", "JS framework"),
            (r'react-dom(?:\.min)?\.js', "React DOM", "JS framework"),
            (r'vue(?:\.min)?\.js', "Vue.js", "JS framework"),
            (r'angular(?:\.min)?\.js', "AngularJS", "JS framework"),
            (r'angular\.core', "Angular", "JS framework"),
            (r'@angular', "Angular", "JS framework (module)"),
            (r'backbone(?:\.min)?\.js', "Backbone.js", "JS library"),
            (r'ember(?:\.min)?\.js', "Ember.js", "JS framework"),
            (r'bootstrap(?:\.min)?\.js', "Bootstrap", "UI framework"),
            (r'moment(?:\.min)?\.js', "Moment.js", "JS library"),
            (r'underscore(?:\.min)?\.js', "Underscore.js", "JS library"),
            (r'lodash(?:\.min)?\.js', "Lodash", "JS library"),
            (r'gstatic\.com', "Google Hosted Libraries", "CDN"),
            (r'ajax\.googleapis\.com', "Google APIs CDN", "CDN"),
            (r'cdnjs\.cloudflare\.com', "Cloudflare CDN (cdnjs)", "CDN"),
            (r'unpkg\.com', "unpkg CDN", "CDN"),
            (r'jsdelivr\.net', "jsDelivr CDN", "CDN"),
            (r'd3(?:\.min)?\.js', "D3.js", "data viz library"),
            (r'chart(?:\.min)?\.js', "Chart.js", "charting library"),
            (r'socket\.io', "Socket.IO", "real-time library"),
            (r'axios(?:\.min)?\.js', "Axios", "HTTP client"),
            (r'three(?:\.min)?\.js', "Three.js", "3D library"),
            (r'wp-includes/js/', "WordPress Core JS", "WP scripts"),
        ]
        for regex, tech, ctx in libs:
            if re.search(regex, body, re.I):
                self._add_tech(tech, ctx, 75)

    def _add_tech(self, name: str, version: str, certainty: int):
        """Add a technology to the target's tech stack."""
        # Deduplicate
        for t in self.target.tech_stack:
            if t.name.lower() == name.lower():
                if certainty > t.certainty:
                    t.certainty = certainty
                    t.version = version
                return
        info = TechInfo(name=name, version=version, certainty=certainty)
        self.target.tech_stack.append(info)
        print(f"    [+] {name} ({version}) [{certainty}%]")
