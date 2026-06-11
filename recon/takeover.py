"""PHANTOM — Subdomain takeover detection via CNAME + HTTP fingerprint."""

import socket
import dns.resolver
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from core.target import VulnFinding


class SubdomainTakeover:
    """Subdomain takeover detection via CNAME analysis + HTTP fingerprinting."""

    name = "takeover"
    description = "Subdomain takeover detection (CNAME + HTTP fingerprint)"

    # (cname_suffix, check_fn, service_name)
    FINGERPRINTS = [
        # AWS S3
        (".s3.amazonaws.com", "aws_s3", "AWS S3"),
        (".s3-website.", "aws_s3", "AWS S3 Website"),
        (".s3.us-east-1.amazonaws.com", "aws_s3", "AWS S3"),
        (".s3-eu-west-1.amazonaws.com", "aws_s3", "AWS S3 EU"),

        # AWS CloudFront
        (".cloudfront.net", "cloudfront", "AWS CloudFront"),

        # AWS Elastic Beanstalk
        (".elasticbeanstalk.com", "generic_404", "AWS Elastic Beanstalk"),

        # GitHub Pages
        (".github.io", "github_pages", "GitHub Pages"),

        # Heroku
        (".herokuapp.com", "heroku", "Heroku"),
        (".herokudns.com", "heroku", "Heroku DNS"),

        # Netlify
        (".netlify.app", "netlify", "Netlify"),
        (".netlify.com", "netlify", "Netlify"),

        # Vercel
        (".vercel.app", "vercel", "Vercel"),
        (".now.sh", "vercel", "Vercel (Now)"),

        # Shopify
        (".myshopify.com", "shopify", "Shopify"),

        # Azure Web Apps
        (".azurewebsites.net", "azure_webapp", "Azure Web App"),
        (".trafficmanager.net", "generic_404", "Azure Traffic Manager"),
        (".cloudapp.net", "generic_404", "Azure Cloud App"),
        (".azureedge.net", "generic_404", "Azure CDN"),

        # Firebase
        (".firebaseapp.com", "firebase", "Firebase"),

        # Fastly
        (".fastly.net", "fastly", "Fastly"),

        # Surge
        (".surge.sh", "surge", "Surge.sh"),

        # Bitbucket
        (".bitbucket.io", "bitbucket", "Bitbucket Pages"),

        # Fly.io
        (".fly.dev", "generic_404", "Fly.io"),

        # Pantheon
        (".pantheonsite.io", "pantheon", "Pantheon"),
        (".pantheon.io", "pantheon", "Pantheon"),

        # Readme.io
        (".readme.io", "readme", "Readme.io"),
        (".readme.com", "readme", "Readme.com"),

        # Helpjuice
        (".helpjuice.com", "helpjuice", "Helpjuice"),

        # Zendesk
        (".zendesk.com", "zendesk", "Zendesk"),

        # Strikingly
        (".strikingly.com", "strikingly", "Strikingly"),
        (".strikinglydns.com", "strikingly", "Strikingly"),

        # Tilda
        (".tilda.ws", "tilda", "Tilda"),
        (".tilda.site", "tilda", "Tilda"),

        # Unbounce
        (".unbouncepages.com", "unbounce", "Unbounce"),

        # Intercom
        (".intercom.com", "intercom", "Intercom"),
        (".custom.intercom.com", "intercom", "Intercom"),
        (".custom.intercom.help", "intercom", "Intercom Help"),

        # WordPress.com / WP Engine
        (".wordpress.com", "wordpress", "WordPress.com"),
        (".wpengine.com", "wpengine", "WP Engine"),
        (".wpenginepowered.com", "wpengine", "WP Engine"),

        # Campaign Monitor
        (".createsend.com", "createsend", "Campaign Monitor"),

        # Freshdesk
        (".freshdesk.com", "freshdesk", "Freshdesk"),

        # Desk.com
        (".desk.com", "desk", "Desk.com"),

        # Statuspage (Atlassian)
        (".statuspage.io", "statuspage", "Atlassian Statuspage"),

        # Atlassian
        (".atlassian.net", "generic_404", "Atlassian"),

        # Ghost
        (".ghost.io", "ghost", "Ghost"),
        (".ghost.org", "ghost", "Ghost"),

        # Tumblr
        (".tumblr.com", "tumblr", "Tumblr"),
    ]

    def __init__(self, engine):
        self.engine = engine
        self.target = engine.target
        self.config = engine.config
        self.findings = engine.findings

    def run(self):
        domain = self.target.domain
        if not domain:
            print("  [!] SubdomainTakeover: no domain set")
            return

        subdomains = self.target.subdomains
        if not subdomains:
            print("  [*] SubdomainTakeover: no subdomains to check")
            return

        print(f"[*] Checking {len(subdomains)} subdomains for takeover")

        checked = 0
        vulnerable = 0

        for sub in subdomains:
            # sub can be SubdomainInfo obj or string
            if hasattr(sub, 'subdomain'):
                fqdn = sub.subdomain
            else:
                fqdn = f"{sub}.{domain}" if not sub.endswith(f".{domain}") else sub

            result = self._check_takeover(fqdn)
            checked += 1
            if result:
                vulnerable += 1
                service, evidence = result
                finding = VulnFinding(
                    name=f"Subdomain Takeover — {service}",
                    severity="HIGH",
                    url=f"https://{fqdn}/",
                    evidence=evidence,
                    description=f"Subdomain {fqdn} points to unclaimed {service} resource. "
                                f"An attacker can claim this resource and host arbitrary content.",
                )
                self.findings.add(finding)
                print(f"  [!] VULNERABLE: {fqdn} -> {service} ({evidence})")

        print(f"  [*] Takeover scan done: {checked} checked, {vulnerable} vulnerable")
        self.target.add_timeline("recon", "takeover_check",
                                 f"{checked} checked, {vulnerable} vulnerable")

    def _check_takeover(self, fqdn: str):
        """Check a single FQDN for subdomain takeover vulnerability.

        Returns (service_name, evidence) if vulnerable, None otherwise.
        """
        cname = self._get_cname(fqdn)
        if not cname:
            return None

        cname_lower = cname.lower()

        for suffix, check_fn, service in self.FINGERPRINTS:
            if suffix in cname_lower:
                # Run the verification check
                fn = getattr(self, f"_verify_{check_fn}", None)
                if fn:
                    evidence = fn(fqdn, cname)
                    if evidence:
                        return (service, evidence)
                break  # Matched a fingerprint but not vulnerable

        return None

    def _get_cname(self, fqdn: str) -> str | None:
        """Resolve CNAME record for a hostname."""
        try:
            answers = dns.resolver.resolve(fqdn, 'CNAME', lifetime=10)
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.LifetimeTimeout, dns.exception.DNSException):
            pass
        return None

    def _fetch(self, url: str, timeout: int = 10) -> tuple[int, str]:
        """Fetch URL and return (status, body)."""
        try:
            req = Request(url, headers={"User-Agent": self.config.user_agent})
            with urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")[:2000]
                return (resp.status, body)
        except HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:2000]
            return (e.code, body)
        except (URLError, socket.timeout, OSError):
            return (0, "")

    # Verification: returns evidence string if vulnerable, None if claimed.

    def _verify_aws_s3(self, fqdn: str, cname: str) -> str | None:
        """Check AWS S3 NoSuchBucket."""
        status, body = self._fetch(f"http://{fqdn}/")
        if status in (404, 403):
            if "NoSuchBucket" in body or "does not exist" in body:
                return "NoSuchBucket error"
        return None

    def _verify_cloudfront(self, fqdn: str, cname: str) -> str | None:
        """Check CloudFront missing distribution."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status in (400, 403, 404):
            if "BadRequest" in body or "not found" in body or "doesn't exist" in body:
                return f"HTTP {status}: CloudFront distribution missing"
        return None

    def _verify_github_pages(self, fqdn: str, cname: str) -> str | None:
        """Check GitHub Pages 404."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "There isn't a GitHub Pages site here" in body:
                return "GitHub Pages site not found"
        return None

    def _verify_heroku(self, fqdn: str, cname: str) -> str | None:
        """Check Heroku no-such-app."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status in (404, 503):
            if "no-such-app" in body or "There's nothing here" in body:
                return "Heroku app not found"
        return None

    def _verify_netlify(self, fqdn: str, cname: str) -> str | None:
        """Check Netlify 404."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Not Found - Netlify" in body or "Page Not Found" in body or "Netlify" in body:
                return "Netlify site not found"
        return None

    def _verify_vercel(self, fqdn: str, cname: str) -> str | None:
        """Check Vercel 404."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Not Found" in body and "Vercel" in body:
                return "Vercel deployment not found"
        return None

    def _verify_shopify(self, fqdn: str, cname: str) -> str | None:
        """Check Shopify store."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Sorry, this shop is currently unavailable" in body:
                return "Shopify store unavailable"
        return None

    def _verify_azure_webapp(self, fqdn: str, cname: str) -> str | None:
        """Check Azure Web App status."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status in (404, 410):
            if "not running" in body or "stopped" in body or "deleted" in body:
                return "Azure Web App not running"
        return None

    def _verify_firebase(self, fqdn: str, cname: str) -> str | None:
        """Check Firebase project."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "project not found" in body or "Firebase" in body:
                return "Firebase project not found"
        return None

    def _verify_fastly(self, fqdn: str, cname: str) -> str | None:
        """Check Fastly service."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Fastly" in body and "not found" in body.lower():
                return "Fastly service not found"
        return None

    def _verify_surge(self, fqdn: str, cname: str) -> str | None:
        """Check Surge.sh project."""
        status, body = self._fetch(f"http://{fqdn}/")
        if status == 404:
            if "project not found" in body.lower() or "not published" in body.lower():
                return "Surge project not found"
        return None

    def _verify_bitbucket(self, fqdn: str, cname: str) -> str | None:
        """Check Bitbucket repo."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Repository not found" in body or "Bitbucket" in body:
                return "Bitbucket repo not found"
        return None

    def _verify_pantheon(self, fqdn: str, cname: str) -> str | None:
        """Check Pantheon site."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status in (404, 405):
            if "pantheon" in body.lower() and ("not found" in body.lower() or "404" in body):
                return "Pantheon site not found"
        return None

    def _verify_readme(self, fqdn: str, cname: str) -> str | None:
        """Check Readme.io project."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Readme" in body and "not found" in body.lower():
                return "Readme project not found"
        return None

    def _verify_helpjuice(self, fqdn: str, cname: str) -> str | None:
        """Helpjuice — knowledge base not found."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "helpjuice" in body.lower() or "knowledge base" in body.lower():
                return "Helpjuice KB not found"
        return None

    def _verify_zendesk(self, fqdn: str, cname: str) -> str | None:
        """Check Zendesk subdomain."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Zendesk" in body and "not found" in body.lower():
                return "Zendesk subdomain not found"
        return None

    def _verify_strikingly(self, fqdn: str, cname: str) -> str | None:
        """Check Strikingly site."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Strikingly" in body or "site not found" in body.lower():
                return "Strikingly site not found"
        return None

    def _verify_tilda(self, fqdn: str, cname: str) -> str | None:
        """Check Tilda page."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "tilda" in body.lower() or "page not found" in body.lower():
                return "Tilda page not found"
        return None

    def _verify_unbounce(self, fqdn: str, cname: str) -> str | None:
        """Check Unbounce page."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Unbounce" in body or "page not found" in body.lower():
                return "Unbounce page not found"
        return None

    def _verify_intercom(self, fqdn: str, cname: str) -> str | None:
        """Check Intercom help center."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Intercom" in body or "help center" in body.lower():
                return "Intercom help center not found"
        return None

    def _verify_wordpress(self, fqdn: str, cname: str) -> str | None:
        """Check WordPress.com blog."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "WordPress.com" in body or "blog not found" in body.lower():
                return "WordPress.com site not found"
        return None

    def _verify_wpengine(self, fqdn: str, cname: str) -> str | None:
        """Check WP Engine install."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "WP Engine" in body or "installation not found" in body.lower():
                return "WP Engine install not found"
        return None

    def _verify_createsend(self, fqdn: str, cname: str) -> str | None:
        """Check Campaign Monitor list."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Subscriber list not found" in body or "createsend" in body.lower():
                return "Campaign Monitor list not found"
        return None

    def _verify_freshdesk(self, fqdn: str, cname: str) -> str | None:
        """Check Freshdesk helpdesk."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Freshdesk" in body or "helpdesk not found" in body.lower():
                return "Freshdesk helpdesk not found"
        return None

    def _verify_desk(self, fqdn: str, cname: str) -> str | None:
        """Check Desk.com site."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "desk" in body.lower() and "not found" in body.lower():
                return "Desk.com site not found"
        return None

    def _verify_statuspage(self, fqdn: str, cname: str) -> str | None:
        """Check Statuspage."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Statuspage" in body or "page not found" in body.lower():
                return "Statuspage not found"
        return None

    def _verify_ghost(self, fqdn: str, cname: str) -> str | None:
        """Check Ghost blog."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Ghost" in body and "not found" in body.lower():
                return "Ghost blog not found"
        return None

    def _verify_tumblr(self, fqdn: str, cname: str) -> str | None:
        """Check Tumblr blog."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status == 404:
            if "Tumblr" in body and "not found" in body.lower():
                return "Tumblr blog not found"
        return None

    def _verify_generic_404(self, fqdn: str, cname: str) -> str | None:
        """Fallback: 404/410 catch for services without specific fingerprints."""
        status, body = self._fetch(f"https://{fqdn}/")
        if status in (404, 410):
            return f"HTTP {status} — resource may be unclaimed"
        return None
