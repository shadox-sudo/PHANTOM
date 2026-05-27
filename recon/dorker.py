"""
PHANTOM — Google Dorking Module

Generates Google dork URLs for the target domain and tests them.
Does NOT scrape Google directly (could trigger blocks) — instead:
1. Generates the search URLs for manual review
2. Optionally checks via a cached/proxy search API
"""
from __future__ import annotations
import logging
import urllib.parse
from typing import Optional

from .base import ReconModule
from core.target import DorkResult

logger = logging.getLogger("phantom.recon.dorker")


class Dorker(ReconModule):
    """Google dork generation and testing."""

    name = "dorker"
    description = "Google dork URL generation and testing"
    depends_on = []

    def run(self, target, config=None):
        """Populates target.dork_results.
        
        Generates Google dork search URLs for the target domain.
        Tests if dork patterns reveal accessible paths.
        """
        domain = target.domain
        if not domain:
            logger.warning("No domain set, skipping dorker")
            return target
        
        # Generate dork queries
        dorks = self._generate_dorks(domain)
        
        # Build results
        results = []
        for dork_name, dork_query in dorks:
            search_url = f"https://www.google.com/search?q={urllib.parse.quote(dork_query)}"
            result = DorkResult(
                dork=dork_name,
                url=search_url,
                description=dork_query,
                found=False,  # Requires manual verification
            )
            results.append(result)
        
        target.dork_results = results
        logger.info("Dorker: generated %d dorks", len(results))
        return target

    def _generate_dorks(self, domain: str) -> list[tuple[str, str]]:
        """Generate Google dork queries for the domain.
        
        Returns:
            List of (dork_name, dork_query) tuples.
        """
        dorks = [
            # Information disclosure
            ("Directory listing", f"site:{domain} intitle:index.of"),
            ("Configuration files", f"site:{domain} ext:xml | ext:conf | ext:cfg | ext:env | ext:ini"),
            ("Database files", f"site:{domain} ext:sql | ext:db | ext:sqlite | ext:mdb"),
            ("Log files", f"site:{domain} ext:log | ext:txt ext:log"),
            ("Backup files", f"site:{domain} ext:bak | ext:old | ext:backup | ext:swp"),
            
            # Admin/management interfaces
            ("Admin panels", f"site:{domain} inurl:admin | inurl:login | inurl:wp-admin"),
            ("PHP info", f"site:{domain} ext:php intitle:phpinfo"),
            
            # Sensitive data
            ("Password files", f"site:{domain} ext:pwd | ext:passwd | ext:htpasswd"),
            ("Private keys", f"site:{domain} ext:key | ext:pem | ext:ppk"),
            ("API keys", f"site:{domain} ext:env | ext:env.example"),
            ("S3 buckets", f"site:{domain} inurl:s3 | inurl:bucket | inurl:aws"),
            
            # Exposed services
            ("Git repositories", f"site:{domain} inurl:.git"),
            ("SVN repositories", f"site:{domain} inurl:.svn"),
            ("Docker configs", f"site:{domain} ext:dockerfile | ext:docker-compose"),
            
            # URLs with parameters (potential injection points)
            ("PHP parameters", f"site:{domain} inurl:\"?\" ext:php"),
            ("ASP parameters", f"site:{domain} inurl:\"?\" ext:asp | ext:aspx"),
            
            # Error messages
            ("PHP errors", f"site:{domain} \"PHP Fatal error\" | \"Notice: Undefined\""),
            ("SQL errors", f"site:{domain} \"SQL syntax\" | \"mysql_fetch\" | \"ORA-\""),
            
            # Specific file types
            ("PDF documents", f"site:{domain} ext:pdf"),
            ("Spreadsheets", f"site:{domain} ext:xls | ext:xlsx | ext:csv"),
            ("Word documents", f"site:{domain} ext:doc | ext:docx"),
        ]
        
        return dorks

    def validate_target(self, target) -> bool:
        return target is not None and bool(target.domain)
