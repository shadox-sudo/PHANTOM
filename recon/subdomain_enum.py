"""
PHANTOM — Subdomain Enumeration Module

Two methods:
1. crt.sh Certificate Transparency log API (passive)
2. Wordlist brute-force with resolver (active)
"""
from __future__ import annotations
import json
import logging
import socket
import threading
import urllib.request
import urllib.error
from typing import Optional

from .base import ReconModule

logger = logging.getLogger("phantom.recon.subdomain")


class SubdomainEnum(ReconModule):
    """Subdomain enumeration via crt.sh + wordlist brute-force."""

    name = "subdomain_enum"
    description = "Subdomain enumeration via crt.sh + wordlist brute-force"
    depends_on = []

    def run(self, target, config=None):
        """Populates target.subdomains and target.ips.
        
        1. Query crt.sh API for certificate-transparency subdomains
        2. Brute-force common subdomains from wordlist
        3. Resolve each found subdomain to IP
        """
        domain = target.domain
        if not domain:
            logger.warning("No domain set, skipping subdomain enumeration")
            return target
        
        all_subs: set[str] = set()
        
        # Method 1: crt.sh passive enumeration
        try:
            crt_subs = self._crt_sh(domain)
            all_subs.update(crt_subs)
            logger.info("crt.sh found %d subdomains", len(crt_subs))
        except Exception as e:
            logger.warning("crt.sh failed: %s", e)
        
        # Method 2: Wordlist brute-force
        wordlist_path = None
        if config and hasattr(config, 'recon'):
            wordlist_path = getattr(config.recon, 'subdomain_wordlist', None)
        
        if wordlist_path:
            try:
                brute_subs = self._brute_force(domain, wordlist_path, config)
                all_subs.update(brute_subs)
                logger.info("Wordlist found %d subdomains", len(brute_subs))
            except Exception as e:
                logger.warning("Wordlist brute-force failed: %s", e)
        
        # Resolve all found subdomains
        resolved: list[str] = []
        for sub in all_subs:
            fqdn = f"{sub}.{domain}"
            ips = self._resolve(fqdn)
            if ips:
                resolved.append(fqdn)
                for ip in ips:
                    if ip not in target.ips:
                        target.ips.append(ip)
        
        target.subdomains = all_subs
        logger.info("Subdomain enum: %d found, %d resolved", len(all_subs), len(resolved))
        return target

    def _crt_sh(self, domain: str) -> set[str]:
        """Query crt.sh Certificate Transparency API for subdomains.
        
        API: https://crt.sh/?q=%25.{domain}&output=json
        """
        subdomains: set[str] = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            
            for entry in data:
                name = entry.get("name_value", "")
                # crt.sh returns comma-separated or newline-separated subdomains
                for sub in name.replace("\n", ",").split(","):
                    sub = sub.strip()
                    if sub.endswith(f".{domain}"):
                        s = sub[:-(len(domain) + 1)]  # strip trailing .domain
                        if s and "*" not in s:   # skip wildcard
                            subdomains.add(s)
        except (urllib.error.URLError, urllib.error.HTTPError,
                json.JSONDecodeError, socket.timeout) as e:
            logger.debug("crt.sh error: %s", e)
        
        return subdomains

    def _brute_force(self, domain: str, wordlist_path: str, config=None) -> set[str]:
        """Brute-force subdomains from a wordlist file.
        
        Uses threading for parallel resolution.
        """
        subdomains: set[str] = set()
        lock = threading.Lock()
        threads = []
        
        try:
            with open(wordlist_path, "r") as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.warning("Wordlist not found: %s", wordlist_path)
            return subdomains
        
        max_threads = 50
        if config and hasattr(config, 'recon'):
            max_threads = getattr(config.recon, 'threads', 50)
        
        def check_sub(word: str) -> None:
            fqdn = f"{word}.{domain}"
            if self._resolve(fqdn):
                with lock:
                    subdomains.add(word)
        
        # Thread pool
        word_iter = iter(words)
        active: list[threading.Thread] = []
        
        try:
            for word in words:
                if len(active) >= max_threads:
                    # Join one thread
                    active[0].join(timeout=5)
                    active = [t for t in active if t.is_alive()]
                
                t = threading.Thread(target=check_sub, args=(word,), daemon=True)
                t.start()
                active.append(t)
            
            # Wait for remaining
            for t in active:
                t.join(timeout=10)
        except Exception as e:
            logger.error("Brute-force error: %s", e)
        
        return subdomains

    def _resolve(self, fqdn: str) -> list[str]:
        """Resolve FQDN to IP addresses."""
        try:
            info = socket.getaddrinfo(fqdn, 0, socket.AF_INET, socket.SOCK_STREAM)
            return list(set(i[4][0] for i in info))
        except socket.gaierror:
            return []

    def validate_target(self, target) -> bool:
        return target is not None and bool(target.domain)
