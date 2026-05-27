"""
PHANTOM — Directory Brute-Forcing Module

Threaded HTTP GET requests against a wordlist of common paths.
Filters: status codes, false positive detection via content similarity.
"""
from __future__ import annotations
import logging
import os
import threading
import time
from queue import Queue
from typing import Optional

import requests

from .base import ReconModule
from core.target import DirEntry
from utils.http import HttpClient

logger = logging.getLogger("phantom.recon.dirbrute")


class DirBrute(ReconModule):
    """Directory and file brute-forcing with false positive detection."""

    name = "dir_brute"
    description = "Directory and file brute-forcing"
    depends_on = ["tech_detect"]

    def run(self, target, config=None):
        """Populates target.directories.
        
        Brute-forces common paths on each discovered web endpoint.
        Filters 200/301/302/403/401/500 responses.
        Skips false positives via content-length similarity to 404.
        """
        http = HttpClient(config)
        
        if not target.endpoints:
            logger.warning("No endpoints to brute-force")
            return target
        
        # Load wordlist
        wordlist_path = self._get_wordlist(config)
        try:
            with open(wordlist_path, "r") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            logger.warning("Wordlist not found: %s", wordlist_path)
            return target
        
        # Get thread count
        max_threads = 20
        if config and hasattr(config, 'recon'):
            max_threads = getattr(config.recon, 'threads', 20)
        
        # Scan each base endpoint
        for base_url in target.endpoints[:3]:  # Limit to first 3 endpoints
            logger.info("Brute-forcing %s (%d words, %d threads)", 
                        base_url, len(words), max_threads)
            
            # Get baseline 404 response for FP detection
            baseline = self._get_404_baseline(http, base_url)
            
            found = self._brute(http, base_url, words, max_threads, baseline)
            target.directories.extend(found)
            logger.info("  Found %d paths", len(found))
        
        return target

    def _get_wordlist(self, config=None) -> str:
        """Get directory wordlist path."""
        # Check config first
        if config and hasattr(config, 'recon'):
            path = getattr(config.recon, 'dir_wordlist', None)
            if path and os.path.exists(path):
                return path
        
        # Check built-in
        builtin = os.path.join(os.path.dirname(__file__), "..", "config", "wordlists", "dirs.txt")
        if os.path.exists(builtin):
            return builtin
        
        return "dirs.txt"

    def _get_404_baseline(self, http, base_url: str) -> Optional[dict]:
        """Get baseline response for non-existent path (FP detection)."""
        import random
        rand_path = f"/phantom-{random.randint(10000, 99999)}.html"
        try:
            resp = http.get(f"{base_url}{rand_path}", timeout=5)
            return {
                "status": resp.status_code,
                "length": len(resp.content),
                "body_hash": hash(resp.text[:500]),
            }
        except requests.RequestException:
            return None

    def _brute(self, http, base_url: str, words: list[str],
               max_threads: int, baseline: Optional[dict]) -> list[DirEntry]:
        """Threaded directory brute-force."""
        found: list[DirEntry] = []
        lock = threading.Lock()
        word_queue: Queue = Queue()
        
        for word in words:
            word_queue.put(word)
        
        def worker() -> None:
            while True:
                try:
                    word = word_queue.get_nowait()
                except Exception:
                    break
                
                try:
                    url = f"{base_url.rstrip('/')}/{word}"
                    resp = http.get(url, timeout=5)
                    
                    if resp.status_code in {200, 301, 302, 403, 401, 500, 307}:
                        # False positive check
                        if baseline and resp.status_code == baseline["status"]:
                            if abs(len(resp.content) - baseline["length"]) < 50:
                                word_queue.task_done()
                                continue
                        
                        entry = DirEntry(
                            path=word,
                            status_code=resp.status_code,
                            content_length=len(resp.content),
                            content_type=resp.headers.get("Content-Type", ""),
                        )
                        with lock:
                            found.append(entry)
                            logger.debug("  %s [%d]", word, resp.status_code)
                except requests.RequestException:
                    pass
                finally:
                    word_queue.task_done()
        
        # Start threads
        threads = []
        num = min(max_threads, len(words))
        for _ in range(num):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait
        word_queue.join()
        
        return found

    def validate_target(self, target) -> bool:
        return target is not None and len(target.endpoints) > 0
