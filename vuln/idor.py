"""
PHANTOM — Insecure Direct Object Reference Detection Module

Detection:
1. Find numeric IDs in URLs, increment/decrement them
2. Compare response sizes/status codes for unauthorized access
3. Patterns: /user/1, /api/users/1, /document/123, ?id=456
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class IDORCheck:
    """Insecure Direct Object Reference detection via ID enumeration."""

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    def run(self):
        """Find numeric IDs in URLs and test adjacent IDs."""
        print("[*] Starting IDOR checks...")
        findings = 0

        patterns = self._find_id_patterns()
        if not patterns:
            print("  [!] No numeric ID patterns found in discovered URLs")
            return

        for pattern in patterns:
            try:
                if self._test_idor(pattern):
                    findings += 1
            except Exception as e:
                print(f"  [!] IDOR test failed: {e}")
                continue

        print(f"  [+] IDOR checks complete — {findings} finding(s)")

    # ── ID pattern discovery ────────────────────────────────────────

    def _find_id_patterns(self) -> list[dict]:
        """Scan all discovered URLs for numeric ID patterns."""
        patterns = []
        seen = set()

        sources = list(set(
            self.target.directories + self.target.js_endpoints
        ))

        for url in sources:
            # URL path pattern: /something/123
            for m in re.finditer(r'(/[a-zA-Z_/-]+)(\d{2,})', url):
                base_path = m.group(1).rstrip("/")
                raw_id = m.group(2)
                if raw_id.isdigit():
                    key = f"path:{base_path}"
                    if key not in seen:
                        seen.add(key)
                        patterns.append({
                            "type": "path",
                            "url": url,
                            "base_path": base_path,
                            "param": None,
                            "id": int(raw_id),
                        })

            # Query parameter pattern: ?id=123
            if "?" in url:
                qs = url.split("?", 1)[1]
                for part in qs.split("&"):
                    if "=" not in part:
                        continue
                    key, val = part.split("=", 1)
                    if val.isdigit() and 1 <= int(val) <= 99999:
                        pkey = f"query:{url}:{key}"
                        if pkey not in seen:
                            seen.add(pkey)
                            patterns.append({
                                "type": "query",
                                "url": url,
                                "base_path": None,
                                "param": key,
                                "id": int(val),
                            })

        return patterns

    # ── IDOR testing ────────────────────────────────────────────────

    def _test_idor(self, pattern: dict) -> bool:
        """Try adjacent IDs and compare response characteristics."""
        # Get baseline response
        try:
            base_resp = request(pattern["url"], timeout=10)
            if not base_resp or base_resp.status == 0:
                return False
            base_len = len(base_resp.body)
            base_status = base_resp.status
        except Exception:
            return False

        # Test adjacent and nearby IDs
        test_ids = [
            pattern["id"] + 1,
            pattern["id"] - 1,
            pattern["id"] + 100,
            pattern["id"] + 1000,
            pattern["id"] + 5000,
            pattern["id"] * 2,
        ]

        for test_id in test_ids:
            if test_id <= 0 or test_id == pattern["id"]:
                continue

            if pattern["type"] == "path":
                test_url = re.sub(
                    r'(\d+)',
                    str(test_id),
                    pattern["url"],
                    count=1,
                )
            else:
                test_url = self._inject_query(
                    pattern["url"],
                    pattern["param"],
                    str(test_id),
                )

            try:
                resp = request(test_url, timeout=10)
                if not resp:
                    continue

                # IDOR indicators:
                # 1. Same status code (both 200) = both accessible
                # 2. Similar response size = same kind of data returned
                # 3. Different content = different object accessed
                if resp.status == base_status and resp.status in (200, 201):
                    size_diff = abs(len(resp.body) - base_len)
                    if size_diff < 500 and resp.body != base_resp.body:
                        self.engine.findings.add(Finding(
                            name="Insecure Direct Object Reference (IDOR)",
                            severity="HIGH",
                            url=pattern["url"],
                            param=pattern.get("param") or "(path)",
                            payload=f"ID {pattern['id']} -> {test_id}",
                            evidence=(
                                f"Original: {base_status} ({base_len}B) | "
                                f"ID {test_id}: {resp.status} ({len(resp.body)}B)"
                            ),
                            phase="vuln",
                        ))
                        print(f"  [+] IDOR @ {pattern['url']} (ID {pattern['id']} -> {test_id})")
                        return True

            except Exception:
                continue

        return False

    # ── Helpers ─────────────────────────────────────────────────────

    def _inject_query(self, url: str, param: str, value: str) -> str:
        """Replace a query parameter value."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_qs = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_qs))
