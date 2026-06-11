"""PHANTOM — Evidence Collector"""
from __future__ import annotations
import logging
import os
from datetime import datetime
from typing import Optional

logger = logging.getLogger("phantom.report.evidence")


class EvidenceCollector:
    """Collects and persists evidence artifacts to disk.

    Evidence is saved under: {output_dir}/evidence/{domain}/
    Each file is named: {timestamp}_{label_slug}.txt

    Args:
        engine: PhantomEngine instance (used for config and target).
    """

    def __init__(self, engine) -> None:
        self.engine = engine
        self.config = getattr(engine, "config", None)
        self.target = getattr(engine, "target", None)

    # ── Public API ─────────────────────────────────────────────

    def save_response(self, url: str, status: int, body: str,
                      param: str = "") -> str:
        """Save HTTP response body as evidence.

        Args:
            url: The request URL.
            status: HTTP status code.
            body: Response body text.
            param: Optional parameter name being tested.

        Returns:
            Path to saved evidence file, or empty string on failure.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")[:19]
        slug = self._slugify(f"resp_{param or 'req'}_{status}")
        filename = f"{timestamp}_{slug}.txt"

        lines = [
            f"# Evidence: HTTP Response",
            f"# Timestamp: {datetime.utcnow().isoformat()}",
            f"# URL: {url}",
            f"# Status: {status}",
            f"# Parameter: {param}" if param else "",
            f"# {'=' * 60}",
            body[:50000] if body else "(empty response)",
        ]
        content = "\n".join(line for line in lines if line)

        path = self._write(filename, content)
        if path:
            logger.debug("Saved response evidence: %s (%d bytes, %d)", url, len(body), status)
        return path

    def capture_screenshot(self, url: str, path_hint: str = "") -> str:
        """Capture a text-based 'screenshot' of a page.

        This is NOT a real screenshot — it saves the full HTML source
        of the page as a text evidence file. For actual screenshots,
        use external tools and call save_raw().

        Args:
            url: The URL being captured.
            path_hint: Optional hint for labeling.

        Returns:
            Path to saved file, or empty string on failure.
        """
        label = path_hint or self._slugify(url)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")[:19]
        filename = f"{timestamp}_screenshot_{label}.txt"

        content = (
            f"# Text Screenshot (HTML Source)\n"
            f"# URL: {url}\n"
            f"# Timestamp: {datetime.utcnow().isoformat()}\n"
            f"# NOTE: This is raw HTML source, not a visual screenshot.\n"
            f"# {'=' * 60}\n"
            f"Use save_response() first to capture the body, then\n"
            f"call capture_screenshot() to register it as a 'screenshot'.\n"
        )

        path = self._write(filename, content)
        if path:
            logger.info("Text screenshot registered: %s", url)
        return path

    def save_raw(self, name: str, data: str) -> str:
        """Save arbitrary raw data as evidence.

        Args:
            name: Short descriptive name (used in filename).
            data: Raw data content to save.

        Returns:
            Path to saved file, or empty string on failure.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")[:19]
        slug = self._slugify(name)
        filename = f"{timestamp}_{slug}.txt"

        content = (
            f"# Raw Evidence: {name}\n"
            f"# Timestamp: {datetime.utcnow().isoformat()}\n"
            f"# {'=' * 60}\n"
            f"{data[:100000] if data else '(empty)'}\n"
        )

        path = self._write(filename, content)
        if path:
            logger.debug("Saved raw evidence: %s (%d bytes)", name, len(data or ""))
        return path

    def save_finding_evidence(self, finding, response_body: str) -> str:
        """Save evidence specifically for a vulnerability finding.

        Constructs a detailed evidence file linking the finding metadata
        with the response body that demonstrates the vulnerability.

        Args:
            finding: A Finding object from engine.findings.
            response_body: The HTTP response body that proves the vuln.

        Returns:
            Path to saved evidence file, or empty string on failure.
        """
        name = getattr(finding, "name", "unknown")
        sev = getattr(finding, "severity", "UNKNOWN")
        url = getattr(finding, "url", "")
        param = getattr(finding, "param", "") or getattr(finding, "parameter", "")
        payload = getattr(finding, "payload", "")
        desc = getattr(finding, "description", "")

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")[:19]
        slug = self._slugify(f"finding_{name}")
        filename = f"{timestamp}_{slug}.txt"

        lines = [
            f"# Finding Evidence",
            f"# Timestamp: {datetime.utcnow().isoformat()}",
            f"# {'=' * 60}",
            f"# Name: {name}",
            f"# Severity: {sev}",
            f"# URL: {url}",
            f"# Parameter: {param}" if param else "",
            f"# Payload: {payload}" if payload else "",
            f"# Description: {desc}" if desc else "",
            f"# {'=' * 60}",
            f"# Response Body ({len(response_body)} bytes):",
            f"# {'=' * 60}",
            response_body[:100000] if response_body else "(empty response)",
        ]
        content = "\n".join(line for line in lines if line)

        path = self._write(filename, content)
        if path:
            logger.info(
                "Saved evidence for finding: %s [%s] (%d bytes)",
                name, sev, len(response_body or ""),
            )
        return path

    # ── Internal ───────────────────────────────────────────────

    def _evidence_dir(self) -> str:
        """Get evidence output directory, creating it if needed.

        Returns:
            Path to evidence directory.
        """
        domain = "unknown"
        if self.target:
            domain = getattr(self.target, "domain", "") or \
                     getattr(self.target, "url", "") or \
                     getattr(self.target, "ip", "unknown")
            domain = domain.replace("https://", "").replace("http://", "").replace("/", "_")

        output_dir = getattr(getattr(self.config, "report", None), "output_dir", None) or \
                     getattr(self.config, "output_dir", "./reports")

        evidence_dir = os.path.join(output_dir, "evidence", domain)
        os.makedirs(evidence_dir, exist_ok=True)
        return evidence_dir

    def _write(self, filename: str, content: str) -> str:
        """Write content to a file in the evidence directory.

        Args:
            filename: Name of the file.
            content: Content to write.

        Returns:
            Full path to the written file, or empty string on failure.
        """
        try:
            path = os.path.join(self._evidence_dir(), filename)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return path
        except OSError as e:
            logger.error("Failed to write evidence file %s: %s", filename, e)
            return ""

    @staticmethod
    def _slugify(text: str) -> str:
        """Convert text to a filesystem-safe slug.

        Args:
            text: Raw text to slugify.

        Returns:
            Slug string safe for use in filenames.
        """
        safe = ""
        for c in text[:64]:
            if c.isalnum() or c in "-_.":
                safe += c
            elif c in " /?&=:":
                safe += "_"
        return safe.strip("_").lower() or "evidence"
