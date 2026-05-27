"""
PHANTOM — Report, Timeline, and Evidence Models
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional


class TimelineEntry:
    """A single event in the scan timeline."""

    def __init__(self, phase: str, module: str,
                 action: str, status: str = "running",
                 duration: Optional[float] = None) -> None:
        self.timestamp: datetime = datetime.utcnow()
        self.phase: str = phase        # recon/vuln/exploit/report
        self.module: str = module      # port_scanner, sqli, etc.
        self.action: str = action      # human-readable description
        self.status: str = status      # running/success/failed/skipped
        self.duration: Optional[float] = duration

    def complete(self, status: str = "success", duration: Optional[float] = None) -> None:
        """Mark timeline entry as completed."""
        self.status = status
        if duration is not None:
            self.duration = duration

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "phase": self.phase,
            "module": self.module,
            "action": self.action,
            "status": self.status,
            "duration": self.duration,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TimelineEntry":
        e = cls(
            phase=data["phase"],
            module=data["module"],
            action=data["action"],
            status=data.get("status", "running"),
            duration=data.get("duration"),
        )
        if "timestamp" in data:
            e.timestamp = datetime.fromisoformat(data["timestamp"])
        return e

    def __repr__(self) -> str:
        return f"[{self.timestamp:%H:%M:%S}] {self.phase}/{self.module}: {self.action} ({self.status})"


class Evidence:
    """Captured evidence for report inclusion."""

    def __init__(self, evidence_type: str, label: str,
                 content: str,
                 finding_id: Optional[str] = None) -> None:
        self.type: str = evidence_type   # response_body, headers, screenshot_text, log
        self.label: str = label
        self.content: str = content
        self.finding_id: Optional[str] = finding_id
        self.timestamp: datetime = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "label": self.label,
            "content": self.content,
            "finding_id": self.finding_id,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Evidence":
        e = cls(
            evidence_type=data["type"],
            label=data["label"],
            content=data["content"],
            finding_id=data.get("finding_id"),
        )
        if "timestamp" in data:
            e.timestamp = datetime.fromisoformat(data["timestamp"])
        return e


class Report:
    """Complete scan report with all findings and evidence."""

    def __init__(self) -> None:
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.duration: Optional[float] = None

    def finalize(self, target) -> None:
        """Calculate final report metrics from target data."""
        self.end_time = datetime.utcnow()
        if self.start_time:
            self.duration = (self.end_time - self.start_time).total_seconds()

        # Summary stats from target
        self.summary = target.summary()

    def to_html(self, template_path: str = "report/templates/report.html") -> str:
        """Generate HTML report from template.
        
        Args:
            template_path: Path to HTML template file.
        
        Returns:
            Rendered HTML string.
        """
        # This will be implemented in report/generator.py
        raise NotImplementedError("Use ReportGenerator.generate()")

    def to_json(self) -> str:
        """Serialize to JSON string."""
        import json
        return json.dumps({
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "summary": getattr(self, "summary", {}),
        }, indent=2)

    def save(self, path: str, content: str) -> str:
        """Write report content to file.
        
        Args:
            path: Output file path.
            content: HTML or JSON content.
        
        Returns:
            Path to saved file.
        """
        with open(path, "w") as f:
            f.write(content)
        return path
