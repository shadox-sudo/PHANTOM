from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Finding:
    name: str
    severity: str
    url: str
    phase: str
    timestamp: str = ""
    param: str = ""
    payload: str = ""
    evidence: str = ""
    cve: str = ""
    description: str = ""
    remediation: str = ""
    confidence: int = 0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "severity": self.severity,
            "url": self.url,
            "phase": self.phase,
            "timestamp": self.timestamp,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "cve": self.cve,
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
        }


class FindingsDB:
    def __init__(self):
        self._findings: list[Finding] = []

    def add(self, finding: Finding):
        self._findings.append(finding)

    def add_raw(self, **kwargs):
        self._findings.append(Finding(**kwargs))

    def all(self) -> list[Finding]:
        return sorted(self._findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def critical(self) -> list[Finding]:
        return self.by_severity("CRITICAL")

    def high(self) -> list[Finding]:
        return self.by_severity("HIGH")

    def medium(self) -> list[Finding]:
        return self.by_severity("MEDIUM")

    def low(self) -> list[Finding]:
        return self.by_severity("LOW")

    def info(self) -> list[Finding]:
        return self.by_severity("INFO")

    def count(self) -> dict:
        counts = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def clear(self):
        self._findings.clear()


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}
