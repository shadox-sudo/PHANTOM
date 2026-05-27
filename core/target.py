import json
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str = ""
    banner: str = ""


@dataclass
class SubdomainInfo:
    subdomain: str
    ip: str = ""
    resolved: bool = False


@dataclass
class TechInfo:
    name: str
    version: str = ""
    certainty: int = 0


@dataclass
class VulnFinding:
    name: str
    severity: str
    url: str
    param: str = ""
    payload: str = ""
    evidence: str = ""
    cve: str = ""
    description: str = ""


@dataclass
class Target:
    domain: str
    ip: str = ""
    ports: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    tech_stack: list = field(default_factory=list)
    directories: list = field(default_factory=list)
    js_endpoints: list = field(default_factory=list)
    dork_results: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    exploits: list = field(default_factory=list)
    screenshot_paths: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    whois_info: dict = field(default_factory=dict)
    dns_records: dict = field(default_factory=dict)
    notes: dict = field(default_factory=dict)

    def add_timeline(self, phase: str, action: str, detail: str = ""):
        self.timeline.append({
            "phase": phase,
            "action": action,
            "detail": detail,
        })

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, path: str = ""):
        data = self.to_dict()
        if path:
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        return json.dumps(data, indent=2, default=str)

    @classmethod
    def from_json(cls, path_or_str: str):
        if path_or_str.endswith(".json"):
            with open(path_or_str) as f:
                data = json.load(f)
        else:
            data = json.loads(path_or_str)
        return cls(**{k: data.get(k, []) if k in (
            "ports", "subdomains", "directories", "js_endpoints",
            "dork_results", "vulnerabilities", "exploits",
            "screenshot_paths", "timeline", "tech_stack"
        ) else data.get(k, {}) if k in (
            "whois_info", "dns_records", "notes"
        ) else data.get(k, "")
           for k in cls.__dataclass_fields__})
