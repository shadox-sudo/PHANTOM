"""
PHANTOM — Configuration System

Hierarchy (lowest → highest priority):
    1. Default hardcoded values
    2. TOML config file
    3. PHANTOM_* environment variables
    4. CLI argument overrides (passed via merge())

Environment variables use the pattern:
    PHANTOM_{SECTION}_{KEY}
    Example: PHANTOM_TARGET_DOMAIN="example.com"
             PHANTOM_TELEGRAM_TOKEN="bot123:abc"
"""
from __future__ import annotations
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Section Dataclasses ────────────────────────────────────────

@dataclass
class TargetSettings:
    domain: str = ""
    url: str = ""
    ip: str = ""
    ports: str = "21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,27017"
    rate_limit_delay: float = 0.1
    timeout: int = 5


@dataclass
class ReconSettings:
    whois: bool = True
    dns: bool = True
    subdomain_enum: bool = True
    port_scan: bool = True
    tech_detect: bool = True
    dir_brute: bool = True
    js_scraper: bool = True
    dorker: bool = False
    threads: int = 50
    subdomain_wordlist: str = ""
    dir_wordlist: str = ""


@dataclass
class VulnSettings:
    sqli: bool = True
    xss: bool = True
    lfi_rfi: bool = True
    ssrf: bool = True
    open_redirect: bool = True
    idor: bool = True
    jwt_analyzer: bool = True
    cors: bool = True
    rate_limit: bool = True
    default_creds: bool = True
    cve_matcher: bool = True


@dataclass
class ExploitSettings:
    auto_exploit: bool = False
    lhost: str = ""
    lport: int = 4444
    payload_type: str = "reverse"   # reverse, bind, beacon
    c2_url: str = ""


@dataclass
class ReportSettings:
    output_dir: str = "./output"
    format: str = "html"
    include_evidence: bool = True


@dataclass
class TelegramSettings:
    enabled: bool = False
    token: str = ""
    chat_id: str = ""


@dataclass
class ProxySettings:
    http: str = ""
    https: str = ""
    socks5: str = ""


@dataclass
class RateLimitSettings:
    max_requests_per_second: float = 10.0
    burst_size: int = 5
    cooldown_seconds: int = 60


@dataclass
class PluginSettings:
    directory: str = ""
    auto_load: bool = True


# ── Main Settings ──────────────────────────────────────────────

class Settings:
    """Central configuration object."""

    def __init__(self) -> None:
        self.target = TargetSettings()
        self.recon = ReconSettings()
        self.vuln = VulnSettings()
        self.exploit = ExploitSettings()
        self.report = ReportSettings()
        self.telegram = TelegramSettings()
        self.proxy = ProxySettings()
        self.rate_limit = RateLimitSettings()
        self.plugins = PluginSettings()

    @classmethod
    def default(cls) -> "Settings":
        """Return default settings."""
        return cls()

    @classmethod
    def from_file(cls, path: str) -> "Settings":
        """Load settings from TOML or JSON file.
        
        Args:
            path: Path to config file (.toml or .json).
        
        Returns:
            Settings instance with values from file merged over defaults.
        
        Raises:
            ConfigError: If file not found or invalid format.
        """
        s = cls()
        if not os.path.exists(path):
            from core.exceptions import ConfigError
            raise ConfigError(f"Config file not found: {path}")
        
        ext = os.path.splitext(path)[1].lower()
        if ext == ".json":
            with open(path, "r") as f:
                data = json.load(f)
        elif ext == ".toml":
            try:
                import tomllib
            except ImportError:
                # Fallback: parse basic TOML manually (no dependency)
                data = _parse_toml_simple(path)
            else:
                with open(path, "rb") as f:
                    data = tomllib.load(f)
        else:
            from core.exceptions import ConfigError
            raise ConfigError(f"Unsupported config format: {ext}")
        
        return s.merge(data)

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from PHANTOM_* environment variables.
        
        Pattern: PHANTOM_{SECTION}_{KEY}
        Example: PHANTOM_TARGET_DOMAIN, PHANTOM_TELEGRAM_TOKEN
        """
        s = cls()
        prefix = "PHANTOM_"
        
        for env_key, env_val in os.environ.items():
            if not env_key.startswith(prefix):
                continue
            
            # Parse key: PHANTOM_TARGET_DOMAIN → section="target", key="domain"
            rest = env_key[len(prefix):].lower()
            parts = rest.split("_", 1)
            if len(parts) != 2:
                continue
            
            section_name, key = parts
            
            # Map to dataclass
            section = getattr(s, section_name, None)
            if section is None:
                continue
            if not hasattr(section, key):
                continue
            
            # Type coerce
            current = getattr(section, key)
            if isinstance(current, bool):
                env_val = env_val.lower() in ("true", "1", "yes")
            elif isinstance(current, int):
                env_val = int(env_val)
            elif isinstance(current, float):
                env_val = float(env_val)
            
            setattr(section, key, env_val)
        
        return s

    def merge(self, overrides: dict) -> "Settings":
        """Override settings with a flat or nested dict.
        
        Supports both:
            {"target": {"domain": "example.com", ...}}
            {"domain": "example.com", "threads": 100}  (flat)
        
        Args:
            overrides: Dict of settings to override.
        
        Returns:
            Self for chaining.
        """
        for key, value in overrides.items():
            if value is None or value == "":
                continue
            
            # Check if key maps to a section
            section = getattr(self, key, None)
            if section is not None and isinstance(value, dict):
                for sub_key, sub_val in value.items():
                    if hasattr(section, sub_key) and sub_val is not None:
                        setattr(section, sub_key, sub_val)
            else:
                # Check all sections for this key
                found = False
                for section_name in self._section_names():
                    section = getattr(self, section_name)
                    if hasattr(section, key) and value is not None:
                        current = getattr(section, key)
                        if isinstance(current, bool):
                            if isinstance(value, str):
                                value = value.lower() in ("true", "1", "yes")
                            elif isinstance(value, (int, float)):
                                value = bool(value)
                        elif isinstance(current, int):
                            value = int(value) if not isinstance(value, int) else value
                        elif isinstance(current, float):
                            value = float(value) if not isinstance(value, float) else value
                        setattr(section, key, value)
                        found = True
                        break
                if not found:
                    # Try setting as direct attribute
                    pass
        
        return self

    def to_dict(self) -> dict:
        """Serialize to nested dict."""
        return {
            "target": asdict(self.target),
            "recon": asdict(self.recon),
            "vuln": asdict(self.vuln),
            "exploit": asdict(self.exploit),
            "report": asdict(self.report),
            "telegram": asdict(self.telegram),
            "proxy": asdict(self.proxy),
            "rate_limit": asdict(self.rate_limit),
            "plugins": asdict(self.plugins),
        }

    def to_file(self, path: str) -> None:
        """Save settings to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def _section_names(self) -> list[str]:
        return [
            "target", "recon", "vuln", "exploit",
            "report", "telegram", "proxy", "rate_limit", "plugins",
        ]


# ── Simple TOML Parser (no dependency fallback) ────────────────

def _parse_toml_simple(path: str) -> dict:
    """Minimal TOML parser for flat config files.
    
    Only supports [section] headers and key = "value" / key = true / key = 123.
    No nested tables, no arrays. Good enough for config files.
    """
    result: dict = {}
    current_section: str = ""
    
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Section header
            m = re.match(r'^\[(\w+)\]$', line)
            if m:
                current_section = m.group(1)
                if current_section not in result:
                    result[current_section] = {}
                continue
            
            # Key = value
            m = re.match(r'^(\w+)\s*=\s*(.+)$', line)
            if m:
                key = m.group(1)
                val = m.group(2).strip()
                
                # Parse value
                if val.lower() in ("true", "false"):
                    val = val.lower() == "true"
                elif val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                elif val.startswith("'") and val.endswith("'"):
                    val = val[1:-1]
                else:
                    try:
                        if "." in val:
                            val = float(val)
                        else:
                            val = int(val)
                    except ValueError:
                        pass  # keep as string
                
                if current_section:
                    result[current_section][key] = val
                else:
                    result[key] = val
    
    return result
