"""PHANTOM — Central config: CLI args + env vars + JSON import."""
import os
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PhantomConfig:
    target: str = ""
    threads: int = 20
    timeout: int = 10
    rate_limit: float = 0.5
    proxy: str = ""
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    user_agents_file: str = ""
    output_dir: str = "reports"
    wordlist_dir: str = "config/wordlists"

    phases: list = field(default_factory=lambda: ["recon", "vuln", "exploit", "report"])

    recon_dns: bool = True
    recon_ports: bool = True
    recon_tech: bool = True
    recon_dirs: bool = True
    recon_js: bool = True
    recon_dorks: bool = True
    recon_takeover: bool = True

    vuln_sqli: bool = True
    vuln_xss: bool = True
    vuln_lfi: bool = True
    vuln_ssrf: bool = True
    vuln_redirect: bool = True
    vuln_idor: bool = True
    vuln_jwt: bool = True
    vuln_cors: bool = True
    vuln_rate_limit: bool = True
    vuln_default_creds: bool = True
    vuln_cve: bool = True

    exploit_auto: bool = True

    report_html: bool = True
    report_json: bool = True

    telegram_token: str = ""
    telegram_chat_id: str = ""

    @classmethod
    def from_dict(cls, d: dict):
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in d.items() if k in valid_keys}
        return cls(**filtered)

    @classmethod
    def from_json(cls, path: str):
        with open(path) as f:
            return cls.from_dict(json.load(f))

    def merge_env(self):
        prefix = "PHANTOM_"
        for key in self.__dataclass_fields__:
                    env_key = f"{prefix}{key.upper()}"
                    if env_key in os.environ:
                        val = os.environ[env_key]
                        current = getattr(self, key)
                        if isinstance(current, bool):
                            setattr(self, key, val.lower() in ("1", "true", "yes"))
                        elif isinstance(current, int):
                            setattr(self, key, int(val))
                        elif isinstance(current, float):
                            setattr(self, key, float(val))
                        elif isinstance(current, list):
                            setattr(self, key, val.split(","))
                        else:
                            setattr(self, key, val)

    def merge_cli(self, args: dict):
        for key, val in args.items():
            if val is not None and key in self.__dataclass_fields__:
                setattr(self, key, val)
