import sys
import os
import importlib
import inspect
from datetime import datetime

from core.target import Target
from core.findings import FindingsDB
from core.config import PhantomConfig
from core.exceptions import PhantomError
from utils.status import LiveStatus, C


class PhaseResult:
    def __init__(self, phase: str, success: bool, data=None):
        self.phase = phase
        self.success = success
        self.data = data or {}
        self.time = datetime.now().isoformat()


class PhantomEngine:
    def __init__(self, config: PhantomConfig):
        self.config = config
        self.target = Target(domain=config.target)
        self.findings = FindingsDB()
        self.results = []
        self._plugins = []
        self._running = True

    def run(self):
        phases = self.config.phases
        for phase in phases:
            if not self._running:
                break
            if phase == "recon":
                self.run_recon()
            elif phase == "vuln":
                self.run_vuln()
            elif phase == "exploit":
                self.run_exploit()
            elif phase == "report":
                self.run_report()

    def run_recon(self):
        print(f"\n{C.BOLD}[*] RECON PHASE — {self.target.domain}{C.RST}")
        self.target.add_timeline("recon", "started")

        modules = []
        if self.config.recon_dns:
            from recon.dns import DNSRecon
            modules.append(DNSRecon(self))
        if self.config.recon_ports:
            from recon.ports import PortScanner
            modules.append(PortScanner(self))
        if self.config.recon_tech:
            from recon.tech import TechDetect
            modules.append(TechDetect(self))
        if self.config.recon_dirs:
            from recon.dirs import DirBrute
            modules.append(DirBrute(self))
        if self.config.recon_js:
            from recon.js_scrape import JSScraper
            modules.append(JSScraper(self))
        if self.config.recon_dorks:
            from recon.dorks import DorkGen
            modules.append(DorkGen(self))

        total = len(modules)
        for i, mod in enumerate(modules, 1):
            if not self._running:
                break
            name = mod.__class__.__name__
            with LiveStatus(f"[{i}/{total}] {name}") as s:
                try:
                    mod.run()
                    rc = len(self.target.subdomains) + len(self.target.ports) + len(self.target.tech_stack) + len(self.target.directories)
                    s.count(rc)
                except Exception as e:
                    s.extra(f"FAILED: {e}")

        self.target.add_timeline("recon", "completed")
        self.results.append(PhaseResult("recon", True))

        subs, ports, tech, dirs = len(self.target.subdomains), len(self.target.ports), len(self.target.tech_stack), len(self.target.directories)
        print(f"  {C.BOLD}RECON DONE:{C.RST} subs={subs} ports={ports} tech={tech} dirs={dirs}")

    def run_vuln(self):
        print(f"\n{C.BOLD}[*] VULN PHASE — {self.target.domain}{C.RST}")
        self.target.add_timeline("vuln", "started")

        checks = []
        if self.config.vuln_sqli:
            from vuln.sqli import SQLiCheck
            checks.append(SQLiCheck(self))
        if self.config.vuln_xss:
            from vuln.xss import XSSCheck
            checks.append(XSSCheck(self))
        if self.config.vuln_lfi:
            from vuln.lfi import LFICheck
            checks.append(LFICheck(self))
        if self.config.vuln_ssrf:
            from vuln.ssrf import SSRFCheck
            checks.append(SSRFCheck(self))
        if self.config.vuln_redirect:
            from vuln.redirect import RedirectCheck
            checks.append(RedirectCheck(self))
        if self.config.vuln_idor:
            from vuln.idor import IDORCheck
            checks.append(IDORCheck(self))
        if self.config.vuln_jwt:
            from vuln.jwt import JWTCheck
            checks.append(JWTCheck(self))
        if self.config.vuln_cors:
            from vuln.cors import CORSCheck
            checks.append(CORSCheck(self))
        if self.config.vuln_rate_limit:
            from vuln.rate_limit import RateLimitCheck
            checks.append(RateLimitCheck(self))
        if self.config.vuln_default_creds:
            from vuln.default_creds import DefaultCredsCheck
            checks.append(DefaultCredsCheck(self))
        if self.config.vuln_cve:
            from vuln.cve import CVEMatcher
            checks.append(CVEMatcher(self))

        total = len(checks)
        for i, chk in enumerate(checks, 1):
            if not self._running:
                break
            name = chk.__class__.__name__
            with LiveStatus(f"[{i}/{total}] {name}") as s:
                try:
                    chk.run()
                    s.count(len(self.findings.all()))
                except Exception as e:
                    s.extra(f"FAILED: {e}")

        self.target.add_timeline("vuln", "completed")
        self.results.append(PhaseResult("vuln", True))

        fc = len(self.findings.all())
        print(f"  {C.BOLD}VULN DONE:{C.RST} {fc} findings")

    def run_exploit(self):
        if not self.config.exploit_auto:
            return
        print(f"\n{C.BOLD}[*] EXPLOIT PHASE — {self.target.domain}{C.RST}")
        self.target.add_timeline("exploit", "started")

        with LiveStatus("Analyzing findings for exploitation") as s:
            from exploit.selector import ExploitSelector
            selector = ExploitSelector(self)
            selector.run()
            s.count(len(self.target.exploits))

        self.target.add_timeline("exploit", "completed")
        self.results.append(PhaseResult("exploit", True))

    def run_report(self):
        print(f"\n{C.BOLD}[*] REPORT PHASE{C.RST}")
        self.target.add_timeline("report", "started")

        if self.config.report_html:
            with LiveStatus("Generating HTML report") as s:
                from report.html import HTMLReport
                path = HTMLReport(self).generate()
                s.extra(path)

        if self.config.report_json:
            path = f"{self.config.output_dir}/{self.target.domain}_report.json"
            with LiveStatus("Generating JSON report") as s:
                self.target.to_json(path)
                s.extra(path)

        self.target.add_timeline("report", "completed")
        self.results.append(PhaseResult("report", True))

    def load_plugins(self, plugin_dir: str = "plugins"):
        if not os.path.isdir(plugin_dir):
            return
        sys.path.insert(0, os.path.abspath(plugin_dir))
        for fname in os.listdir(plugin_dir):
            if fname.endswith(".py") and not fname.startswith("_"):
                mod_name = fname[:-3]
                try:
                    mod = importlib.import_module(mod_name)
                    for _, obj in inspect.getmembers(mod, inspect.isclass):
                        if hasattr(obj, "is_phantom_plugin") and obj.is_phantom_plugin:
                            self._plugins.append(obj(self))
                            print(f"  [+] Loaded plugin: {obj.__name__}")
                except Exception as e:
                    print(f"  [!] Failed to load plugin {mod_name}: {e}")
