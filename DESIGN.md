# PHANTOM — Autonomous Python Pentest Tool

## Architecture Overview

PHANTOM is a modular, pipeline-based autonomous penetration testing framework.
Each phase is independent — run them together or standalone.

```
  ┌─────────────────────────────────────────────────────────────┐
  │                      PHANTOM ENGINE                         │
  │  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────┐     │
  │  │  RECON  │→ │  VULN    │→ │ EXPLOIT │→ │  REPORT  │     │
  │  │  Phase  │  │  Phase   │  │  Phase  │  │  Phase   │     │
  │  │    1    │  │    2     │  │    3    │  │    4     │     │
  │  └─────────┘  └──────────┘  └─────────┘  └──────────┘     │
  │       │              │            │             │           │
  │       ▼              ▼            ▼             ▼           │
  │  ┌──────────────────────────────────────────────────┐      │
  │  │                 TARGET OBJECT                     │      │
  │  │  (accumulates data through pipeline phases)       │      │
  │  └──────────────────────────────────────────────────┘      │
  │                                                             │
  │  ┌──────────────────────────────────────────────────┐      │
  │  │              TELEGRAM BOT (async)                 │      │
  │  │  real-time notifications at every phase           │      │
  │  └──────────────────────────────────────────────────┘      │
  └─────────────────────────────────────────────────────────────┘
```

---

## 1. Directory Structure

```
PHANTOM/
├── phantom.py                        # Entry point — CLI args, engine init
├── DESIGN.md                         # This file
├── requirements.txt                  # Dependencies (minimal — requests only)
│
├── config/
│   ├── __init__.py
│   ├── settings.py                   # Central config class (env vars, toml)
│   └── wordlists/
│       ├── subdomains.txt            # Top 10k subdomains
│       ├── dirs.txt                  # Top 5k directories
│       └── passwords.txt             # Top 1k passwords
│
├── core/
│   ├── __init__.py
│   ├── engine.py                     # PhantomEngine — orchestrator
│   ├── target.py                     # Target — data object for scan state
│   ├── findings.py                   # Finding, VulnerabilityFinding, etc.
│   ├── report.py                     # Report, TimelineEntry, Evidence
│   └── exceptions.py                 # Custom exception hierarchy
│
├── recon/
│   ├── __init__.py
│   ├── base.py                       # ReconModule ABC
│   ├── whois_dns.py                  # WHOIS, DNS records
│   ├── subdomain_enum.py             # crt.sh API + wordlist brute
│   ├── port_scanner.py               # Custom threaded TCP scanner
│   ├── tech_detect.py                # HTTP header/cookie analysis
│   ├── dir_brute.py                  # Directory/file brute force
│   ├── js_scraper.py                 # JS endpoint/secret extraction
│   └── dorker.py                     # Google dork URL generation
│
├── vuln/
│   ├── __init__.py
│   ├── base.py                       # VulnCheck ABC
│   ├── sqli.py                       # SQLi (time/error/boolean)
│   ├── xss.py                        # Reflected + stored XSS
│   ├── lfi_rfi.py                    # LFI/RFI path traversal
│   ├── ssrf.py                       # SSRF probe
│   ├── open_redirect.py              # Open redirect test
│   ├── idor.py                       # IDOR enumeration
│   ├── jwt_analyzer.py               # JWT decode/weak key
│   ├── cors.py                       # CORS misconfig
│   ├── rate_limit.py                 # Rate limiting absence
│   ├── default_creds.py              # Known default creds
│   └── cve_matcher.py                # Response fingerprint → CVE
│
├── exploit/
│   ├── __init__.py
│   ├── base.py                       # ExploitModule ABC
│   ├── selector.py                   # Auto-select best vuln
│   ├── payloads.py                   # Payload generation engine
│   ├── shell.py                      # Reverse shell / beacon
│   └── persistence.py                # Persistence mechanisms
│
├── report/
│   ├── __init__.py
│   ├── generator.py                  # Report builder → HTML
│   ├── evidence.py                   # Screenshot (text), response capture
│   └── templates/
│       └── report.html               # Jinja2-style HTML template
│
├── tg_bot/
│   ├── __init__.py
│   └── bot.py                        # Telegram bot client
│
├── plugins/
│   ├── __init__.py
│   └── loader.py                     # Dynamic plugin loader
│
└── utils/
    ├── __init__.py
    ├── network.py                    # Socket helpers, timeouts, resolvers
    ├── http.py                       # Requests wrapper (retry, proxy, UA rotation)
    ├── crypto.py                     # JWT decode, hash, random generation
    └── log.py                        # Colored logging setup
```

---

## 2. Class Hierarchy

### 2.1 Core Classes

```
Target
├── domain: str | None
├── url: str | None
├── ips: list[str]
├── subdomains: set[str]
├── open_ports: list[PortInfo]
├── tech_stack: dict[str, str]          # {nginx: 1.18.0, php: 7.4}
├── endpoints: list[str]
├── js_endpoints: list[str]
├── js_secrets: list[JsSecret]
├── dork_results: list[DorkResult]
├── directories: list[DirEntry]
├── findings: list[Finding]
├── vulnerabilities: list[VulnerabilityFinding]
├── exploit_results: list[ExploitResult]
├── timeline: list[TimelineEntry]
├── notes: dict[str, Any]
├── evidence: list[Evidence]
│
├── to_dict() -> dict
├── to_json() -> str
├── from_dict(data: dict) -> Target
├── merge(other: Target) -> None
└── summary() -> dict

PortInfo
├── port: int
├── state: str                # open/filtered/closed
├── service: str | None
├── banner: str | None
├── protocol: str             # tcp/udp
└── to_dict() -> dict

JsSecret
├── url: str
├── type: str                 # api_key, endpoint, jwt, aws_key, etc.
├── value: str
├── context: str              # surrounding JS snippet
├── confidence: float
└── to_dict() -> dict

Finding (base)
├── id: str                   # UUID
├── type: str                 # sql-injection, xss, etc.
├── severity: str             # critical/high/medium/low/info
├── confidence: float         # 0.0 - 1.0
├── description: str
├── details: dict
├── timestamp: datetime
└── to_dict() -> dict

VulnerabilityFinding(Finding)
├── endpoint: str
├── parameter: str | None
├── payload: str | None
├── proof: str                # response excerpt, timing delta, etc.
├── poc: str                  # reproducible PoC curl command or URL
├── cve_id: str | None
├── cvss_score: float | None
└── to_dict() -> dict

ExploitResult
├── vulnerability: VulnerabilityFinding
├── success: bool
├── shell_type: str | None    # reverse, bind, beacon
├── session_id: str | None
├── output: str | None
├── persistence: bool
├── timestamp: datetime
└── to_dict() -> dict

TimelineEntry
├── timestamp: datetime
├── phase: str                # recon/vuln/exploit/report
├── module: str               # port_scanner, sqli, etc.
├── action: str               # description
├── status: str               # running/success/failed/skipped
├── duration: float           # seconds
└── to_dict() -> dict

Evidence
├── type: str                 # response_body, headers, screenshot_text, log
├── label: str
├── content: str
├── finding_id: str | None
└── to_dict() -> dict

Report
├── target: Target
├── start_time: datetime
├── end_time: datetime
├── duration: float
├── summary: dict
├── to_html() -> str
├── to_json() -> str
└── save(path: str) -> str
```

### 2.2 Module Base Classes

```
ReconModule (ABC)
├── name: str
├── description: str
├── depends_on: list[str]     # other recon modules required first
├── abstract run(target: Target, config: Settings) -> Target
└── validate_target(target: Target) -> bool

VulnCheck (ABC)
├── name: str
├── description: str
├── severity: str
├── requires: list[str]       # e.g., ['open_ports', 'endpoints']
├── abstract check(target: Target, config: Settings) -> list[VulnerabilityFinding]
└── validate_target(target: Target) -> bool

ExploitModule (ABC)
├── name: str
├── description: str
├── supported_vulns: list[str]
├── abstract exploit(target: Target, vuln: VulnerabilityFinding, config: Settings) -> ExploitResult
├── abstract validate(vuln: VulnerabilityFinding) -> bool
└── cleanup() -> None
```

### 2.3 Engine Classes

```
PhantomEngine
├── config: Settings
├── recon_modules: dict[str, ReconModule]
├── vuln_modules: dict[str, VulnCheck]
├── exploit_modules: dict[str, ExploitModule]
├── bot: TelegramBot | None
├── target: Target
├── report: Report
│
├── run_all(domain: str) -> Report
├── run_phase(phase: str, target: Target) -> Target
├── run_recon(target: Target) -> Target
├── run_vuln(target: Target) -> Target
├── run_exploit(target: Target) -> Target
├── run_report(target: Target) -> Report
├── register_recon(module: ReconModule) -> None
├── register_vuln(module: VulnCheck) -> None
├── register_exploit(module: ExploitModule) -> None
├── load_plugins(directory: str) -> None
├── export_target(path: str) -> None
├── import_target(path: str) -> Target
└── _notify(message: str) -> None

ExploitSelector
├── config: Settings
├── select(target: Target) -> VulnerabilityFinding | None
├── rank_vulns(vulns: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]
└── _score(vuln: VulnerabilityFinding) -> float
```

### 2.4 Utility Classes

```
HttpClient
├── session: requests.Session
├── config: Settings
├── get(url, params, headers, timeout) -> Response
├── post(url, data, json, headers, timeout) -> Response
├── request(method, url, **kwargs) -> Response
├── _rotate_user_agent() -> None
├── _handle_rate_limit(response) -> None
└── close() -> None

TelegramBot
├── token: str
├── chat_id: str
├── running: bool
├── start() -> None
├── stop() -> None
├── send_message(text: str) -> None
├── send_phase_update(phase: str, status: str, details: str) -> None
├── send_finding(finding: VulnerabilityFinding) -> None
├── send_report_summary(report: Report) -> None
├── _poll_loop() -> None
└── _dispatch_command(cmd: dict) -> None

PluginLoader
├── plugin_dirs: list[str]
├── loaded_modules: dict
├── discover(directory: str) -> list[str]
├── load(module_path: str) -> ReconModule | VulnCheck | ExploitModule
├── load_all(directory: str) -> list[ReconModule | VulnCheck | ExploitModule]
├── validate_module(module: Any) -> bool
└── _import_path(path: str) -> str

Settings
├── target: TargetSettings
├── recon: ReconSettings
├── vuln: VulnSettings
├── exploit: ExploitSettings
├── report: ReportSettings
├── telegram: TelegramSettings
├── proxy: ProxySettings
├── rate_limit: RateLimitSettings
│
├── from_file(path: str) -> Settings
├── from_env() -> Settings
├── to_file(path: str) -> None
├── to_dict() -> dict
└── merge(overrides: dict) -> Settings
```

---

## 3. Module Design — Public APIs

### 3.1 Recon Modules

#### `recon/whois_dns.py`
```python
class WhoisDnsModule(ReconModule):
    name = "whois_dns"
    description = "WHOIS lookup + DNS record enumeration"
    depends_on = []

    def run(self, target: Target, config: Settings) -> Target:
        """Populates target.ips and adds DNS records to target.notes['dns'].
        
        Queries: A, AAAA, MX, NS, TXT, CNAME, SOA.
        Falls back to socket.getaddrinfo if dnspython not available.
        Uses subprocess + whois CLI if python-whois not available.
        """
```

#### `recon/subdomain_enum.py`
```python
class SubdomainEnum(ReconModule):
    name = "subdomain_enum"
    description = "Subdomain enumeration via crt.sh + wordlist brute force"
    depends_on = []

    def run(self, target: Target, config: Settings) -> Target:
        """Populates target.subdomains.
        
        1. Query crt.sh API: https://crt.sh/?q=%25.{domain}&output=json
        2. Brute-force common subdomains from wordlist
        3. Resolve each found subdomain → add to target.ips
        """
```

#### `recon/port_scanner.py`
```python
class PortScanner(ReconModule):
    name = "port_scanner"
    description = "Multithreaded TCP port scanner (pure sockets)"
    depends_on = []  # can run if target.ips is populated

    def run(self, target: Target, config: Settings) -> Target:
        """Populates target.open_ports.
        
        Uses raw sockets with SYN/custom TCP connect scan.
        Configurable: ports range, threads, timeout, service detection via banner grab.
        """
    
    def _scan_port(self, ip: str, port: int, timeout: float) -> PortInfo | None:
        """Single TCP connect attempt. Returns PortInfo if open."""
    
    def _banner_grab(self, ip: str, port: int, timeout: float) -> str | None:
        """Send probe bytes, read up to 1KB banner."""
    
    def _detect_service(self, port: int, banner: str | None) -> str:
        """Map port number + banner → service name."""
```

#### `recon/tech_detect.py`
```python
class TechDetect(ReconModule):
    name = "tech_detect"
    description = "Technology stack detection via HTTP responses"
    depends_on = []  # needs at least one web port

    def run(self, target: Target, config: Settings) -> Target:
        """Populates target.tech_stack and target.endpoints.
        
        Sends requests to each open web port.
        Analyzes: Server header, X-Powered-By, Set-Cookie patterns,
        response body signatures (generator meta tags, specific paths).
        """
    
    def _fingerprint(self, response: requests.Response) -> dict[str, str]:
        """Map response headers + body → tech stack dict."""
```

#### `recon/dir_brute.py`
```python
class DirBrute(ReconModule):
    name = "dir_brute"
    description = "Directory and file brute forcing"
    depends_on = ["tech_detect"]

    def run(self, target: Target, config: Settings) -> Target:
        """Populates target.directories.
        
        Threaded HTTP GET for each wordlist entry.
        Filters: status codes (200, 301, 302, 403, 401, 500).
        Detects: false positives via response size/content similarity.
        """
    
    def _is_false_positive(self, response: requests.Response) -> bool:
        """Compare response to 404 baseline, detect wildcard."""
```

#### `recon/js_scraper.py`
```python
class JsScraper(ReconModule):
    name = "js_scraper"
    description = "JavaScript scraping for endpoints, secrets, API keys"
    depends_on = ["tech_detect"]

    def run(self, target: Target, config: Settings) -> Target:
        """Populates target.js_endpoints and target.js_secrets.
        
        1. Find all <script src="..."> from known pages
        2. Download each JS file
        3. Regex scan for:
           - API endpoints (/api/v1/, /graphql, etc.)
           - API keys / secrets (aws_key, stripe, jwt, etc.)
           - Internal paths
           - Firebase URLs
           - Hardcoded tokens
        """
    
    def _download_js(self, js_url: str) -> str | None:
        """Fetch and cache JS file content."""
    
    def _scan_js(self, content: str, url: str) -> tuple[list[str], list[JsSecret]]:
        """Extract endpoints + secrets from JS content."""
```

#### `recon/dorker.py`
```python
class Dorker(ReconModule):
    name = "dorker"
    description = "Google dork URL generation and testing"
    depends_on = []

    def run(self, target: Target, config: Settings) -> Target:
        """Populates target.dork_results.
        
        Generates dork URLs (does not actually scrape Google — just builds
        the search URLs for manual review or automated check).
        Tests if dork patterns reveal accessible paths.
        """
    
    def _generate_dorks(self, domain: str) -> list[str]:
        """Generate dork query strings for the target domain."""
    
    def _test_dork(self, dork_url: str) -> DorkResult | None:
        """Check if dork returns results (via requests to custom search or cached)."""
```

### 3.2 Vulnerability Modules

#### `vuln/sqli.py`
```python
class SQLiDetector(VulnCheck):
    name = "sqli"
    description = "SQL injection detection (time, error, boolean blind)"
    severity = "critical"
    requires = ["endpoints"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Test each parameter on each endpoint for SQL injection.
        
        Three detection methods:
        1. Error-based: inject ' and look for SQL errors in response
        2. Boolean blind: compare responses to true/false conditions
        3. Time-based: SLEEP/BENCHMARK payloads, measure response time
        """
    
    def _test_error_based(self, url: str, param: str, base_resp: str) -> VulnerabilityFinding | None:
        """Inject SQL syntax errors, look for DB error messages."""
    
    def _test_boolean_blind(self, url: str, param: str, base_resp: str) -> VulnerabilityFinding | None:
        """Compare response for '1=1' vs '1=2' conditions."""
    
    def _test_time_based(self, url: str, param: str, base_time: float) -> VulnerabilityFinding | None:
        """Test SLEEP(5) payloads, detect time delays."""
```

#### `vuln/xss.py`
```python
class XSSDetector(VulnCheck):
    name = "xss"
    description = "Reflected and stored XSS detection"
    severity = "high"
    requires = ["endpoints"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Test parameters for XSS vulnerabilities.
        
        Payload types: <script>alert(1)</script>, <img src=x onerror=alert(1)>,
        polyglot payloads, event handler attributes.
        Detects: reflected (payload in response), stored (check other pages).
        """
```

#### `vuln/lfi_rfi.py`
```python
class LfiRfiCheck(VulnCheck):
    name = "lfi_rfi"
    description = "Local/Remote File Inclusion checks"
    severity = "critical"
    requires = ["endpoints"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Test path traversal in file-related parameters.
        
        LFI: /etc/passwd, /windows/win.ini, php://filter/base64
        RFI: remote URL inclusion in include() parameters
        """
```

#### `vuln/ssrf.py`
```python
class SsrfCheck(VulnCheck):
    name = "ssrf"
    description = "Server-Side Request Forgery checks"
    severity = "high"
    requires = ["endpoints"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Probe parameters that fetch external URLs.
        
        Sends requests to collab-ready URL patterns.
        Detects: URL parameter reflection, metadata endpoints.
        """
```

#### `vuln/open_redirect.py`
```python
class OpenRedirectCheck(VulnCheck):
    name = "open_redirect"
    description = "Open redirect vulnerability detection"
    severity = "medium"
    requires = ["endpoints"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Test redirect parameters for open redirects.
        
        Payloads: //evil.com, https://evil.com, @evil.com, \%2eevil.com
        Detects: Location header matching external domains.
        """
```

#### `vuln/idor.py`
```python
class IdorCheck(VulnCheck):
    name = "idor"
    description = "Insecure Direct Object Reference tests"
    severity = "high"
    requires = ["endpoints"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Enumerate sequential IDs in URL paths/parameters.
        
        Pattern detection: /user/1, ?id=100, /profile/42
        Tests: increment/decrement IDs, check for unauthorized access.
        """
```

#### `vuln/jwt_analyzer.py`
```python
class JwtAnalyzer(VulnCheck):
    name = "jwt_analyzer"
    description = "JWT decoding and security analysis"
    severity = "high"
    requires = []  # scans all collected data for JWT tokens

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Decode and analyze all discovered JWT tokens.
        
        Checks: alg=none, weak HMAC secret, expired, malformed.
        Extracts: header, payload, signature status.
        """
    
    def _find_tokens(self, target: Target) -> list[str]:
        """Search cookies, headers, JS content for JWT tokens."""
    
    def _decode_jwt(self, token: str) -> dict | None:
        """Base64 decode header+payload without verification."""
    
    def _crack_secret(self, token: str, wordlist: list[str]) -> str | None:
        """Try common secrets against HMAC JWT."""
```

#### `vuln/cors.py`
```python
class CorsCheck(VulnCheck):
    name = "cors"
    description = "CORS misconfiguration detection"
    severity = "medium"
    requires = ["endpoints"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Test CORS headers for misconfigurations.
        
        Checks: Access-Control-Allow-Origin: *, null origin reflection,
        weak origin reflection, preflight cache abuse.
        """
```

#### `vuln/rate_limit.py`
```python
class RateLimitCheck(VulnCheck):
    name = "rate_limit"
    description = "Rate limiting absence detection"
    severity = "medium"
    requires = ["endpoints"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Rapid-fire requests to detect missing rate limits.
        
        Sends N identical requests in burst.
        Checks: 429 status, Retry-After header, blocking after threshold.
        """
```

#### `vuln/default_creds.py`
```python
class DefaultCredsCheck(VulnCheck):
    name = "default_creds"
    description = "Default credentials testing"
    severity = "critical"
    requires = ["open_ports", "tech_detect"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Test known default credentials for detected services.
        
        Matches tech_stack services against default cred database.
        Attempts: admin:admin, root:root, admin:password, etc.
        Targets: login forms, basic auth, API endpoints.
        """
```

#### `vuln/cve_matcher.py`
```python
class CveMatcher(VulnCheck):
    name = "cve_matcher"
    description = "Known CVE matching via response fingerprinting"
    severity = "high"
    requires = ["tech_detect"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Match tech stack versions against known CVEs.
        
        Built-in CVE database (version ranges, fingerprints).
        Matches: server version → known vulns, JS library version → CVEs.
        """
    
    def _load_cve_db(self) -> list[dict]:
        """Load built-in CVE fingerprint database."""
    
    def _match_version(self, software: str, version: str) -> list[dict]:
        """Find CVEs matching software + version range."""
```

### 3.3 Exploit Modules

#### `exploit/payloads.py`
```python
class PayloadGenerator:
    """Generates exploit payloads based on vulnerability type."""
    
    def for_sqli(self, vuln: VulnerabilityFinding) -> str:
        """Generate SQLi payload (union select, data extraction)."""
    
    def for_xss(self, vuln: VulnerabilityFinding) -> str:
        """Generate XSS payload (cookie steal, keylogger, beacon)."""
    
    def for_lfi(self, vuln: VulnerabilityFinding) -> str:
        """Generate LFI payload (php wrapper, log poisoning)."""
    
    def for_rce(self, vuln: VulnerabilityFinding) -> str:
        """Generate RCE payload (reverse shell one-liner)."""
    
    def for_open_redirect(self, vuln: VulnerabilityFinding) -> str:
        """Generate redirect payload (phishing URL)."""
```

#### `exploit/selector.py`
```python
class ExploitSelector:
    """Auto-selects the best vulnerability to exploit."""
    
    def select(self, target: Target) -> VulnerabilityFinding | None:
        """Pick the most exploitable vuln based on scoring."""
    
    def rank_vulns(self, vulns: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        """Score and sort vulnerabilities by exploitability.
        
        Scoring factors:
        - Severity (critical=100, high=70, medium=40, low=10)
        - Confidence (0.0 - 1.0 multiplier)
        - Exploitability (RCE > file read > data exposure > redirect)
        - Has PoC (y/n, 1.5x multiplier)
        """
    
    def _score(self, vuln: VulnerabilityFinding) -> float:
        """Calculate single vuln exploitability score."""
```

#### `exploit/shell.py`
```python
class ShellManager:
    """Manages reverse shell / beacon connections."""
    
    def start_listener(self, lhost: str, lport: int, protocol: str = "reverse") -> None:
        """Start listener for incoming connection (threaded)."""
    
    def send_reverse_shell(self, target_url: str, vuln: VulnerabilityFinding, lhost: str, lport: int) -> bool:
        """Inject and trigger reverse shell payload."""
    
    def send_beacon(self, target_url: str, vuln: VulnerabilityFinding, c2_url: str) -> bool:
        """Deploy beacon callback to C2 infrastructure."""
    
    def interact(self, session_id: str) -> str:
        """Send command to active session, get output."""
    
    def close_session(self, session_id: str) -> None:
        """Terminate session cleanly."""
```

#### `exploit/persistence.py`
```python
class PersistenceManager:
    """Manages post-exploitation persistence."""
    
    def apply(self, shell, vuln: VulnerabilityFinding, config: Settings) -> bool:
        """Apply persistence via detected OS.
        
        Linux: cron, ssh authorized_keys, systemd service
        Windows: registry Run key, schtasks, WMI startup
        Web: webshell upload, backdoor in existing page
        """
    
    def install_webshell(self, url: str, vuln: VulnerabilityFinding) -> str | None:
        """Upload/install web shell via file upload or LFI."""
```

### 3.4 Report Module

#### `report/generator.py`
```python
class ReportGenerator:
    """Generates comprehensive HTML reports."""
    
    def generate(self, report: Report, target: Target) -> str:
        """Build complete HTML report from template."""
    
    def _build_timeline(self, entries: list[TimelineEntry]) -> str:
        """Render timeline as HTML."""
    
    def _build_findings_table(self, findings: list[VulnerabilityFinding]) -> str:
        """Render findings as structured HTML table."""
    
    def _build_evidence(self, evidence: list[Evidence]) -> str:
        """Render collected evidence."""
    
    def _build_recon_summary(self, target: Target) -> str:
        """Render recon data summary."""
    
    def save(self, html: str, output_path: str) -> str:
        """Write HTML to file, return path."""
```

#### `report/evidence.py`
```python
class EvidenceCollector:
    """Captures evidence for report."""
    
    def capture_response(self, url: str, response: requests.Response) -> Evidence:
        """Save full response details as evidence."""
    
    def capture_text_screenshot(self, text: str, label: str) -> Evidence:
        """Save text 'screenshot' (response body, console output)."""
    
    def capture_diff(self, original: str, payload: str, result: str) -> Evidence:
        """Show before/after for payload testing."""
```

### 3.5 Telegram Bot

#### `tg_bot/bot.py`
```python
class TelegramBot:
    """Asynchronous Telegram bot for real-time scan updates."""
    
    def __init__(self, token: str, chat_id: str):
        """Initialize with bot token and target chat ID."""
    
    def start(self) -> None:
        """Start polling thread for incoming commands."""
    
    def stop(self) -> None:
        """Stop polling thread gracefully."""
    
    def send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        """Send text message to configured chat."""
    
    def send_phase_update(self, phase: str, status: str, details: str = "") -> None:
        """Send formatted phase status update."""
    
    def send_finding(self, finding: VulnerabilityFinding) -> None:
        """Send formatted vulnerability finding alert."""
    
    def send_report_summary(self, report: Report) -> None:
        """Send executive summary of completed scan."""
    
    def _poll_loop(self) -> None:
        """Background thread: poll for commands (stop, status, etc.)."""
    
    def _dispatch_command(self, cmd: dict) -> None:
        """Handle incoming bot command from user."""
```

---

## 4. Data Flow

### 4.1 Standard Pipeline Flow

```
INPUT: domain or URL
    │
    ▼
┌──────────────────────────────────────────────────────────┐
│ PHASE 1: RECON                                           │
│                                                          │
│  WhoisDnsModule                                          │
│    → target.ips = ['192.0.2.1']                          │
│    → target.notes['dns'] = {mx: [...], ns: [...], ...}   │
│                                                          │
│  SubdomainEnum                                           │
│    → target.subdomains = {'admin.example.com', ...}      │
│    → target.ips updated with resolved addresses          │
│                                                          │
│  PortScanner                                             │
│    → target.open_ports = [                               │
│        PortInfo(80, 'open', 'http', ...),                │
│        PortInfo(443, 'open', 'https', ...),              │
│        PortInfo(22, 'open', 'ssh', ...),                 │
│      ]                                                    │
│                                                          │
│  TechDetect                                              │
│    → target.tech_stack = {'nginx': '1.18.0', ...}        │
│    → target.endpoints = ['https://example.com/login']    │
│                                                          │
│  DirBrute                                                │
│    → target.directories = [                              │
│        DirEntry('/admin', 200),                          │
│        DirEntry('/backup', 403),                         │
│      ]                                                    │
│                                                          │
│  JsScraper                                               │
│    → target.js_endpoints = ['/api/v1/users']             │
│    → target.js_secrets = [JsSecret(...)]                  │
│                                                          │
│  Dorker                                                  │
│    → target.dork_results = [DorkResult(...)]              │
│                                                          │
│  (Timeline entries added for each step)                  │
└──────────────────────┬───────────────────────────────────┘
                       │ Target object passed forward
                       ▼
┌──────────────────────────────────────────────────────────┐
│ PHASE 2: VULNERABILITY DETECTION                         │
│                                                          │
│  For each VulnCheck that has its requirements met:       │
│                                                          │
│  SQLiDetector → list[VulnerabilityFinding]               │
│    appended to target.vulnerabilities                    │
│                                                          │
│  XSSDetector → list[VulnerabilityFinding]                │
│    appended to target.vulnerabilities                    │
│                                                          │
│  LfiRfiCheck → list[VulnerabilityFinding]                │
│    appended to target.vulnerabilities                    │
│                                                          │
│  ... (all other checks) ...                              │
│                                                          │
│  CveMatcher → list[VulnerabilityFinding]                 │
│    appended to target.vulnerabilities                    │
│                                                          │
│  (Timeline entries added for each check)                 │
└──────────────────────┬───────────────────────────────────┘
                       │ Target with findings passed forward
                       ▼
┌──────────────────────────────────────────────────────────┐
│ PHASE 3: EXPLOIT                                         │
│                                                          │
│  ExploitSelector.select(target)                          │
│    → picks best VulnerabilityFinding                     │
│    → if None: skip (no exploitable vuln found)           │
│                                                          │
│  PayloadGenerator.for_<type>(vuln)                       │
│    → generates appropriate payload                       │
│                                                          │
│  ShellManager.send_reverse_shell(...)                    │
│    → fires exploit, gets shell                           │
│    → OR: sends beacon to C2                              │
│                                                          │
│  PersistenceManager.apply(...)                           │
│    → installs persistence mechanism                      │
│                                                          │
│  → target.exploit_results appended                      │
│  → target.timeline updated                              │
└──────────────────────┬───────────────────────────────────┘
                       │ Final target state
                       ▼
┌──────────────────────────────────────────────────────────┐
│ PHASE 4: REPORT                                          │
│                                                          │
│  EvidenceCollector captures proof                         │
│  ReportGenerator builds HTML                             │
│  → ./output/report_*.html                                 │
│                                                          │
│  TelegramBot.send_report_summary(report)                 │
│    → sends executive summary to Telegram                 │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Inter-Phase Data

No database — data lives in the `Target` object in memory. The `Target` can be serialized to/from JSON for:
- Pausing/resuming scans
- Sharing data between distributed scanners
- Import/export between phases

When each phase runs, modules read from and write to the **same Target object**. The engine manages the ordering and dependency resolution.

### 4.3 Side-Channel: Telegram

The Telegram bot runs in a background thread and can:
1. Send status updates when each phase starts/completes
2. Alert on critical findings immediately
3. Accept commands (stop, status, pause)
4. Send final report summary

---

## 5. Plugin System

### 5.1 Architecture

```
plugins/
├── __init__.py
└── loader.py         ← Plugin discovery + loading logic

Any directory can be scanned for plugins:
  engine.load_plugins('/path/to/custom/plugins')
```

### 5.2 How to Add a New Vulnerability Check

A plugin is any Python file that exports a class inheriting from `VulnCheck` (or `ReconModule` / `ExploitModule`).

**Example: Adding an SSTI detection plugin**

```python
# plugins/custom/ssti.py
from vuln.base import VulnCheck
from core.findings import VulnerabilityFinding
from core.target import Target
from config.settings import Settings

class SSTIDetector(VulnCheck):
    name = "ssti"
    description = "Server-Side Template Injection detection"
    severity = "critical"
    requires = ["endpoints"]

    def check(self, target: Target, config: Settings) -> list[VulnerabilityFinding]:
        """Test endpoints for SSTI vulnerabilities."""
        findings = []
        for endpoint in target.endpoints:
            # Test {{7*7}} payloads, detect '49' in response
            # Test ${7*7}, #{7*7}, etc.
            pass
        return findings
```

### 5.3 Registration Discovery

```python
# Plugin auto-discovery
loader = PluginLoader()
modules = loader.load_all('/path/to/plugins')

for module in modules:
    if isinstance(module, ReconModule):
        engine.register_recon(module)
    elif isinstance(module, VulnCheck):
        engine.register_vuln(module)
    elif isinstance(module, ExploitModule):
        engine.register_exploit(module)
```

### 5.4 Plugin Contract

Every plugin module MUST:
1. Inherit from `ReconModule`, `VulnCheck`, or `ExploitModule` ABC
2. Set `name`, `description`, `severity` (vuln only), `requires` class attributes
3. Implement the abstract `run()` / `check()` / `exploit()` method
4. Return the correct type (`Target` / `list[VulnerabilityFinding]` / `ExploitResult`)
5. Be a single `.py` file (no sub-packages for simplicity)

### 5.5 Built-in Plugin Directory

The `plugins/` directory in the project root is always scanned on startup.
Users can also point to external directories via config:

```toml
[plugins]
directory = "/opt/phantom_plugins"
auto_load = true
```

---

## 6. Configuration System

### 6.1 Settings Hierarchy

```
1. Default settings (hardcoded in settings.py)
2. Config file (TOML in ~/.config/phantom/config.toml or --config path)
3. Environment variables (PHANTOM_* prefix)
4. CLI arguments (highest priority)
```

### 6.2 Config File Format (TOML)

```toml
[target]
domain = ""
url = ""
ip = ""
ports = "21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,27017"
rate_limit_delay = 0.1
timeout = 5

[recon]
whois = true
dns = true
subdomain_enum = true
port_scan = true
tech_detect = true
dir_brute = true
js_scraper = true
dorker = false
threads = 50
subdomain_wordlist = ""
dir_wordlist = ""

[vuln]
sqli = true
xss = true
lfi_rfi = true
ssrf = true
open_redirect = true
idor = true
jwt_analyzer = true
cors = true
rate_limit = true
default_creds = true
cve_matcher = true

[exploit]
auto_exploit = false
lhost = ""
lport = 4444
payload_type = "reverse"
c2_url = ""

[report]
output_dir = "./output"
format = "html"
include_evidence = true

[telegram]
enabled = false
token = ""
chat_id = ""

[proxy]
http = ""
https = ""
socks5 = ""

[rate_limit]
max_requests_per_second = 10
burst_size = 5
cooldown_seconds = 60

[plugins]
directory = ""
auto_load = true
```

### 6.3 Environment Variables

```bash
export PHANTOM_TARGET_DOMAIN="example.com"
export PHANTOM_PORT_RANGE="1-10000"
export PHANTOM_THREADS=100
export PHANTOM_TELEGRAM_TOKEN="bot123:abc"
export PHANTOM_TELEGRAM_CHAT_ID="-1001234567890"
export PHANTOM_PROXY_HTTP="http://127.0.0.1:8080"
export PHANTOM_AUTO_EXPLOIT="true"
export PHANTOM_LHOST="192.168.1.100"
export PHANTOM_LPORT=4444
```

### 6.4 Settings Class Design

```python
@dataclass
class TargetSettings:
    domain: str = ""
    url: str = ""
    ip: str = ""
    ports: str = "21,22,23,25,53,80,110,143,443,445,993,995,1433..."
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
    payload_type: str = "reverse"
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

class Settings:
    target: TargetSettings
    recon: ReconSettings
    vuln: VulnSettings
    exploit: ExploitSettings
    report: ReportSettings
    telegram: TelegramSettings
    proxy: ProxySettings
    rate_limit: RateLimitSettings
    plugins: PluginSettings

    @classmethod
    def from_file(cls, path: str) -> 'Settings':
        """Load settings from TOML file."""

    @classmethod
    def from_env(cls) -> 'Settings':
        """Load settings from PHANTOM_* environment variables."""

    @classmethod
    def default(cls) -> 'Settings':
        """Return default settings."""

    def to_dict(self) -> dict:
        """Serialize to dict."""

    def merge(self, overrides: dict) -> 'Settings':
        """Override with CLI arguments."""
```

---

## 7. Entry Point

```python
# phantom.py

#!/usr/bin/env python3
"""
PHANTOM — Autonomous Python Penetration Testing Tool

Usage:
    python phantom.py example.com
    python phantom.py http://example.com --recon-only
    python phantom.py target.json --import
    python phantom.py --config custom.toml example.com
    python phantom.py --phase vuln --import target.json --export report.json
"""

def main():
    parser = argparse.ArgumentParser(description="PHANTOM — Autonomous Pentest Tool")
    parser.add_argument("target", nargs="?", help="Domain or URL to test")
    parser.add_argument("--config", "-c", help="Path to TOML config file")
    parser.add_argument("--phase", choices=["recon", "vuln", "exploit", "report", "all"],
                        default="all", help="Run specific phase only")
    parser.add_argument("--import", dest="import_path", help="Import target JSON")
    parser.add_argument("--export", help="Export target JSON after phase")
    parser.add_argument("--recon-only", action="store_true", help="Stop after recon")
    parser.add_argument("--vuln-only", action="store_true", help="Stop after vuln")
    parser.add_argument("--auto-exploit", action="store_true", help="Enable exploitation")
    parser.add_argument("--lhost", help="Listener IP for reverse shells")
    parser.add_argument("--lport", type=int, help="Listener port for reverse shells")
    parser.add_argument("--threads", type=int, help="Thread count for scans")
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds")
    parser.add_argument("--proxy", help="HTTP proxy URL")
    parser.add_argument("--output", "-o", default="./output", help="Output directory")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress stdout")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version="PHANTOM 1.0.0")

    args = parser.parse_args()
    
    # 1. Load config
    config = Settings.from_env()
    if args.config:
        config = config.merge(Settings.from_file(args.config))
    config = config.merge(vars(args))
    
    # 2. Setup logging
    logger = setup_logger(config)
    
    # 3. Create engine
    engine = PhantomEngine(config)
    
    # 4. Setup Telegram bot
    if config.telegram.enabled:
        bot = TelegramBot(config.telegram.token, config.telegram.chat_id)
        engine.bot = bot
        bot.start()
    
    # 5. Load target
    if args.import_path:
        target = Target.from_file(args.import_path)
    else:
        target = Target(domain=args.target)
    
    # 6. Run
    report = engine.run_phase(args.phase, target)
    
    # 7. Export
    if args.export:
        target.to_file(args.export)
    
    # 8. Cleanup
    if engine.bot:
        engine.bot.stop()

if __name__ == "__main__":
    main()
```

---

## 8. Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Stdlib vs deps** | Pure Python3 + `requests` only | Minimize attack surface, no npm/Cargo hell, easy deploy |
| **Data persistence** | In-memory Target + JSON export | No DB setup, easy to debug, phase-independent |
| **Threading model** | threading + queue | Simple, good enough for I/O-bound scans |
| **Plugin discovery** | File-system scan + ABC check | No registration ceremony, drop file = new module |
| **Config format** | TOML | Human-readable, Python stdlib-like, better than YAML |
| **Scan modes** | Phase-independent | Run recon on Monday, vuln on Tuesday — import/export between |
| **Telegram** | Thread-based polling | Simple, no asyncio dependency, good enough for updates |
| **Timeout handling** | socket timeout + signal | Avoid hanging scans on dead hosts |
| **Report format** | Pure HTML (no JS deps) | Self-contained, opens anywhere, can be emailed |

---

## 9. OPSEC Considerations (from Shadow)

1. **Rate limiting**: Built-in delays between requests (configurable). Avoids WAF triggers.
2. **User-agent rotation**: HttpClient rotates through a pool of real browser UAs.
3. **Proxy chain**: Supports HTTP/HTTPS/SOCKS5 proxies for IP obfuscation.
4. **Tor support**: SOCKS5 proxy can point to Tor (127.0.0.1:9050).
5. **No persistence logs**: Scan state is in-memory; JSON exports are opt-in.
6. **Telegram over HTTPS**: Bot API is TLS-encrypted by default.
7. **Modular = compartmentalized**: Each phase runs independently. No cross-contamination.
8. **Default creds**: Tested against login forms that exist. No brute force of non-existent services.

---

## 10. Future Expansion Points

- **WebSocket checks** (add to vuln module)
- **GraphQL introspection** (add to recon + vuln)
- **Cloud metadata enumeration** (add to recon)
- **Container escape checks** (add to exploit)
- **Active Directory checks** (new phase module)
- **API fuzzing** (add to vuln)
- **Report formats** (PDF via weasyprint, JSON for tooling)
- **Distributed scanning** (Target JSON + multi-engine coordination)
- **Web UI** (Flask dashboard for real-time visualization)

---

*Design by Shadow. Built for Musawir. PHANTOM is yours, bro.*
