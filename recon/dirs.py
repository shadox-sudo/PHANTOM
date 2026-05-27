"""
PHANTOM — Directory Brute-Forcer Module
Discovers hidden paths on web servers using threaded HTTP GET requests.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.http_client import request


class DirBrute:
    """Directory and file brute-forcing with status code filtering."""

    name = "dirs"
    description = "Directory brute-force discovery"

    # Built-in wordlist (~60 common paths)
    BUILTIN_WORDLIST = [
        "admin", "administrator", "backup", "backups", "bak", "wp-admin",
        "wp-content", "wp-includes", "wp-login.php", "wp-json",
        ".git", ".git/config", ".gitignore", ".svn", ".svn/entries",
        ".env", ".env.example", ".env.production", ".env.local",
        "config", "config.php", "configuration", "config.json",
        "database", "db", "sql", "mysql", "phpmyadmin", "pma",
        "adminer.php", "api", "api/v1", "api/v2", "graphql",
        "swagger", "swagger-ui", "swagger.json", "api-docs",
        "robots.txt", "sitemap.xml", "sitemap.xml.gz",
        "crossdomain.xml", "clientaccesspolicy.xml",
        ".htaccess", ".htpasswd", "login", "dashboard",
        "console", "debug", "test", "tests", "testing",
        "uploads", "files", "images", "img", "assets", "static",
        "vendor", "node_modules", "src", "dist", "build",
        "index.php", "index.html", "default.aspx",
        "shell.php", "cmd.php", "info.php", "phpinfo.php",
        "server-status", "server-info", "status",
        "manager", "management", "monitor", "monitoring",
        "jenkins", "gitlab", "jira", "confluence", "wiki",
        "wordpress", "joomla", "drupal", "magento", "laravel",
        "cgi-bin", "cgi-bin/", "cpanel", "whm", "plesk",
        "webdav", "owa", "exchange", "autodiscover",
        "remote", "remote.php", "remote/login",
        "error", "error_log", "errors", "logs", "log",
        "tmp", "temp", "cache", "session", "sessions",
        "install", "setup", "wizard", "upgrade", "migrate",
    ]

    INTERESTING_STATUSES = {200, 201, 204, 301, 302, 303, 307, 308,
                            401, 403, 405, 500, 502, 503}

    def __init__(self, engine):
        self.engine = engine
        self.target = engine.target
        self.config = engine.config

    def run(self):
        domain = self.target.domain
        if not domain:
            print("  [!] DirBrute: no domain set")
            return

        # Determine base URL from target info
        base_url = self._get_base_url()
        if not base_url:
            print("  [!] DirBrute: could not determine base URL")
            return

        # Load wordlist
        wordlist = self._load_wordlist()
        if not wordlist:
            print("  [!] DirBrute: empty wordlist")
            return

        print(f"[*] Directory brute-force on {base_url}")
        print(f"  [*] {len(wordlist)} paths, {self.config.threads} threads")

        threads = min(self.config.threads, len(wordlist))
        found = []
        lock = threading.Lock()
        import threading

        def check_path(path: str):
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            try:
                resp = request(
                    url, method="GET",
                    timeout=self.config.timeout,
                    headers={"User-Agent": self.config.user_agent},
                )
                if resp.status in self.INTERESTING_STATUSES:
                    redirect = resp.headers.get("location", "")
                    entry = {
                        "url": url,
                        "status": resp.status,
                        "size": len(resp.body) if resp.body else 0,
                        "redirect": redirect,
                    }
                    with lock:
                        found.append(entry)
                    loc = f" -> {redirect[:60]}" if redirect else ""
                    print(f"    {resp.status}  {url}  [{len(resp.body or ''):,}b]{loc}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(check_path, w) for w in wordlist]
            for _ in as_completed(futures):
                pass

        self.target.directories = found
        self.target.add_timeline("recon", "dir_brute",
                                 f"{len(found)} paths found")
        print(f"  [*] Directory brute-force done: {len(found)} paths discovered")

    def _get_base_url(self) -> str:
        """Build a base URL from target data."""
        domain = self.target.domain

        # Use IP with port from first web port if available
        if self.target.ports:
            for p in self.target.ports:
                if p.state == "open" and p.port in (80, 443, 8080, 8443, 8000, 8888):
                    ip = self.target.ip or domain
                    scheme = "https" if p.port in (443, 8443) else "http"
                    if p.port in (80, 443):
                        return f"{scheme}://{ip}/"
                    return f"{scheme}://{ip}:{p.port}/"

        # Fallback: try domain
        return f"https://{domain}/"

    def _load_wordlist(self) -> list:
        """Load wordlist from file or use built-in."""
        path = f"{self.config.wordlist_dir}/dirs.txt"
        try:
            with open(path) as f:
                words = [line.strip() for line in f
                         if line.strip() and not line.startswith("#")]
            if words:
                return words
        except FileNotFoundError:
            pass

        return self.BUILTIN_WORDLIST
