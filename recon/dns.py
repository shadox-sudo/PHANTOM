"""PHANTOM — DNS recon: WHOIS, DNS records, crt.sh + wordlist subdomain enum."""
import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.target import SubdomainInfo


class DNSRecon:
    """DNS reconnaissance: WHOIS, DNS records, subdomain enumeration."""

    name = "dns"
    description = "WHOIS lookup + DNS records + subdomain enumeration"

    def __init__(self, engine):
        self.engine = engine
        self.target = engine.target
        self.config = engine.config

    def run(self):
        domain = self.target.domain
        if not domain:
            print("  [!] DNSRecon: no domain set")
            return

        print(f"[*] DNS recon on {domain}")

        # 1. WHOIS lookup
        print("  [*] WHOIS lookup...")
        whois = self._whois_lookup(domain)
        if whois:
            self.target.whois_info = whois
            print(f"  [+] WHOIS data: {len(whois)} fields collected")

        # 2. DNS records
        print("  [*] DNS records...")
        dns = self._dns_records(domain)
        if dns:
            self.target.dns_records = dns
            for rtype, records in dns.items():
                print(f"  [+] {rtype.upper()}: {len(records)} records")

        # 3. Subdomain enumeration via crt.sh
        print("  [*] crt.sh subdomain search...")
        subs = self._crt_sh(domain)
        print(f"  [+] crt.sh: {len(subs)} subdomains")

        # 4. Subdomain brute force
        print("  [*] Subdomain wordlist brute force...")
        brute_subs = self._brute_subdomains(domain)
        print(f"  [+] Brute force: {len(brute_subs)} subdomains")

        all_subs = subs | brute_subs
        for sub_name in sorted(all_subs):
            fqdn = f"{sub_name}.{domain}"
            ip = self._resolve(fqdn)
            info = SubdomainInfo(subdomain=fqdn, ip=ip, resolved=bool(ip))
            self.target.subdomains.append(info)
            if ip:
                print(f"    [+] {fqdn} -> {ip}")

        self.target.add_timeline("recon", "dns_complete",
                                 f"{len(self.target.subdomains)} subdomains")
        print(f"  [*] DNS recon done: {len(self.target.subdomains)} total subdomains")

    def _whois_lookup(self, domain: str) -> dict:
        """WHOIS via raw socket to IANA/ARIN."""
        result = {}
        servers = ["whois.iana.org", "whois.arin.net"]

        for server in servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15)
                sock.connect((server, 43))
                sock.sendall(f"{domain}\r\n".encode())

                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 65536:
                        break
                sock.close()

                text = data.decode("utf-8", errors="replace")
                for line in text.split("\n"):
                    line = line.strip()
                    if ":" in line and not line.startswith("%"):
                        key, _, val = line.partition(":")
                        key = key.strip().lower().replace(" ", "_")
                        val = val.strip()
                        if key and val and key not in result:
                            result[key] = val
                if result:
                    break
            except Exception:
                continue

        return result

    def _dns_records(self, domain: str) -> dict:
        """Fetch A + AAAA records."""
        records = {}

        a_recs = self._resolve_a(domain)
        if a_recs:
            records["a"] = a_recs

        aaaa = self._resolve_aaaa(domain)
        if aaaa:
            records["aaaa"] = aaaa

        return records

    def _resolve_a(self, domain: str) -> list:
        ips = []
        try:
            info = socket.getaddrinfo(domain, 0, socket.AF_INET,
                                      socket.SOCK_STREAM)
            for i in info:
                ip = i[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        return ips

    def _resolve_aaaa(self, domain: str) -> list:
        ips = []
        try:
            info = socket.getaddrinfo(domain, 0, socket.AF_INET6,
                                      socket.SOCK_STREAM)
            for i in info:
                ip = i[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        return ips

    def _resolve(self, host: str) -> str:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return ""

    def _crt_sh(self, domain: str) -> set:
        """crt.sh certificate transparency lookup."""
        subs: set = set()
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": self.config.user_agent},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.replace("\n", ",").split(","):
                    sub = sub.strip()
                    if sub.endswith(f".{domain}") and "*" not in sub:
                        s = sub[:-(len(domain) + 1)]
                        if s:
                            subs.add(s)
        except Exception:
            pass
        return subs

    def _brute_subdomains(self, domain: str) -> set:
        """Threaded subdomain brute-force."""
        found: set = set()
        lock = threading.Lock()
        words = self._load_subdomain_wordlist()

        if not words:
            return set()

        def check(word: str):
            fqdn = f"{word}.{domain}"
            ip = self._resolve(fqdn)
            if ip:
                with lock:
                    found.add(word)

        threads = min(self.config.threads * 2, len(words))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(check, w) for w in words]
            for _ in as_completed(futures):
                pass

        return found

    def _load_subdomain_wordlist(self) -> list:
        """Load wordlist from file or fall back to built-in."""
        path = f"{self.config.wordlist_dir}/subdomains.txt"
        try:
            with open(path) as f:
                return [line.strip() for line in f
                        if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            pass

        return [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "admin", "cdn", "api", "dev", "staging",
            "test", "portal", "support", "help", "forum", "news", "shop",
            "store", "app", "m", "mobile", "en", "fr", "de", "es", "it", "pt",
            "ru", "jp", "cn", "br", "ar", "au", "ca", "in", "uk", "nl", "se",
            "no", "fi", "dk", "pl", "cz", "hu", "ro", "gr", "tr", "il", "za",
            "eg", "ng", "ke", "ma", "tn", "dz", "lb", "jo", "qa", "kw", "sa",
            "ae", "ir", "pk", "bd", "lk", "np", "mm", "kh", "vn", "id", "ph",
            "my", "sg", "th", "kr", "tw", "hk", "intranet", "extranet",
            "gateway", "firewall", "proxy", "router", "switch", "mx1", "mx2",
            "pop3", "imap", "owa", "exchange", "cpanel", "whm", "plesk",
            "direct", "status", "stats", "monitor", "tracking", "analytics",
            "pixel", "static", "assets", "img", "images", "css", "js", "fonts",
            "media", "video", "download", "upload", "ftp", "sftp", "ssh",
            "telnet", "rdp", "vnc", "dashboard", "manager", "console",
            "phpmyadmin", "adminer", "mysql", "pma", "sql", "db", "database",
            "redis", "jenkins", "gitlab", "jira", "confluence", "wiki", "docs",
        ]
