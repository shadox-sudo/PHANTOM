"""
PHANTOM — TCP Port Scanner Module
Multithreaded TCP connect scan with banner grabbing.
"""
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.target import PortInfo


class PortScanner:
    """Multithreaded TCP port scanner using raw socket connect."""

    name = "ports"
    description = "TCP port scanner with banner grab"

    # Top 100 ports (nmap top-100) + common extras
    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445,
        465, 502, 512, 513, 514, 587, 593, 636, 873, 902, 993, 995,
        1080, 1099, 1433, 1434, 1521, 1527, 1604, 1701, 1720, 1723, 1741,
        1755, 1801, 1863, 1900, 1993, 2000, 2001, 2049, 2082, 2083, 2100,
        2222, 2301, 2375, 2376, 2480, 2525, 2628, 2809, 3000, 3128, 3260,
        3268, 3300, 3306, 3389, 3632, 3690, 3702, 3737, 3768, 4000, 4045,
        4224, 4242, 4321, 4443, 4444, 4500, 4567, 4662, 4848, 4899, 5000,
        5001, 5003, 5050, 5060, 5100, 5222, 5269, 5280, 5298, 5353, 5357,
        5405, 5414, 5432, 5500, 5554, 5555, 5560, 5601, 5632, 5666,
        5671, 5672, 5800, 5900, 5901, 5985, 5986, 6000, 6001, 6002,
        6050, 6100, 6101, 6346, 6379, 6380, 6443, 6481, 6522, 6543,
        6566, 6580, 6600, 6660, 6661, 6662, 6663, 6664, 6665, 6666,
        6667, 6668, 6669, 6679, 6697, 6700, 6881, 6900, 6969, 7000,
        7001, 7002, 7022, 7070, 7100, 7120, 7170, 7200, 7210, 7272,
        7290, 7390, 7410, 7420, 7450, 7474, 7547, 7570, 7626, 7680,
        7700, 7744, 7777, 7778, 8000, 8001, 8008, 8009, 8010, 8020,
        8022, 8031, 8042, 8060, 8070, 8080, 8081, 8082, 8086, 8087,
        8088, 8090, 8091, 8100, 8112, 8140, 8172, 8181, 8200, 8222,
        8243, 8280, 8291, 8300, 8332, 8333, 8384, 8400, 8403, 8443,
        8500, 8600, 8649, 8654, 8741, 8800, 8834, 8880, 8888, 8889,
        8900, 8983, 9000, 9001, 9002, 9042, 9043, 9050, 9060, 9080,
        9090, 9091, 9092, 9100, 9111, 9200, 9191, 9292, 9300, 9400,
        9418, 9443, 9500, 9535, 9600, 9675, 9797, 9800, 9876, 9898,
        9900, 9981, 9987, 9990, 9991, 9993, 9997, 9999, 10000, 10001,
        10009, 10011, 10050, 10080, 10082, 10101, 10180, 10243, 10389,
        10497, 10554, 10629, 11000, 11111, 11211, 11371, 11740, 12000,
        12345, 13337, 13722, 14000, 14238, 14441, 15000, 15002, 15104,
        15567, 15345, 16080, 16113, 16509, 16992, 16993, 17001, 17184,
        18080, 18091, 18200, 18463, 18634, 19000, 19283, 19315, 19638,
        19780, 19801, 19842, 20000, 20031, 20222, 20480, 21000, 21571,
        22000, 22273, 22707, 22939, 23000, 23280, 23456, 24000, 24680,
        24999, 25000, 25601, 25734, 26000, 26208, 26214, 27000, 27015,
        27017, 27018, 27274, 27500, 27888, 28015, 28017, 28443, 28888,
        28960, 29000, 29999, 30000, 30102, 30303, 30566, 30704, 30718,
        31000, 31099, 31100, 31337, 31457, 32000, 32137, 32400, 32764,
        32768, 32815, 33001, 33030, 33333, 33334, 33434, 33656, 34249,
        34333, 34455, 34567, 35432, 35881, 36330, 37444, 37601, 37777,
        38551, 39213, 39681, 40000, 40193, 40628, 40808, 41097, 41111,
        41373, 41511, 42042, 42510, 42662, 43000, 43210, 43501, 43594,
        44334, 44442, 44443, 44501, 45000, 45365, 45564, 45576, 45678,
        45824, 45935, 47000, 47001, 47544, 47624, 47808, 48080, 49152,
        49153, 49154, 49155, 49156, 50000, 50001, 50050, 50070, 50100,
        50101, 50242, 50300, 50389, 50500, 50636, 50800, 51103, 51413,
        51820, 52000, 52193, 52237, 52424, 52546, 53046, 53119, 53369,
        53535, 53557, 54045, 54321, 54440, 54545, 55056, 55161, 55553,
        55554, 55555, 55600, 55773, 55849, 55877, 56000, 56046, 56112,
        56238, 56371, 56445, 56667, 56789, 57000, 57123, 57294, 57393,
        57410, 57500, 57525, 57605, 57797, 57843, 57967, 58000, 58080,
        58123, 58178, 58255, 58320, 58458, 58541, 58636, 58777, 58888,
        58999, 59000, 59090, 59123, 59259, 59338, 59444, 59555, 59601,
        59777, 59888, 59999, 60000, 60123, 60172, 60222, 60333, 60444,
        60555, 60666, 60777, 60888, 60999, 61000, 61001, 61123, 61234,
        61345, 61456, 61567, 61678, 61889, 62000, 62078, 62123, 62222,
        62333, 62444, 62555, 62666, 62777, 62888, 62999, 63000, 63123,
        63234, 63345, 63456, 63567, 63678, 63789, 63900, 64000, 64123,
        64222, 64333, 64444, 64555, 64666, 64777, 64888, 64999, 65000,
        65001, 65002, 65111, 65222, 65333, 65389, 65432, 65444, 65535,
    ]

    def __init__(self, engine):
        self.engine = engine
        self.target = engine.target
        self.config = engine.config

    def run(self):
        target_ip = self.target.ip or self.target.domain
        if not target_ip:
            print("  [!] PortScanner: no target IP/domain")
            return

        print(f"[*] Port scan on {target_ip}")

        # Resolve domain if needed
        ip = target_ip
        if not self._is_ip(target_ip):
            try:
                ip = socket.gethostbyname(target_ip)
                self.target.ip = ip
                print(f"  [+] Resolved {target_ip} -> {ip}")
            except socket.gaierror:
                print(f"  [!] Cannot resolve {target_ip}")
                return

        ports = self.TOP_PORTS
        threads = min(self.config.threads, len(ports))
        print(f"  [*] Scanning {len(ports)} ports with {threads} threads...")

        def scan_port(port: int):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.config.timeout)
                res = s.connect_ex((ip, port))
                if res == 0:
                    banner = self._grab_banner(s, port)
                    service = self._detect_service(port, banner)
                    s.close()
                    return PortInfo(
                        port=port, protocol="tcp", state="open",
                        service=service, banner=banner or "",
                    )
                s.close()
            except Exception:
                pass
            return None

        open_ports = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(scan_port, p): p for p in ports}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    open_ports.append(result)
                    p = result.port
                    s = result.service or "unknown"
                    print(f"  [+] PORT {p:5d}/tcp  OPEN  {s}")
                    time.sleep(self.config.rate_limit)

        self.target.ports = sorted(open_ports, key=lambda x: x.port)
        self.target.add_timeline("recon", "port_scan",
                                 f"{len(self.target.ports)} open ports")
        print(f"  [*] Port scan done: {len(open_ports)} open ports")

    def _is_ip(self, s: str) -> bool:
        try:
            socket.inet_aton(s)
            return True
        except OSError:
            return False

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Attempt to grab a service banner from an open socket."""
        try:
            sock.settimeout(3)
            if port in (80, 8080, 8000, 8888, 8081):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP banner on connect
            elif port == 22:
                pass  # SSH banner on connect
            elif port == 25:
                sock.sendall(b"EHLO phantom.local\r\n")
            elif port == 110:
                sock.sendall(b"USER phantom\r\n")
            data = sock.recv(1024)
            text = data.decode("utf-8", errors="replace")
            clean = "".join(c if c.isprintable() or c in "\r\n\t" else "."
                            for c in text)
            return clean.strip()[:200]
        except Exception:
            return ""

    def _detect_service(self, port: int, banner: str) -> str:
        """Detect service by port number or banner."""
        common = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 81: "http", 110: "pop3",
            111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
            143: "imap", 389: "ldap", 443: "https", 445: "smb",
            465: "smtps", 502: "modbus", 587: "submission",
            636: "ldaps", 873: "rsync", 902: "vmware-auth",
            993: "imaps", 995: "pop3s", 1080: "socks5",
            1433: "mssql", 1521: "oracle", 1527: "oracle",
            1701: "l2tp", 1723: "pptp", 2049: "nfs",
            2375: "docker", 2376: "docker-s", 3128: "squid",
            3306: "mysql", 3389: "rdp", 5432: "postgresql",
            5900: "vnc", 5901: "vnc", 5985: "winrm",
            5986: "winrm-s", 6379: "redis", 6667: "irc",
            8080: "http-proxy", 8443: "https-alt",
            9000: "php-fpm", 9200: "elasticsearch",
            9300: "elasticsearch", 11211: "memcached",
            27017: "mongod", 50000: "sap", 50070: "hdfs",
        }
        if port in common:
            return common[port]

        bl = banner.lower()
        if "ssh" in bl:
            return "ssh"
        if "ftp" in bl:
            return "ftp"
        if "smtp" in bl or "esmtp" in bl:
            return "smtp"
        if "http" in bl or "nginx" in bl or "apache" in bl:
            return "http"
        return "unknown"
