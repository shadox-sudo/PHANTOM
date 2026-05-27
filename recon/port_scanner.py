"""
PHANTOM — Multithreaded TCP Port Scanner

Pure-socket TCP connect scanner.
No SYN scan (requires raw sockets / root) — uses full TCP connect.
"""
from __future__ import annotations
import logging
import socket
import threading
import time
from queue import Queue
from typing import Optional

from .base import ReconModule
from core.target import PortInfo
from utils.http import is_web_port

logger = logging.getLogger("phantom.recon.portscan")


class PortScanner(ReconModule):
    """Multithreaded TCP port scanner using raw sockets."""

    name = "port_scanner"
    description = "Multithreaded TCP port scan with service detection"
    depends_on = []

    def run(self, target, config=None):
        """Populates target.open_ports.
        
        Scans each IP address in target.ips.
        If no IPs, resolves domain first.
        Service detection via banner grab + port mapping.
        """
        # Ensure we have IPs to scan
        if not target.ips and target.domain:
            self._resolve_target(target)
        
        if not target.ips:
            logger.warning("No IPs to scan")
            return target
        
        # Parse port range
        ports = self._parse_ports(config)
        
        # Thread count
        max_threads = 100
        if config and hasattr(config, 'recon'):
            max_threads = getattr(config.recon, 'threads', 100)
        
        timeout = 2
        if config and hasattr(config, 'target'):
            timeout = getattr(config.target, 'timeout', 2)
        
        for ip in target.ips:
            logger.info("Scanning %s (%d ports, %d threads)", ip, len(ports), max_threads)
            open_ports = self._scan_ip(ip, ports, max_threads, timeout)
            target.open_ports.extend(open_ports)
            logger.info("  %s: %d open ports", ip, len(open_ports))
        
        return target

    def _resolve_target(self, target) -> None:
        """Resolve target domain to IPs."""
        try:
            addrinfo = socket.getaddrinfo(target.domain, 0, socket.AF_INET, socket.SOCK_STREAM)
            for info in addrinfo:
                ip = info[4][0]
                if ip not in target.ips:
                    target.ips.append(ip)
            if target.ips and not target.root_ip:
                target.root_ip = target.ips[0]
        except socket.gaierror:
            pass

    def _parse_ports(self, config=None) -> list[int]:
        """Parse port specification from config."""
        ports_str = "21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,27017"
        if config and hasattr(config, 'target'):
            ports_str = getattr(config.target, 'ports', ports_str)
        
        ports: list[int] = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-")
                    ports.extend(range(int(start), int(end) + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        
        return sorted(set(ports))

    def _scan_ip(self, ip: str, ports: list[int],
                 max_threads: int, timeout: float) -> list[PortInfo]:
        """Scan all ports on an IP using a thread pool."""
        open_ports: list[PortInfo] = []
        lock = threading.Lock()
        queue: Queue = Queue()
        
        for port in ports:
            queue.put(port)
        
        def worker() -> None:
            while True:
                try:
                    port = queue.get_nowait()
                except Exception:
                    break
                
                result = self._check_port(ip, port, timeout)
                if result:
                    with lock:
                        open_ports.append(result)
                queue.task_done()
        
        # Start threads
        threads = []
        num_threads = min(max_threads, len(ports))
        for _ in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait with timeout
        queue.join()
        for t in threads:
            t.join(timeout=1)
        
        return sorted(open_ports, key=lambda p: p.port)

    def _check_port(self, ip: str, port: int, timeout: float) -> Optional[PortInfo]:
        """Check single port via TCP connect."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Port is open — grab banner
                banner = self._grab_banner(sock, port, timeout)
                sock.close()
                
                service = self._detect_service(port, banner)
                return PortInfo(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                    protocol="tcp",
                )
            
            sock.close()
        except (socket.timeout, socket.error, OSError):
            pass
        
        return None

    def _grab_banner(self, sock: socket.socket, port: int, timeout: float) -> Optional[str]:
        """Grab service banner from open socket."""
        try:
            sock.settimeout(timeout)
            
            # Send probes for common services
            if port == 80 or port == 8080:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443 or port == 8443:
                pass  # TLS — would need ssl wrap
            elif port == 22:
                pass  # SSH banner is sent immediately
            elif port == 21:
                pass  # FTP banner is sent immediately
            
            # Read response
            data = sock.recv(1024)
            text = data.decode("utf-8", errors="replace")
            text = "".join(c if c.isprintable() or c in "\r\n\t" else "." for c in text)
            return text.strip()[:200]
        except (socket.timeout, socket.error):
            return None

    def _detect_service(self, port: int, banner: Optional[str]) -> str:
        """Detect service name from port number and banner."""
        common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 2049: "nfs",
            3306: "mysql", 3389: "rdp", 5432: "postgresql",
            5900: "vnc", 6379: "redis", 8080: "http-proxy",
            8443: "https-alt", 9000: "php-fpm", 27017: "mongod",
        }
        
        if port in common_ports:
            return common_ports[port]
        
        return "unknown"

    def validate_target(self, target) -> bool:
        return target is not None
