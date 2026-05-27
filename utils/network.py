"""
PHANTOM — Network Utility Functions

Pure socket-based helpers with no external dependencies.
"""
import socket
import struct
from typing import Optional


def resolve_domain(domain: str) -> list[str]:
    """Resolve domain to IPv4 addresses using socket.getaddrinfo.
    
    Args:
        domain: Domain name to resolve.
    
    Returns:
        List of IPv4 address strings.
    
    Example:
        >>> resolve_domain("example.com")
        ['93.184.216.34']
    """
    ips: list[str] = []
    try:
        addrinfo = socket.getaddrinfo(domain, 0, socket.AF_INET, socket.SOCK_STREAM)
        for info in addrinfo:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        pass
    return ips


def resolve_domain_all(domain: str) -> dict[str, list[str]]:
    """Resolve domain to all record types (A, AAAA).
    
    Args:
        domain: Domain name to resolve.
    
    Returns:
        Dict with 'ipv4' and 'ipv6' lists.
    """
    result: dict[str, list[str]] = {"ipv4": [], "ipv6": []}
    
    try:
        addrinfo = socket.getaddrinfo(domain, 0, socket.AF_INET, socket.SOCK_STREAM)
        for info in addrinfo:
            ip = info[4][0]
            if ip not in result["ipv4"]:
                result["ipv4"].append(ip)
    except socket.gaierror:
        pass
    
    try:
        addrinfo = socket.getaddrinfo(domain, 0, socket.AF_INET6, socket.SOCK_STREAM)
        for info in addrinfo:
            ip = info[4][0]
            if ip not in result["ipv6"]:
                result["ipv6"].append(ip)
    except socket.gaierror:
        pass
    
    return result


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a TCP port is open.
    
    Args:
        host: IP address or hostname.
        port: Port number.
        timeout: Connection timeout in seconds.
    
    Returns:
        True if port is open.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.timeout, socket.error):
        return False


def banner_grab(host: str, port: int, timeout: float = 3.0,
                probe: Optional[bytes] = None) -> Optional[str]:
    """Grab service banner from a port.
    
    Args:
        host: IP address.
        port: Port number.
        timeout: Socket timeout.
        probe: Optional probe bytes to send (e.g., HTTP request).
    
    Returns:
        Banner string or None if no banner.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        if probe:
            sock.send(probe)
        
        banner = sock.recv(1024)
        sock.close()
        
        # Decode, remove non-printable
        text = banner.decode("utf-8", errors="replace")
        text = "".join(c if c.isprintable() or c in "\r\n\t" else "." for c in text)
        return text.strip()[:500]  # limit length
    except (socket.timeout, socket.error, ConnectionRefusedError):
        return None


def get_local_ip() -> str:
    """Get local machine's primary IP address.
    
    Returns:
        Local IP string (e.g., '192.168.1.5').
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except socket.error:
        return "127.0.0.1"


def ip_to_int(ip: str) -> int:
    """Convert IPv4 string to integer.
    
    Args:
        ip: IPv4 address string.
    
    Returns:
        Integer representation.
    """
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n: int) -> str:
    """Convert integer to IPv4 string.
    
    Args:
        n: Integer representation.
    
    Returns:
        IPv4 address string.
    """
    return socket.inet_ntoa(struct.pack("!I", n))


def cidr_to_ips(cidr: str) -> list[str]:
    """Expand CIDR notation to individual IPs.
    
    Args:
        cidr: CIDR notation (e.g., '192.168.1.0/24').
    
    Returns:
        List of IP strings.
    """
    from ipaddress import ip_network
    return [str(ip) for ip in ip_network(cidr, strict=False).hosts()]


def check_dns_txt(domain: str, nameserver: Optional[str] = None) -> list[str]:
    """Query TXT records using socket/dns resolution.
    
    Args:
        domain: Domain to query.
        nameserver: Optional DNS server override.
    
    Returns:
        List of TXT record strings.
    """
    # Fallback: try simple approach using nslookup via subprocess
    import subprocess
    try:
        cmd = ["nslookup", "-type=TXT", domain]
        if nameserver:
            cmd.append(nameserver)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        records = []
        for line in result.stdout.split("\n"):
            if 'text =' in line:
                txt = line.split('text =')[1].strip().strip('"')
                records.append(txt)
        return records
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
