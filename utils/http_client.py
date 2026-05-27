import random
import time
import socket
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlencode


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

_ua_index = 0
_ssl_ctx = None


def get_ssl_ctx():
    global _ssl_ctx
    if not _ssl_ctx:
        _ssl_ctx = ssl.create_default_context()
        _ssl_ctx.check_hostname = False
        _ssl_ctx.verify_mode = ssl.CERT_NONE
    return _ssl_ctx


def rotate_ua():
    global _ua_index
    ua = USER_AGENTS[_ua_index % len(USER_AGENTS)]
    _ua_index += 1
    return ua


class Response:
    def __init__(self, status=0, body="", headers=None, url="", elapsed=0.0):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.url = url
        self.elapsed = elapsed

    def __bool__(self):
        return self.status > 0


def request(url, method="GET", data=None, headers=None, timeout=10,
            proxy="", ua_rotation=True):
    ua = rotate_ua() if ua_rotation else USER_AGENTS[0]
    hdrs = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if headers:
        hdrs.update(headers)

    body_bytes = None
    if data:
        if isinstance(data, dict):
            body_bytes = urlencode(data).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            body_bytes = data.encode()
        else:
            body_bytes = data

    t0 = time.time()

    try:
        if proxy and proxy.startswith("socks5://"):
            return _socks5_request(url, method, hdrs, body_bytes, proxy, timeout)

        req = urllib.request.Request(url, data=body_bytes, headers=hdrs,
                                     method=method)
        ctx = get_ssl_ctx() if url.startswith("https") else None
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx)
        ) if ctx else urllib.request.build_opener()
        opener.addheaders = []

        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            rh = {}
            for k, v in resp.headers.items():
                rh[k.lower()] = v
            elapsed = time.time() - t0
            return Response(resp.status, body, rh, url, elapsed)

    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except:
            body = ""
        rh = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
        elapsed = time.time() - t0
        return Response(e.code, body, rh, url, elapsed)

    except Exception as e:
        return Response(0, str(e), {}, url, time.time() - t0)


def _socks5_request(url, method, headers, body, proxy, timeout):
    m = re.match(r"socks5://([^:]+):(\d+)", proxy)
    if not m:
        return Response(0, "Invalid SOCKS5 proxy")
    phost, pport = m.group(1), int(m.group(2))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((phost, pport))
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        sock.close()
        return Response(0, "SOCKS5 auth failed")

    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addr = socket.inet_aton(host)
    req = b"\x05\x01\x00\x01" + addr + port.to_bytes(2, "big")
    sock.sendall(req)
    resp = sock.recv(10)
    if len(resp) < 2 or resp[1] != 0x00:
        sock.close()
        return Response(0, f"SOCKS5 CONNECT failed")

    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(sock, server_hostname=host)
    else:
        s = sock

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    req_line = f"{method} {path} HTTP/1.1\r\n"
    h_str = f"Host: {host}:{port}\r\n"
    for k, v in headers.items():
        h_str += f"{k}: {v}\r\n"
    h_str += "\r\n"
    payload = req_line + h_str
    if body:
        payload += body.decode() if isinstance(body, bytes) else body
    s.sendall(payload.encode() if isinstance(payload, str) else payload)

    raw = b""
    while True:
        try:
            c = s.recv(4096)
            if not c:
                break
            raw += c
        except:
            break
    s.close()
    sock.close()

    text = raw.decode("utf-8", errors="replace")
    parts = text.split("\r\n\r\n", 1)
    head_part = parts[0]
    body_out = parts[1] if len(parts) > 1 else ""
    lines = head_part.split("\r\n")
    status = 0
    if lines and " " in lines[0]:
        try:
            status = int(lines[0].split(" ", 2)[1])
        except:
            pass
    rh = {}
    for line in lines[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            rh[k.lower()] = v
    return Response(status, body_out, rh, url, timeout)
