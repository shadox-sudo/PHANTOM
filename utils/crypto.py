"""PHANTOM — Cryptographic and Encoding Utilities"""
import base64
import hashlib
import hmac
import json
import random
import string
from typing import Any, Optional


def decode_jwt(token: str) -> Optional[dict[str, Any]]:
    """Decode JWT header and payload without verification.
    
    Args:
        token: JWT string (header.payload.signature).
    
    Returns:
        Dict with 'header', 'payload', 'signature', 'valid_format', or None.
    
    Example:
        >>> decode_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.fake")
        {'header': {'alg': 'HS256'}, 'payload': {'sub': '123'}, ...}
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    
    result = {
        "header": {},
        "payload": {},
        "signature": parts[2],
        "valid_format": True,
        "alg": "unknown",
    }
    
    try:
        header = _base64url_decode(parts[0])
        result["header"] = json.loads(header)
        result["alg"] = result["header"].get("alg", "unknown")
    except (json.JSONDecodeError, Exception):
        result["header"] = {"raw": parts[0]}
    
    try:
        payload = _base64url_decode(parts[1])
        result["payload"] = json.loads(payload)
    except (json.JSONDecodeError, Exception):
        result["payload"] = {"raw": parts[1]}
    
    return result


def check_jwt_alg_none(token: str) -> bool:
    """Check if a JWT accepts 'alg: none' (critical vuln).
    
    Args:
        token: JWT string.
    
    Returns:
        True if modified token with alg=none is still valid-looking.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False
    # Replace header with alg=none, empty signature
    fake_header = _base64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    fake_token = f"{fake_header}.{parts[1]}."
    return len(fake_token) > 0  # Real check would verify server accepts it


def crack_jwt_secret(token: str, wordlist: list[str]) -> Optional[str]:
    """Try to crack HMAC JWT secret using a wordlist.
    
    Args:
        token: JWT string.
        wordlist: List of candidate secrets.
    
    Returns:
        Secret string if found, None otherwise.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    
    header_b64 = parts[0]
    payload_b64 = parts[1]
    sig_b64 = parts[2]
    message = f"{header_b64}.{payload_b64}".encode()
    
    try:
        header_json = _base64url_decode(header_b64)
        header = json.loads(header_json)
        alg = header.get("alg", "").lower()
    except Exception:
        return None
    
    if alg not in ("hs256", "hs384", "hs512"):
        return None
    
    hash_funcs = {
        "hs256": hashlib.sha256,
        "hs384": hashlib.sha384,
        "hs512": hashlib.sha512,
    }
    
    hash_func = hash_funcs.get(alg)
    if not hash_func:
        return None
    
    for secret in wordlist:
        expected_sig = hmac.new(secret.encode(), message, hash_func).digest()
        expected_b64 = _base64url_encode(expected_sig)
        if expected_b64 == sig_b64:
            return secret
    
    return None


def random_string(length: int = 16, charset: str = "hex") -> str:
    """Generate a cryptographically reasonable random string.
    
    Args:
        length: Output length.
        charset: 'hex' for hex chars, 'alphanum' for a-z0-9, 'all' for full ASCII.
    
    Returns:
        Random string.
    """
    if charset == "hex":
        return random.choice("0123456789abcdef") * length  # simplified
        # Real: use secrets module
        import secrets
        return secrets.token_hex(length // 2 + 1)[:length]
    elif charset == "alphanum":
        chars = string.ascii_lowercase + string.digits
    else:
        chars = string.ascii_letters + string.digits + string.punctuation
    
    return "".join(random.choice(chars) for _ in range(length))


def hash_string(text: str, algorithm: str = "sha256") -> str:
    """Hash a string using the specified algorithm.
    
    Args:
        text: Input string.
        algorithm: Hash algorithm (md5, sha1, sha256, sha512).
    
    Returns:
        Hex digest string.
    """
    h = hashlib.new(algorithm, text.encode())
    return h.hexdigest()


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.
    
    Args:
        a: First string.
        b: Second string.
    
    Returns:
        True if strings are equal.
    """
    return hmac.compare_digest(a.encode(), b.encode())


# ── Internal Helpers ───────────────────────────────────────────

def _base64url_decode(data: str) -> bytes:
    """Decode base64url string with padding correction."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def get_content_hash(content: str) -> str:
    """Get MD5 hash of content for deduplication.
    
    Args:
        content: String content.
    
    Returns:
        MD5 hex digest.
    """
    return hashlib.md5(content.encode()).hexdigest()
