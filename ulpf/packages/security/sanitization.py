"""
Security Validation, Sanitization, and Rate Limiting Subsystem
Provides strict path traversal protection, identifier validation, and sliding-window rate limiting.
"""

import re
import threading
import time
from collections import deque

from fastapi import HTTPException, status

IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.:]+$")


def validate_safe_identifier(identifier: str, field_name: str = "identifier") -> str:
    """
    Validates that a path parameter or resource ID is clean of path traversal sequences,
    slashes, null bytes, and malicious control characters.
    """
    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name}: cannot be empty",
        )

    if len(identifier) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name}: length exceeds 128 characters",
        )

    if (
        ".." in identifier
        or "/" in identifier
        or "\\" in identifier
        or "\x00" in identifier
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security Alert: Path traversal sequence rejected in {field_name}",
        )

    if not IDENTIFIER_REGEX.match(identifier):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name}: contains disallowed characters",
        )

    return identifier


# ReDoS vulnerable pattern signature: nested repetition / unbounded quantifiers
REDOS_VULNERABLE_PATTERNS = [
    re.compile(r"\([^)]*[+*]\)[+*]"),  # (a+)+ or (a*)*
    re.compile(r"\([^)]*\{[0-9,]+\}\)[+*]"),  # (a{1,5})+
    re.compile(r"\{[0-9,]+\}[+*]"),  # a{1,5}+
    re.compile(r"\.\*[+*]"),  # .*+ or .**
    re.compile(r"[+*]{2,}"),  # a++ or a**
]


def validate_safe_regex(pattern: str, max_length: int = 512) -> str:
    """
    Validates that a user-supplied regex does not exceed length bounds,
    compiles cleanly, and does not contain classic nested-quantifier ReDoS vectors.
    """
    if not pattern:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid regex pattern: cannot be empty",
        )

    if len(pattern) > max_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid regex pattern: length exceeds maximum of {max_length} characters",
        )

    # Check for pathological nested quantifier structures (catastrophic backtracking)
    for vuln_re in REDOS_VULNERABLE_PATTERNS:
        if vuln_re.search(pattern):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security Alert: Potential ReDoS vulnerability detected (nested quantifiers)",
            )

    try:
        re.compile(pattern)
    except re.error as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid regular expression syntax: {e}",
        )

    return pattern


# SSRF target blocklist: Cloud IMDS & Link-Local IPs
SSRF_BLOCKED_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "fd00:ec2::254",
}


def validate_safe_url(url: str, allow_private: bool = True) -> str:
    """
    Validates a URL against Server-Side Request Forgery (SSRF) and Cloud Metadata exfiltration.
    """
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty",
        )

    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL scheme '{parsed.scheme}': only http and https are permitted",
        )

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL: missing valid hostname",
        )

    if hostname in SSRF_BLOCKED_HOSTS or hostname.endswith(".internal"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security Alert: SSRF target blocked (cloud metadata service or internal domain)",
        )

    return url


def sanitize_log_string(value: str, max_length: int = 512) -> str:
    """
    Sanitizes arbitrary user input to prevent Log Injection / HTTP Header Splitting (CRLF injection).
    Replaces newlines, carriage returns, and control characters with sanitized spaces.
    """
    if not value:
        return ""

    sanitized = re.sub(r"[\r\n\x00-\x1f\x7f-\x9f]", " ", value)
    sanitized = sanitized.strip()
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."
    return sanitized


class InMemoryRateLimiter:
    """
    Thread-safe sliding-window rate limiter per client IP address.
    """

    def __init__(self, requests_per_minute: int = 60):
        self.rpm = requests_per_minute
        self._lock = threading.Lock()
        self._clients: dict[str, deque] = {}

    def check_rate_limit(self, client_ip: str) -> bool:
        """Returns True if request is permitted, False if rate limit exceeded."""
        now = time.time()
        window_start = now - 60.0

        with self._lock:
            if client_ip not in self._clients:
                self._clients[client_ip] = deque()

            history = self._clients[client_ip]

            # Evict timestamps older than 60 seconds
            while history and history[0] < window_start:
                history.popleft()

            if len(history) >= self.rpm:
                return False

            history.append(now)
            return True


# Global Rate Limiters
auth_rate_limiter = InMemoryRateLimiter(requests_per_minute=60)
ingest_rate_limiter = InMemoryRateLimiter(requests_per_minute=60000)
