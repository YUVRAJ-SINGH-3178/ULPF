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
