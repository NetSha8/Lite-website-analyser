"""Security utilities for Heimdall API."""

import html
import ipaddress
import re
import socket
from urllib.parse import urlparse, urlunparse
from typing import Any

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


# ============== URL Validation ==============

# Allowed URL schemes
ALLOWED_SCHEMES = {"http", "https"}

# Maximum URL length to prevent DoS
MAX_URL_LENGTH = 2048

# Regex for basic URL validation
URL_PATTERN = re.compile(
    r'^https?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\.?|'  # domain
    r'localhost|'  # localhost
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or IP
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$',  # path
    re.IGNORECASE
)

# Dangerous patterns that might indicate injection attempts
DANGEROUS_PATTERNS = [
    r'javascript:',
    r'data:',
    r'vbscript:',
    r'file:',
    r'<script',
    r'</script',
    r'onerror\s*=',
    r'onload\s*=',
    r'onclick\s*=',
    r'onmouseover\s*=',
    r'onfocus\s*=',
    r'onblur\s*=',
]

# Blocked hostnames (SSRF protection)
BLOCKED_HOSTNAMES = {
    'localhost',
    'localhost.localdomain',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
    'metadata.google.internal',  # GCP metadata
    '169.254.169.254',  # AWS/Azure metadata
    'metadata.internal',
}


class URLValidationError(Exception):
    """Raised when URL validation fails."""
    pass


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_multicast or
            ip.is_reserved or
            ip.is_unspecified
        )
    except ValueError:
        return False


def validate_url(url: str, allow_internal: bool = False) -> str:
    """
    Validate and sanitize a URL.
    
    Args:
        url: The URL to validate
        allow_internal: If True, allow internal/private IPs (default False for SSRF protection)
        
    Returns:
        The sanitized URL
        
    Raises:
        URLValidationError: If the URL is invalid or potentially malicious
    """
    if not url:
        raise URLValidationError("URL cannot be empty")
    
    # Strip whitespace
    url = url.strip()
    
    # Check length
    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters")
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    # Check for dangerous patterns (case insensitive)
    url_lower = url.lower()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, url_lower, re.IGNORECASE):
            raise URLValidationError("URL contains potentially dangerous content")
    
    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        raise URLValidationError("Invalid URL format")
    
    # Validate scheme
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise URLValidationError(f"URL scheme '{parsed.scheme}' is not allowed. Use http or https.")
    
    # Validate hostname exists
    if not parsed.netloc:
        raise URLValidationError("URL must have a valid hostname")
    
    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL must have a valid hostname")
    
    # SSRF Protection: Check blocked hostnames
    if not allow_internal:
        hostname_lower = hostname.lower()
        
        # Check blocked list
        if hostname_lower in BLOCKED_HOSTNAMES:
            raise URLValidationError("Access to internal resources is not allowed")
        
        # Check if it's an IP address
        try:
            if is_private_ip(hostname):
                raise URLValidationError("Access to private IP addresses is not allowed")
        except ValueError:
            pass  # Not an IP, continue with hostname
        
        # Try to resolve and check if it resolves to a private IP
        try:
            resolved_ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, type_, proto, canonname, sockaddr in resolved_ips:
                ip = str(sockaddr[0])
                if is_private_ip(ip):
                    raise URLValidationError("URL resolves to a private IP address")
        except socket.gaierror:
            # DNS resolution failed, but we'll let the actual request handle that
            pass
    
    # Check for null bytes
    if '\x00' in url:
        raise URLValidationError("URL contains null bytes")
    
    # Check for newlines (HTTP header injection)
    if '\n' in url or '\r' in url:
        raise URLValidationError("URL contains newline characters")
    
    # Reconstruct the URL to normalize it
    sanitized = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        parsed.params,
        parsed.query,
        ''  # Remove fragment as it's not sent to server
    ))
    
    return sanitized


def sanitize_for_html(text: str) -> str:
    """
    Sanitize text for safe HTML output.
    
    Args:
        text: The text to sanitize
        
    Returns:
        HTML-escaped text
    """
    return html.escape(str(text))


def sanitize_dict_for_html(data: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively sanitize all string values in a dictionary for HTML output.
    """
    result = {}
    for key, value in data.items():
        if isinstance(value, str):
            result[key] = sanitize_for_html(value)
        elif isinstance(value, dict):
            result[key] = sanitize_dict_for_html(value)
        elif isinstance(value, list):
            result[key] = [
                sanitize_for_html(item) if isinstance(item, str) 
                else sanitize_dict_for_html(item) if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            result[key] = value
    return result


# ============== Security Headers Middleware ==============

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        # Content Security Policy
        # Allows Tailwind CDN, HTMX, Alpine.js
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://cdn.tailwindcss.com "
            "https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS Protection (legacy but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions Policy (disable unnecessary features)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=()"
        )
        
        # Cache control for sensitive content
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
        
        return response


# ============== Rate Limiting ==============

from collections import defaultdict
from datetime import datetime, timedelta
import asyncio


class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(
        self,
        requests_per_minute: int = 30,
        requests_per_hour: int = 200,
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.minute_requests: dict[str, list[datetime]] = defaultdict(list)
        self.hour_requests: dict[str, list[datetime]] = defaultdict(list)
        self._lock = asyncio.Lock()
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP from request, handling proxies."""
        # Check X-Forwarded-For header (from reverse proxy)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Get first IP in chain (original client)
            return forwarded.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fallback to direct client IP
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _cleanup_old_requests(self, client_ip: str, now: datetime):
        """Remove expired request timestamps."""
        minute_ago = now - timedelta(minutes=1)
        hour_ago = now - timedelta(hours=1)
        
        self.minute_requests[client_ip] = [
            ts for ts in self.minute_requests[client_ip]
            if ts > minute_ago
        ]
        self.hour_requests[client_ip] = [
            ts for ts in self.hour_requests[client_ip]
            if ts > hour_ago
        ]
    
    async def check_rate_limit(self, request: Request) -> tuple[bool, str | None]:
        """
        Check if request should be rate limited.
        
        Returns:
            Tuple of (is_allowed, error_message)
        """
        client_ip = self._get_client_ip(request)
        now = datetime.now()
        
        async with self._lock:
            self._cleanup_old_requests(client_ip, now)
            
            # Check minute limit
            if len(self.minute_requests[client_ip]) >= self.requests_per_minute:
                return False, f"Rate limit exceeded. Max {self.requests_per_minute} requests per minute."
            
            # Check hour limit
            if len(self.hour_requests[client_ip]) >= self.requests_per_hour:
                return False, f"Rate limit exceeded. Max {self.requests_per_hour} requests per hour."
            
            # Record this request
            self.minute_requests[client_ip].append(now)
            self.hour_requests[client_ip].append(now)
            
            return True, None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce rate limiting."""
    
    def __init__(self, app, rate_limiter: RateLimiter):
        super().__init__(app)
        self.rate_limiter = rate_limiter
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Only rate limit API endpoints
        if request.url.path.startswith("/api/"):
            is_allowed, error_message = await self.rate_limiter.check_rate_limit(request)
            
            if not is_allowed:
                return Response(
                    content=f'{{"error": "{error_message}"}}',
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    media_type="application/json",
                    headers={"Retry-After": "60"}
                )
        
        return await call_next(request)


# ============== Request Validation ==============

def validate_request_size(request: Request, max_size: int = 10240) -> bool:
    """
    Validate request content length.
    
    Args:
        request: The incoming request
        max_size: Maximum allowed size in bytes (default 10KB)
        
    Returns:
        True if valid, raises HTTPException otherwise
    """
    content_length = request.headers.get("Content-Length")
    if content_length:
        try:
            size = int(content_length)
            if size > max_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Request too large. Maximum size is {max_size} bytes."
                )
        except ValueError:
            pass
    return True
