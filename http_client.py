"""Shared HTTP client with connection pooling for Heimdall."""

import httpx
from contextlib import asynccontextmanager
from typing import AsyncIterator

# Global HTTP client with connection pooling
# This avoids creating new connections for each request
_http_client: httpx.AsyncClient | None = None

# Default configuration
DEFAULT_TIMEOUT = httpx.Timeout(
    connect=5.0,      # Connection timeout
    read=10.0,        # Read timeout
    write=5.0,        # Write timeout
    pool=5.0,         # Pool timeout
)

DEFAULT_LIMITS = httpx.Limits(
    max_keepalive_connections=20,  # Max idle connections
    max_connections=100,           # Max total connections
    keepalive_expiry=30.0,         # Connection keepalive (seconds)
)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


async def get_http_client() -> httpx.AsyncClient:
    """
    Get the global HTTP client instance.
    
    Creates the client on first call with connection pooling enabled.
    """
    global _http_client
    
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            limits=DEFAULT_LIMITS,
            headers=DEFAULT_HEADERS,
            follow_redirects=True,
            verify=False,  # Allow self-signed certs for analysis
            http2=False,    # Disable HTTP/2 to avoid dependency issues
        )
    
    return _http_client


async def close_http_client() -> None:
    """Close the global HTTP client."""
    global _http_client
    
    if _http_client is not None and not _http_client.is_closed:
        await _http_client.aclose()
        _http_client = None


@asynccontextmanager
async def managed_http_client() -> AsyncIterator[httpx.AsyncClient]:
    """
    Context manager for managed HTTP client lifecycle.
    
    Use this in scripts or tests where you need to ensure cleanup.
    """
    client = await get_http_client()
    try:
        yield client
    finally:
        await close_http_client()


async def fetch_url(
    url: str,
    timeout: float | None = None,
    max_content_length: int = 5 * 1024 * 1024,  # 5MB default
) -> tuple[str, int, dict[str, str]]:
    """
    Fetch a URL with safety limits.
    
    Args:
        url: URL to fetch
        timeout: Optional timeout override
        max_content_length: Maximum response size in bytes
        
    Returns:
        Tuple of (content, status_code, headers)
        
    Raises:
        httpx.HTTPError: On HTTP errors
        ValueError: If content exceeds max_content_length
    """
    client = await get_http_client()
    
    # Use custom timeout if provided
    request_timeout = timeout or DEFAULT_TIMEOUT.read
    
    async with client.stream("GET", url, timeout=request_timeout) as response:
        # Check Content-Length header first
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > max_content_length:
            raise ValueError(f"Content too large: {content_length} bytes")
        
        # Read with size limit
        chunks = []
        total_size = 0
        
        async for chunk in response.aiter_bytes(chunk_size=8192):
            total_size += len(chunk)
            if total_size > max_content_length:
                raise ValueError(f"Content exceeded {max_content_length} bytes")
            chunks.append(chunk)
        
        content = b"".join(chunks)
        
        # Try to decode as text
        try:
            text = content.decode(response.encoding or "utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        
        return text, response.status_code, dict(response.headers)
