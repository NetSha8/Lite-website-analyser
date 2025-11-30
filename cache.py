"""Caching layer for Heimdall API."""

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar
from collections import OrderedDict

T = TypeVar('T')


@dataclass
class CacheEntry(Generic[T]):
    """A single cache entry with expiration."""
    value: T
    expires_at: float
    created_at: float = field(default_factory=time.time)
    
    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class TTLCache(Generic[T]):
    """
    Simple in-memory TTL cache with LRU eviction.
    
    Thread-safe for async operations.
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        """
        Initialize cache.
        
        Args:
            max_size: Maximum number of entries
            default_ttl: Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0
    
    def _make_key(self, key: str) -> str:
        """Create a normalized cache key."""
        return hashlib.md5(key.encode()).hexdigest()
    
    async def get(self, key: str) -> T | None:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        normalized_key = self._make_key(key)
        
        async with self._lock:
            entry = self._cache.get(normalized_key)
            
            if entry is None:
                self._misses += 1
                return None
            
            if entry.is_expired:
                del self._cache[normalized_key]
                self._misses += 1
                return None
            
            # Move to end (LRU)
            self._cache.move_to_end(normalized_key)
            self._hits += 1
            return entry.value
    
    async def set(self, key: str, value: T, ttl: int | None = None) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        normalized_key = self._make_key(key)
        ttl = ttl if ttl is not None else self.default_ttl
        
        async with self._lock:
            # Evict oldest entries if at capacity
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
            
            self._cache[normalized_key] = CacheEntry(
                value=value,
                expires_at=time.time() + ttl,
            )
    
    async def delete(self, key: str) -> bool:
        """
        Delete entry from cache.
        
        Returns:
            True if entry was deleted, False if not found
        """
        normalized_key = self._make_key(key)
        
        async with self._lock:
            if normalized_key in self._cache:
                del self._cache[normalized_key]
                return True
            return False
    
    async def clear(self) -> None:
        """Clear all entries from cache."""
        async with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
    
    async def cleanup_expired(self) -> int:
        """
        Remove all expired entries.
        
        Returns:
            Number of entries removed
        """
        async with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired
            ]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)
    
    @property
    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0.0
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(hit_rate, 2),
        }


# Global cache instances
# Cache for full analysis results (5 minutes TTL)
analysis_cache: TTLCache[dict[str, Any]] = TTLCache(max_size=500, default_ttl=300)

# Cache for WHOIS data (1 hour TTL - WHOIS data changes rarely)
whois_cache: TTLCache[dict[str, Any]] = TTLCache(max_size=1000, default_ttl=3600)

# Cache for DNS lookups (5 minutes TTL)
dns_cache: TTLCache[list[str]] = TTLCache(max_size=1000, default_ttl=300)


async def get_cached_or_compute(
    cache: TTLCache[T],
    key: str,
    compute_func,
    ttl: int | None = None,
) -> T:
    """
    Get value from cache or compute it.
    
    Args:
        cache: Cache instance
        key: Cache key
        compute_func: Async function to compute value if not cached
        ttl: Optional TTL override
        
    Returns:
        Cached or computed value
    """
    cached = await cache.get(key)
    if cached is not None:
        return cached
    
    # Compute the value
    value = await compute_func()
    
    # Store in cache
    await cache.set(key, value, ttl)
    
    return value
