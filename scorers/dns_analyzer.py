"""DNS analysis scoring module."""

import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .base import BaseScorer, ScoreResult
from cache import dns_cache

# Shared thread pool for blocking DNS calls
_dns_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="dns")


class DNSAnalyzerScorer(BaseScorer):
    """
    Score based on DNS analysis.
    
    Analyzes:
    - DNS resolution success
    - Multiple IP addresses (CDN detection)
    - Reverse DNS lookup
    - DNS response time
    """
    
    @property
    def name(self) -> str:
        return "DNS Analysis"
    
    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname or parsed.path.split('/')[0]
    
    def _resolve_dns(self, hostname: str) -> list[str]:
        """Resolve DNS to get IP addresses."""
        try:
            # Get all IP addresses
            result = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list(set(str(addr[4][0]) for addr in result))
            return ips
        except socket.gaierror:
            return []
    
    def _reverse_dns(self, ip: str) -> str | None:
        """Perform reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is a private address."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    def _is_localhost(self, ip: str) -> bool:
        """Check if IP is localhost."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_loopback
        except ValueError:
            return False
    
    async def analyze(self, url: str) -> ScoreResult:
        """Analyze DNS for the given URL."""
        hostname = self._extract_hostname(url)
        details: dict[str, Any] = {"hostname": hostname}
        warnings: list[str] = []
        score = 100.0
        
        try:
            loop = asyncio.get_event_loop()
            
            # Check DNS cache first
            cached_ips = await dns_cache.get(hostname)
            
            if cached_ips is not None:
                ips = cached_ips
                details["cached"] = True
            else:
                # Resolve DNS using thread pool
                ips = await loop.run_in_executor(_dns_executor, self._resolve_dns, hostname)
                
                # Cache the result
                if ips:
                    await dns_cache.set(hostname, ips)
            
            if not ips:
                return self._create_result(
                    score=10.0,
                    details=details,
                    errors=["DNS resolution failed - domain does not exist or is not configured"],
                )
            
            details["ip_addresses"] = ips
            details["ip_count"] = len(ips)
            
            # Check for private/localhost IPs
            private_ips = [ip for ip in ips if self._is_private_ip(ip)]
            localhost_ips = [ip for ip in ips if self._is_localhost(ip)]
            
            if localhost_ips:
                warnings.append("Domain resolves to localhost")
                score -= 40
                details["localhost"] = True
            elif private_ips:
                warnings.append("Domain resolves to private IP address")
                score -= 30
                details["private_ips"] = private_ips
            
            # Multiple IPs can indicate CDN (positive) or rotation (neutral)
            if len(ips) > 1:
                details["uses_multiple_ips"] = True
                # CDNs often use multiple IPs - this is generally a good sign
                score += 5
            
            # Reverse DNS lookup for first IP
            first_ip = ips[0] if ips else None
            if first_ip and not self._is_private_ip(first_ip) and not self._is_localhost(first_ip):
                reverse_hostname = await loop.run_in_executor(_dns_executor, self._reverse_dns, first_ip)
                
                if reverse_hostname:
                    details["reverse_dns"] = reverse_hostname
                    
                    # Check if reverse DNS matches forward DNS
                    if hostname.lower() in reverse_hostname.lower() or reverse_hostname.lower() in hostname.lower():
                        details["reverse_dns_matches"] = True
                        score += 5
                    else:
                        details["reverse_dns_matches"] = False
                        # Mismatched reverse DNS is common but slightly suspicious
                        warnings.append("Reverse DNS does not match domain")
                        score -= 5
                else:
                    details["reverse_dns"] = None
                    warnings.append("No reverse DNS configured")
                    score -= 5
            
            # Check for known hosting patterns in reverse DNS
            reverse_dns = details.get("reverse_dns")
            if reverse_dns:
                rdns = reverse_dns.lower()
                
                # Known legitimate hosting providers
                legitimate_hosts = [
                    "amazonaws.com", "cloudflare", "google", "microsoft",
                    "azure", "akamai", "fastly", "cloudfront",
                    "github.io", "netlify", "vercel", "heroku",
                ]
                
                if any(host in rdns for host in legitimate_hosts):
                    details["known_host"] = True
                    score += 5
            
            return self._create_result(
                score=max(0, min(100, score)),
                details=details,
                warnings=warnings,
            )
            
        except Exception as e:
            return self._create_result(
                score=30.0,
                details=details,
                errors=[f"DNS analysis failed: {str(e)}"],
            )
