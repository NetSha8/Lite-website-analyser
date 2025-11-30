"""SSL Certificate scoring module."""

import asyncio
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .base import BaseScorer, ScoreResult

# Shared thread pool for blocking SSL checks
_ssl_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="ssl")


class SSLScorer(BaseScorer):
    """
    Score based on SSL/TLS certificate analysis.
    
    Checks:
    - Certificate validity
    - Certificate expiration
    - Certificate issuer (self-signed vs CA-signed)
    - Certificate chain completeness
    - Hostname matching
    """
    
    @property
    def name(self) -> str:
        return "SSL Certificate"
    
    def _extract_hostname(self, url: str) -> tuple[str, int]:
        """Extract hostname and port from URL."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path.split('/')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        return hostname, port
    
    def _get_certificate_info(self, hostname: str, port: int = 443) -> dict[str, Any]:
        """Retrieve SSL certificate information."""
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                return {
                    "cert": cert,
                    "cipher": cipher,
                    "version": version,
                }
    
    def _parse_cert_date(self, date_str: str) -> datetime:
        """Parse certificate date string to datetime."""
        # SSL cert dates are in format: 'Mon DD HH:MM:SS YYYY GMT'
        return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    
    def _analyze_certificate(self, cert_info: dict[str, Any], hostname: str) -> tuple[float, dict[str, Any], list[str]]:
        """
        Analyze certificate and return score, details, and warnings.
        """
        cert = cert_info["cert"]
        warnings: list[str] = []
        score = 100.0
        
        details: dict[str, Any] = {
            "cipher": cert_info["cipher"][0] if cert_info["cipher"] else None,
            "tls_version": cert_info["version"],
        }
        
        # Check certificate dates
        not_before = self._parse_cert_date(cert["notBefore"])
        not_after = self._parse_cert_date(cert["notAfter"])
        now = datetime.now(timezone.utc)
        
        details["valid_from"] = not_before.isoformat()
        details["valid_until"] = not_after.isoformat()
        
        # Check if certificate is currently valid
        if now < not_before:
            warnings.append("Certificate is not yet valid")
            score -= 50
        
        if now > not_after:
            warnings.append("Certificate has expired")
            score -= 60
        else:
            # Check days until expiration
            days_until_expiry = (not_after - now).days
            details["days_until_expiry"] = days_until_expiry
            
            if days_until_expiry < 7:
                warnings.append("Certificate expires in less than 7 days")
                score -= 20
            elif days_until_expiry < 30:
                warnings.append("Certificate expires in less than 30 days")
                score -= 10
        
        # Check issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        
        details["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
        details["subject"] = subject.get("commonName", "Unknown")
        
        # Check for self-signed certificate
        if issuer == subject:
            warnings.append("Certificate appears to be self-signed")
            score -= 30
        
        # Check hostname matching
        san = cert.get("subjectAltName", [])
        valid_names = [name for type_, name in san if type_ == "DNS"]
        valid_names.append(subject.get("commonName", ""))
        
        hostname_matches = any(
            self._match_hostname(hostname, valid_name)
            for valid_name in valid_names
        )
        
        details["valid_hostnames"] = valid_names
        
        if not hostname_matches:
            warnings.append(f"Hostname '{hostname}' does not match certificate")
            score -= 40
        
        # Check TLS version
        tls_version = cert_info["version"]
        if tls_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0"):
            warnings.append(f"Outdated TLS version: {tls_version}")
            score -= 20
        elif tls_version == "TLSv1.1":
            warnings.append(f"TLS 1.1 is deprecated")
            score -= 10
        
        # Bonus for modern TLS
        if tls_version == "TLSv1.3":
            score = min(100, score + 5)
        
        return max(0, score), details, warnings
    
    def _match_hostname(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches the certificate pattern (supports wildcards)."""
        if pattern.startswith("*."):
            # Wildcard certificate
            suffix = pattern[2:]
            parts = hostname.split(".", 1)
            return len(parts) == 2 and parts[1] == suffix
        return hostname.lower() == pattern.lower()
    
    async def analyze(self, url: str) -> ScoreResult:
        """Analyze SSL certificate for the given URL."""
        hostname, port = self._extract_hostname(url)
        details: dict[str, Any] = {"hostname": hostname, "port": port}
        
        # Check if it's HTTP (no SSL)
        if url.startswith("http://"):
            return self._create_result(
                score=20.0,
                details=details,
                warnings=["Site uses HTTP instead of HTTPS - no encryption"],
            )
        
        try:
            # Run SSL check in thread pool (it's blocking)
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(
                _ssl_executor, self._get_certificate_info, hostname, port
            )
            
            score, cert_details, warnings = self._analyze_certificate(cert_info, hostname)
            details.update(cert_details)
            
            return self._create_result(
                score=score,
                details=details,
                warnings=warnings,
            )
            
        except ssl.SSLCertVerificationError as e:
            return self._create_result(
                score=10.0,
                details=details,
                errors=[f"SSL certificate verification failed: {str(e)}"],
            )
        except ssl.SSLError as e:
            return self._create_result(
                score=15.0,
                details=details,
                errors=[f"SSL error: {str(e)}"],
            )
        except socket.timeout:
            return self._create_result(
                score=30.0,
                details=details,
                errors=["Connection timeout while checking SSL"],
            )
        except socket.gaierror as e:
            return self._create_result(
                score=20.0,
                details=details,
                errors=[f"DNS resolution failed: {str(e)}"],
            )
        except Exception as e:
            return self._create_result(
                score=25.0,
                details=details,
                errors=[f"SSL check failed: {str(e)}"],
            )
