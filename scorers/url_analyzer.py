"""URL pattern analysis scoring module."""

import re
from typing import Any
from urllib.parse import urlparse, parse_qs

import tldextract

from .base import BaseScorer, ScoreResult


# Common suspicious patterns in URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "bank", "paypal", "amazon", "apple", "microsoft",
    "google", "facebook", "instagram", "netflix", "support",
    "billing", "payment", "wallet", "crypto", "free", "winner",
    "prize", "gift", "offer", "bonus", "urgent", "alert",
    "suspended", "locked", "expire", "limited",
]

# Known legitimate TLDs that are often abused
SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq",  # Free TLDs
    "xyz", "top", "club", "online", "site", "website",
    "work", "click", "link", "buzz", "info",
]

# Legitimate popular TLDs
TRUSTED_TLDS = [
    "com", "org", "net", "edu", "gov", "mil",
    "co.uk", "co.jp", "de", "fr", "ca", "au",
]


class URLAnalyzerScorer(BaseScorer):
    """
    Score based on URL pattern analysis.
    
    Analyzes:
    - Domain length and complexity
    - Suspicious keywords in URL
    - TLD reputation
    - URL encoding and obfuscation
    - Number of subdomains
    - IP address usage
    - Suspicious characters and patterns
    """
    
    @property
    def name(self) -> str:
        return "URL Pattern"
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address."""
        # IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # IPv6
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        
        return bool(re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname))
    
    def _count_suspicious_keywords(self, url: str) -> list[str]:
        """Find suspicious keywords in URL."""
        url_lower = url.lower()
        found = []
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                found.append(keyword)
        return found
    
    def _analyze_domain_structure(self, url: str) -> dict[str, Any]:
        """Analyze domain structure."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        hostname = parsed.hostname or ""
        
        return {
            "hostname": hostname,
            "domain": extracted.domain,
            "suffix": extracted.suffix,
            "subdomain": extracted.subdomain,
            "subdomain_count": len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
            "path": parsed.path,
            "query": parsed.query,
            "full_domain": f"{extracted.domain}.{extracted.suffix}",
        }
    
    def _check_character_anomalies(self, url: str) -> list[str]:
        """Check for suspicious characters and patterns."""
        anomalies = []
        
        # Homograph attacks (mixed scripts)
        # Check for Cyrillic characters that look like Latin
        cyrillic_pattern = r'[а-яА-ЯёЁ]'
        if re.search(cyrillic_pattern, url):
            anomalies.append("Contains Cyrillic characters (possible homograph attack)")
        
        # Check for excessive URL encoding
        encoded_count = url.count('%')
        if encoded_count > 5:
            anomalies.append(f"Excessive URL encoding ({encoded_count} encoded characters)")
        
        # Check for @ symbol (URL can redirect)
        if '@' in url:
            anomalies.append("Contains @ symbol (possible URL obfuscation)")
        
        # Check for multiple dots in suspicious patterns
        if re.search(r'\.{2,}', url):
            anomalies.append("Contains consecutive dots")
        
        # Check for suspicious number patterns (like dates that might indicate phishing campaign)
        if re.search(r'-\d{6,}', url) or re.search(r'\d{10,}', url):
            anomalies.append("Contains suspicious number sequence")
        
        # Check for brand misspellings with extra characters
        misspelling_patterns = [
            (r'g[o0]{2,}gle', 'google'),
            (r'amaz[o0]n', 'amazon'),
            (r'faceb[o0]{2,}k', 'facebook'),
            (r'paypai|paypa1', 'paypal'),
            (r'micros[o0]ft', 'microsoft'),
            (r'app1e|appie', 'apple'),
        ]
        
        url_lower = url.lower()
        for pattern, brand in misspelling_patterns:
            if re.search(pattern, url_lower) and brand not in url_lower:
                anomalies.append(f"Possible {brand} misspelling/impersonation")
        
        return anomalies
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text (high entropy = random = suspicious)."""
        import math
        from collections import Counter
        
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        
        return entropy
    
    async def analyze(self, url: str) -> ScoreResult:
        """Analyze URL patterns."""
        score = 100.0
        warnings: list[str] = []
        details: dict[str, Any] = {"url": url}
        
        # Analyze domain structure
        structure = self._analyze_domain_structure(url)
        details.update(structure)
        
        # Check if using IP address instead of domain
        if self._is_ip_address(structure["hostname"]):
            warnings.append("URL uses IP address instead of domain name")
            score -= 30
            details["uses_ip"] = True
        else:
            details["uses_ip"] = False
        
        # Check TLD reputation
        suffix = structure["suffix"].lower()
        if suffix in SUSPICIOUS_TLDS:
            warnings.append(f"Uses suspicious TLD: .{suffix}")
            score -= 15
        elif suffix in TRUSTED_TLDS:
            score += 5  # Small bonus for trusted TLDs
        
        details["tld_category"] = (
            "suspicious" if suffix in SUSPICIOUS_TLDS
            else "trusted" if suffix in TRUSTED_TLDS
            else "neutral"
        )
        
        # Check domain length
        domain_length = len(structure["full_domain"])
        details["domain_length"] = domain_length
        
        if domain_length > 30:
            warnings.append("Unusually long domain name")
            score -= 10
        elif domain_length > 50:
            warnings.append("Excessively long domain name")
            score -= 20
        
        # Check subdomain count
        subdomain_count = structure["subdomain_count"]
        details["subdomain_count"] = subdomain_count
        
        if subdomain_count > 3:
            warnings.append(f"Excessive subdomains ({subdomain_count})")
            score -= 10 * (subdomain_count - 3)
        
        # Check for suspicious keywords
        suspicious_keywords = self._count_suspicious_keywords(url)
        if suspicious_keywords:
            details["suspicious_keywords"] = suspicious_keywords
            keyword_penalty = min(25, len(suspicious_keywords) * 5)
            score -= keyword_penalty
            
            if len(suspicious_keywords) >= 3:
                warnings.append(f"Multiple suspicious keywords: {', '.join(suspicious_keywords[:5])}")
            elif suspicious_keywords:
                warnings.append(f"Contains suspicious keyword(s): {', '.join(suspicious_keywords)}")
        
        # Check for character anomalies
        anomalies = self._check_character_anomalies(url)
        if anomalies:
            details["character_anomalies"] = anomalies
            warnings.extend(anomalies)
            score -= len(anomalies) * 15
        
        # Check URL entropy (randomness)
        domain_entropy = self._calculate_entropy(structure["domain"])
        details["domain_entropy"] = round(domain_entropy, 2)
        
        if domain_entropy > 4.0:
            warnings.append("Domain appears randomly generated")
            score -= 15
        
        # Check path length and complexity
        path = structure["path"]
        if len(path) > 100:
            warnings.append("Unusually long URL path")
            score -= 10
        
        # Check query string for suspicious patterns
        query = structure["query"]
        if query:
            query_params = parse_qs(query)
            if any(len(v[0]) > 100 for v in query_params.values() if v):
                warnings.append("Contains very long query parameter")
                score -= 10
            
            # Check for base64-like patterns in query
            base64_pattern = r'^[A-Za-z0-9+/]{20,}={0,2}$'
            for values in query_params.values():
                for val in values:
                    if re.match(base64_pattern, val):
                        warnings.append("Query contains encoded/obfuscated data")
                        score -= 10
                        break
        
        # Check for HTTPS
        if url.startswith("http://"):
            warnings.append("Uses insecure HTTP protocol")
            score -= 15
        
        return self._create_result(
            score=max(0, min(100, score)),
            details=details,
            warnings=warnings,
        )
