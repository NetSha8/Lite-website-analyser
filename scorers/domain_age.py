"""Domain age scoring module using WHOIS data."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import whois
import tldextract

from .base import BaseScorer, ScoreResult
from cache import whois_cache

# Shared thread pool for blocking WHOIS calls
_whois_executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="whois")


class DomainAgeScorer(BaseScorer):
    """
    Score based on domain age.
    
    Older domains are generally more trustworthy.
    - Domains < 30 days: Very suspicious
    - Domains < 6 months: Suspicious  
    - Domains < 1 year: Slightly suspicious
    - Domains < 2 years: Neutral
    - Domains > 2 years: Trustworthy
    - Domains > 5 years: Very trustworthy
    """
    
    @property
    def name(self) -> str:
        return "Domain Age"
    
    def _extract_domain(self, url: str) -> str:
        """Extract the registrable domain from a URL."""
        # Handle URLs without scheme
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def _calculate_age_score(self, creation_date: datetime) -> tuple[float, int]:
        """
        Calculate score based on domain age.
        
        Returns:
            Tuple of (score, age_in_days)
        """
        now = datetime.now(timezone.utc)
        
        # Make creation_date timezone aware if it isn't
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        
        age_days = (now - creation_date).days
        
        if age_days < 0:
            # Future date - very suspicious (data error or manipulation)
            return 0.0, age_days
        elif age_days < 30:
            # Less than 1 month - very suspicious
            return 10.0 + (age_days / 30) * 15, age_days
        elif age_days < 180:
            # 1-6 months - suspicious
            return 25.0 + ((age_days - 30) / 150) * 25, age_days
        elif age_days < 365:
            # 6 months - 1 year - slightly suspicious
            return 50.0 + ((age_days - 180) / 185) * 15, age_days
        elif age_days < 730:
            # 1-2 years - neutral to slightly trustworthy
            return 65.0 + ((age_days - 365) / 365) * 15, age_days
        elif age_days < 1825:
            # 2-5 years - trustworthy
            return 80.0 + ((age_days - 730) / 1095) * 10, age_days
        else:
            # More than 5 years - very trustworthy
            return 90.0 + min(10, (age_days - 1825) / 1825 * 10), age_days
    
    async def analyze(self, url: str) -> ScoreResult:
        """Analyze domain age for the given URL."""
        domain = self._extract_domain(url)
        warnings: list[str] = []
        details: dict[str, Any] = {"domain": domain}
        
        try:
            # Check cache first
            cached_whois = await whois_cache.get(domain)
            
            if cached_whois is not None:
                whois_data = cached_whois
                details["cached"] = True
            else:
                # Run WHOIS lookup in thread pool (it's blocking)
                loop = asyncio.get_event_loop()
                whois_data = await loop.run_in_executor(_whois_executor, whois.whois, domain)
                
                # Cache the result (as dict for serialization)
                if whois_data:
                    await whois_cache.set(domain, {
                        "domain_name": getattr(whois_data, 'domain_name', None),
                        "creation_date": getattr(whois_data, 'creation_date', None),
                        "expiration_date": getattr(whois_data, 'expiration_date', None),
                        "registrar": getattr(whois_data, 'registrar', None),
                    })
            
            # Handle cached dict vs whois object
            if isinstance(whois_data, dict):
                domain_name = whois_data.get('domain_name')
                creation_date = whois_data.get('creation_date')
                expiration_date = whois_data.get('expiration_date')
                registrar = whois_data.get('registrar')
            else:
                domain_name = getattr(whois_data, 'domain_name', None)
                creation_date = getattr(whois_data, 'creation_date', None)
                expiration_date = getattr(whois_data, 'expiration_date', None)
                registrar = getattr(whois_data, 'registrar', None)
            
            if whois_data is None or domain_name is None:
                return self._create_result(
                    score=20.0,
                    details=details,
                    errors=["Could not retrieve WHOIS data - domain may not exist"],
                )
            
            # Handle case where creation_date is a list
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date is None:
                return self._create_result(
                    score=30.0,
                    details=details,
                    warnings=["Creation date not available in WHOIS data"],
                )
            
            score, age_days = self._calculate_age_score(creation_date)
            
            # Calculate human-readable age
            if age_days < 30:
                age_str = f"{age_days} days"
            elif age_days < 365:
                age_str = f"{age_days // 30} months"
            else:
                years = age_days // 365
                months = (age_days % 365) // 30
                age_str = f"{years} years, {months} months"
            
            # Format expiration date
            exp_date_str = None
            if expiration_date:
                if isinstance(expiration_date, list):
                    exp_date_str = expiration_date[0].isoformat()
                else:
                    exp_date_str = expiration_date.isoformat()
            
            details["creation_date"] = creation_date.isoformat()
            details["age_days"] = age_days
            details["age_human"] = age_str
            details["registrar"] = registrar
            details["expiration_date"] = exp_date_str
            
            # Additional warnings
            if age_days < 30:
                warnings.append("Domain was created very recently (less than 30 days)")
            elif age_days < 180:
                warnings.append("Domain is relatively new (less than 6 months)")
            
            # Check expiration date
            exp_date = expiration_date
            if isinstance(exp_date, list):
                exp_date = exp_date[0]
            if exp_date:
                if exp_date.tzinfo is None:
                    exp_date = exp_date.replace(tzinfo=timezone.utc)
                days_until_expiry = (exp_date - datetime.now(timezone.utc)).days
                if days_until_expiry < 30:
                    warnings.append("Domain expires very soon")
                    score = max(0, score - 10)
                elif days_until_expiry < 90:
                    warnings.append("Domain expires in less than 3 months")
                    score = max(0, score - 5)
            
            return self._create_result(
                score=score,
                details=details,
                warnings=warnings,
            )
            
        except Exception as e:
            return self._create_result(
                score=25.0,
                details=details,
                errors=[f"WHOIS lookup failed: {str(e)}"],
            )
