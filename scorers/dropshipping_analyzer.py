"""Dropshipping detection module."""

import re
from typing import Any

from bs4 import BeautifulSoup

from .base import BaseScorer, ScoreResult
from http_client import fetch_url


class DropshippingAnalyzer(BaseScorer):
    """
    Score based on dropshipping indicators.
    
    Analyzes:
    - E-commerce platform signatures (Shopify, etc.)
    - Known dropshipping apps and plugins
    - Suspicious shipping/refund policies
    - Social proof widgets (fake sales)
    - Product image patterns
    """
    
    @property
    def name(self) -> str:
        return "Dropshipping Analysis"
    
    async def _fetch_content(self, url: str) -> tuple[str, int, dict[str, str]]:
        """Fetch webpage content using shared HTTP client."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        # Use shared client with connection pooling
        return await fetch_url(url, timeout=10.0)
    
    def _analyze_headers(self, headers: dict[str, str]) -> tuple[float, list[str], dict[str, Any]]:
        """Analyze HTTP headers for platform signatures."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        # Normalize headers to lowercase
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check for Shopify headers
        if 'x-shopify-stage' in headers_lower or \
           'shopify-api-version' in headers_lower or \
           'server' in headers_lower and 'shopify' in headers_lower['server'].lower():
            details["platform_header"] = "Shopify"
            # Strong signal for Shopify
        
        return score_delta, warnings, details

    def _analyze_platform(self, soup: BeautifulSoup, html: str, headers: dict[str, str] = None) -> tuple[float, list[str], dict[str, Any]]:
        """Identify e-commerce platform."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        platform = "Unknown"
        
        # Check headers first
        if headers:
            _, _, header_details = self._analyze_headers(headers)
            details.update(header_details)
            if header_details.get("platform_header") == "Shopify":
                platform = "Shopify"
        
        # Check for Shopify in HTML if not found in headers
        if platform == "Unknown":
            if "shopify" in html.lower() or soup.find('script', string=re.compile(r'Shopify')):
                platform = "Shopify"
        
        # Check for WooCommerce
        if platform == "Unknown" and ("woocommerce" in html.lower() or "wp-content" in html.lower()):
            platform = "WooCommerce"
            
        details["platform"] = platform
        return score_delta, warnings, details

    def _analyze_dropshipping_apps(self, html: str) -> tuple[float, list[str], dict[str, Any]]:
        """Check for known dropshipping apps."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        # List of common dropshipping/social proof apps
        suspicious_apps = [
            (r'ali-reviews', "AliReviews (AliExpress reviews importer)"),
            (r'loox', "Loox (Photo reviews, often used for social proof)"),
            (r'oberlo', "Oberlo (AliExpress dropshipping tool)"),
            (r'dsers', "DSers (AliExpress dropshipping tool)"),
            (r'cjdropshipping', "CJ Dropshipping"),
            (r'spocket', "Spocket"),
            (r'printful', "Printful (Print on demand)"),
            (r'sales-popup', "Sales Popup (Fake social proof)"),
            (r'countdown-timer', "Countdown Timer (False urgency)"),
            (r'trust-badge', "Trust Badge (Generic trust seals)"),
        ]
        
        found_apps = []
        for pattern, name in suspicious_apps:
            if re.search(pattern, html, re.IGNORECASE):
                found_apps.append(name)
                score_delta -= 5  # Small penalty for each dropshipping tool
        
        if found_apps:
            warnings.append(f"Detected dropshipping/marketing apps: {', '.join(found_apps)}")
            details["detected_apps"] = found_apps
            
            # Higher penalty if multiple tools are used
            if len(found_apps) >= 3:
                score_delta -= 10
                warnings.append("High usage of dropshipping tools detected")
        
        return score_delta, warnings, details

    def _analyze_content_keywords(self, soup: BeautifulSoup) -> tuple[float, list[str], dict[str, Any]]:
        """Check for suspicious keywords in text."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        text = soup.get_text().lower()
        
        # Keywords often associated with low-quality dropshipping
        suspicious_phrases = [
            (r'please allow \d+-\d+ (business )?days', "Long shipping times"),
            (r'shipping takes \d+-\d+ weeks', "Long shipping times"),
            (r'due to high demand', "Generic 'high demand' excuse"),
            (r'just pay shipping', "Free+Shipping model (often deceptive)"),
            (r'limited time only', "False urgency"),
            (r'huge sale', "Generic sales hype"),
            (r'50% off today', "Generic deep discount"),
        ]
        
        found_phrases = []
        for pattern, description in suspicious_phrases:
            if re.search(pattern, text):
                found_phrases.append(description)
                score_delta -= 5
        
        if found_phrases:
            details["suspicious_phrases"] = found_phrases
            warnings.append(f"Suspicious content phrases: {', '.join(found_phrases)}")
            
        return score_delta, warnings, details

    def _analyze_contact_and_social(self, soup: BeautifulSoup) -> tuple[float, list[str], dict[str, Any]]:
        """Check contact info and social links."""
        score_delta = 0.0
        warnings: list[str] = []
        details: dict[str, Any] = {}
        
        # Check for generic email providers
        text = soup.get_text().lower()
        generic_domains = [r'@gmail\.com', r'@yahoo\.com', r'@hotmail\.com', r'@outlook\.com']
        found_generic = []
        for domain in generic_domains:
            if re.search(domain, text):
                found_generic.append(domain.replace(r'\\', ''))
        
        if found_generic:
            warnings.append(f"Uses generic email domain: {', '.join(found_generic)}")
            score_delta -= 5
            details["generic_emails"] = True

        # Check for placeholder social links
        social_links = soup.find_all('a', href=True)
        suspicious_socials = 0
        for link in social_links:
            href = link.get('href', '').lower()
            text = link.get_text().lower()
            
            # Check if it looks like a social link but is empty or default
            is_social_url = any(x in href for x in ['facebook.com', 'instagram.com', 'twitter.com', 'tiktok.com'])
            is_social_text = any(x in text for x in ['facebook', 'instagram', 'twitter', 'tiktok'])
            
            if is_social_url:
                # Suspicious if it points to root, shopify, or contains placeholder
                if href.endswith('#') or 'shopify.com' in href or href.count('/') <= 3 or 'placeholder' in href:
                    suspicious_socials += 1
            elif (href == '#' or href == '/') and is_social_text:
                # Suspicious if it's an empty link with social text
                suspicious_socials += 1
        
        if suspicious_socials > 0:
            warnings.append("Contains placeholder/empty social media links")
            score_delta -= 5
            details["suspicious_social_links"] = suspicious_socials
            
        return score_delta, warnings, details

    async def analyze(self, url: str) -> ScoreResult:
        """Analyze for dropshipping indicators."""
        score = 100.0
        warnings: list[str] = []
        details: dict[str, Any] = {"url": url}
        
        try:
            html, status_code, headers = await self._fetch_content(url)
            
            if status_code >= 400:
                return self._create_result(score=50.0, details=details, errors=[f"HTTP {status_code}"])
            
            soup = BeautifulSoup(html, 'html.parser')
            
            # Platform analysis
            _, plat_warnings, plat_details = self._analyze_platform(soup, html, headers)
            warnings.extend(plat_warnings)
            details.update(plat_details)
            
            # App analysis
            app_delta, app_warnings, app_details = self._analyze_dropshipping_apps(html)
            score += app_delta
            warnings.extend(app_warnings)
            details.update(app_details)
            
            # Content analysis
            content_delta, content_warnings, content_details = self._analyze_content_keywords(soup)
            score += content_delta
            warnings.extend(content_warnings)
            details.update(content_details)
            
            # Contact and Social analysis
            social_delta, social_warnings, social_details = self._analyze_contact_and_social(soup)
            score += social_delta
            warnings.extend(social_warnings)
            details.update(social_details)
            
            # Adjust score based on findings
            if details.get("platform") == "Shopify":
                indicators = 0
                if len(details.get("detected_apps", [])) > 0: indicators += 1
                if len(details.get("suspicious_phrases", [])) > 0: indicators += 1
                if details.get("generic_emails"): indicators += 1
                if details.get("suspicious_social_links", 0) > 0: indicators += 1
                
                if indicators >= 2:
                    score -= 15
                    warnings.append(f"Shopify store with multiple ({indicators}) dropshipping indicators")
            
            return self._create_result(
                score=score,
                details=details,
                warnings=warnings
            )
            
        except Exception as e:
            return self._create_result(
                score=50.0,
                details=details,
                errors=[f"Analysis failed: {str(e)}"]
            )
