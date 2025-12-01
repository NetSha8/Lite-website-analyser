"""Reputation scoring based on Trustpilot ratings."""

import re
from typing import Any

import tldextract
from bs4 import BeautifulSoup

from .base import BaseScorer, ScoreResult
from http_client import fetch_url


class ReputationScorer(BaseScorer):
    """
    Score based on Trustpilot reputation.
    
    Analyzes:
    - Trustpilot TrustScore (star rating)
    - Number of reviews (more reviews = more reliable)
    """
    
    @property
    def name(self) -> str:
        return "Reputation (Trustpilot)"
    
    def _extract_domain(self, url: str) -> str:
        """Extract the registrable domain from a URL."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    
    async def _fetch_trustpilot_page(self, domain: str) -> tuple[str, int]:
        """Fetch Trustpilot page for a domain."""
        trustpilot_url = f"https://www.trustpilot.com/review/{domain}"
        
        try:
            html, status_code, _ = await fetch_url(trustpilot_url, timeout=5.0)
            return html, status_code
        except Exception as e:
            raise Exception(f"Failed to fetch Trustpilot page: {str(e)}")
    
    def _parse_trustscore(self, html: str) -> tuple[float | None, int | None]:
        """Parse TrustScore and review count from HTML."""
        soup = BeautifulSoup(html, 'html.parser')
        
        trust_score = None
        review_count = None
        
        # Method 1: Try to find in JSON-LD structured data
        script_tags = soup.find_all('script', type='application/ld+json')
        for script in script_tags:
            try:
                import json
                data = json.loads(script.string)
                if isinstance(data, dict):
                    # Check for aggregateRating
                    if 'aggregateRating' in data:
                        rating = data['aggregateRating']
                        if 'ratingValue' in rating:
                            trust_score = float(rating['ratingValue'])
                        if 'reviewCount' in rating:
                            review_count = int(rating['reviewCount'])
                        break
            except:
                continue
        
        # Method 2: Extract from page title (e.g., "Scandinaviansmiles Reviews | Read Customer Service Reviews")
        # Often the OG description contains the TrustScore
        if trust_score is None:
            og_desc = soup.find('meta', property='og:description')
            if og_desc:
                desc_content = og_desc.get('content', '')
                # Look for patterns like "TrustScore 1.5" or just numbers with "customers"
                match = re.search(r'TrustScore[:\s]+(\d+\.?\d*)', desc_content, re.I)
                if match:
                    trust_score = float(match.group(1))
                
                # Extract review count from description
                match = re.search(r'(\d+)\s+customers?', desc_content, re.I)
                if match:
                    review_count = int(match.group(1))
        
        # Method 3: Look for data attributes or aria labels
        # Trustpilot often uses data-* attributes
        if trust_score is None:
            # Try to find elements with star ratings or score data
            score_elements = soup.find_all(attrs={'data-rating-typography': True})
            for elem in score_elements:
                text = elem.get_text().strip()
                match = re.search(r'(\d+\.?\d*)', text)
                if match:
                    trust_score = float(match.group(1))
                    break
        
        # Method 4: Look in any element that might contain "TrustScore" text
        if trust_score is None:
            # Search for text containing trustscore
            body_text = soup.get_text()
            match = re.search(r'TrustScore[:\s]+(\d+\.?\d*)', body_text, re.I)
            if match:
                trust_score = float(match.group(1))
        
        # Method 5: Extract from page title
        if review_count is None:
            title = soup.find('title')
            if title:
                title_text = title.get_text()
                # Look for review count in title
                match = re.search(r'(\d+)\s+reviews?', title_text, re.I)
                if match:
                    review_count = int(match.group(1))
        
        # Method 6: Look for review count in visible text
        if review_count is None:
            # Often in format like "Based on 1,234 reviews" or just "681" in title
            text = soup.get_text()
            match = re.search(r'([\d,]+)\s+reviews?', text, re.I)
            if match:
                count_str = match.group(1).replace(',', '')
                try:
                    review_count = int(count_str)
                except ValueError:
                    pass
        
        return trust_score, review_count
    
    def _calculate_score(self, trust_score: float, review_count: int | None) -> tuple[float, list[str]]:
        """Calculate score from TrustScore and review count."""
        warnings: list[str] = []
        
        # Convert 1-5 star rating to 0-100 scale
        # 5.0 stars = 100, 1.0 star = 20
        base_score = (trust_score - 1.0) / 4.0 * 80.0 + 20.0
        
        # Adjust based on review count
        if review_count is not None:
            if review_count < 10:
                warnings.append(f"Very few reviews ({review_count}) - rating may not be reliable")
                base_score = max(0, base_score - 10)
            elif review_count < 50:
                warnings.append(f"Limited reviews ({review_count})")
                base_score = max(0, base_score - 5)
        
        # Add warnings based on score
        if trust_score < 2.0:
            warnings.append(f"Very poor Trustpilot rating: {trust_score}/5")
        elif trust_score < 3.0:
            warnings.append(f"Poor Trustpilot rating: {trust_score}/5")
        elif trust_score >= 4.5:
            # Good rating, but don't add a warning
            pass
        
        return base_score, warnings
    
    async def analyze(self, url: str) -> ScoreResult:
        """Analyze Trustpilot reputation for the given URL."""
        domain = self._extract_domain(url)
        details: dict[str, Any] = {"domain": domain}
        warnings: list[str] = []
        
        try:
            html, status_code = await self._fetch_trustpilot_page(domain)
            
            if status_code == 404:
                # Domain not found on Trustpilot - don't contribute to score
                result = self._create_result(
                    score=50.0,
                    details={**details, "trustpilot_found": False},
                    warnings=["Domain not found on Trustpilot"],
                )
                # Override weight to 0 so it doesn't affect overall score
                result.weight = 0.0
                return result
            elif status_code >= 400:
                result = self._create_result(
                    score=50.0,
                    details=details,
                    errors=[f"Trustpilot returned HTTP {status_code}"],
                )
                result.weight = 0.0
                return result
            
            trust_score, review_count = self._parse_trustscore(html)
            
            if trust_score is None:
                result = self._create_result(
                    score=50.0,
                    details={**details, "trustpilot_found": True, "parse_failed": True},
                    warnings=["Found Trustpilot page but could not parse score"],
                )
                result.weight = 0.0
                return result
            
            score, score_warnings = self._calculate_score(trust_score, review_count)
            warnings.extend(score_warnings)
            
            details["trustpilot_found"] = True
            details["trust_score"] = trust_score
            details["review_count"] = review_count
            details["trustpilot_url"] = f"https://www.trustpilot.com/review/{domain}"
            
            return self._create_result(
                score=score,
                details=details,
                warnings=warnings,
            )
            
        except Exception as e:
            result = self._create_result(
                score=50.0,
                details=details,
                errors=[f"Trustpilot lookup failed: {str(e)}"],
            )
            result.weight = 0.0
            return result
