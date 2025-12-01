"""Aggregator for all scoring modules."""

import asyncio
from dataclasses import dataclass, field
from typing import Any

from .base import BaseScorer, ScoreResult
from .domain_age import DomainAgeScorer
from .ssl_checker import SSLScorer
from .url_analyzer import URLAnalyzerScorer
from .content_analyzer import ContentAnalyzerScorer
from .dns_analyzer import DNSAnalyzerScorer
from .dropshipping_analyzer import DropshippingAnalyzer
from .reputation_scorer import ReputationScorer
from cache import analysis_cache


@dataclass
class LegitimacyReport:
    """Complete legitimacy report for a URL."""
    
    url: str
    overall_score: float  # 0-100
    risk_level: str  # "critical", "high", "medium", "low", "safe"
    results: list[ScoreResult] = field(default_factory=list)
    summary: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "url": self.url,
            "overall_score": round(self.overall_score, 1),
            "risk_level": self.risk_level,
            "summary": self.summary,
            "scores": [
                {
                    "name": r.name,
                    "score": round(r.score, 1),
                    "weight": r.weight,
                    "weighted_score": round(r.weighted_score, 1),
                    "details": r.details,
                    "warnings": r.warnings,
                    "errors": r.errors,
                }
                for r in self.results
            ],
        }


class LegitimacyScorer:
    """
    Main scorer that aggregates all individual scoring modules.
    
    Calculates an overall legitimacy score by combining weighted scores
    from multiple analysis modules.
    """
    
    def __init__(self):
        # Initialize all scorers with their weights
        # Higher weight = more importance in final score
        self.scorers: list[BaseScorer] = [
            DomainAgeScorer(weight=2.0),       # Domain age is very important
            SSLScorer(weight=0.5),             # SSL is common now, less critical
            URLAnalyzerScorer(weight=1.0),     # URL patterns matter
            ContentAnalyzerScorer(weight=1.8), # Content analysis is key
            DNSAnalyzerScorer(weight=0.8),     # DNS info is supporting
            DropshippingAnalyzer(weight=1.5),  # Dropshipping detection
            ReputationScorer(weight=2.5),      # Trustpilot reputation (high weight)
        ]
    
    def _calculate_risk_level(self, score: float) -> str:
        """Determine risk level from overall score."""
        if score >= 80:
            return "safe"
        elif score >= 60:
            return "low"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "high"
        else:
            return "critical"
    
    def _generate_summary(self, score: float, results: list[ScoreResult]) -> str:
        """Generate a human-readable summary."""
        risk_level = self._calculate_risk_level(score)
        
        all_warnings = []
        all_errors = []
        for result in results:
            all_warnings.extend(result.warnings)
            all_errors.extend(result.errors)
        
        if risk_level == "safe":
            summary = "This website appears to be legitimate and trustworthy."
        elif risk_level == "low":
            summary = "This website appears mostly legitimate with minor concerns."
        elif risk_level == "medium":
            summary = "This website has some suspicious characteristics. Exercise caution."
        elif risk_level == "high":
            summary = "This website shows multiple warning signs. Be very careful."
        else:
            summary = "This website is highly suspicious and potentially dangerous. Avoid interaction."
        
        if all_warnings:
            top_warnings = all_warnings[:3]
            summary += f" Key concerns: {'; '.join(top_warnings)}."
        
        if all_errors:
            summary += f" Note: Some checks failed ({len(all_errors)} errors)."
        
        return summary
    
    async def analyze(self, url: str, parallel: bool = True, use_cache: bool = True) -> LegitimacyReport:
        """
        Perform complete legitimacy analysis on a URL.
        
        Args:
            url: The URL to analyze
            parallel: Whether to run scorers in parallel (faster) or sequentially
            use_cache: Whether to use cached results if available
            
        Returns:
            LegitimacyReport with overall score and individual results
        """
        # Check cache first
        if use_cache:
            cached = await analysis_cache.get(url)
            if cached is not None:
                # Reconstruct ScoreResults from cached dict
                results = [
                    ScoreResult(
                        name=s["name"],
                        score=s["score"],
                        weight=s["weight"],
                        details=s["details"],
                        warnings=s["warnings"],
                        errors=s["errors"],
                    )
                    for s in cached["scores"]
                ]
                return LegitimacyReport(
                    url=cached["url"],
                    overall_score=cached["overall_score"],
                    risk_level=cached["risk_level"],
                    results=results,
                    summary=cached["summary"],
                )
        
        results: list[ScoreResult] = []
        
        if parallel:
            # Run all scorers in parallel
            tasks = [scorer.analyze(url) for scorer in self.scorers]
            results = await asyncio.gather(*tasks)
        else:
            # Run sequentially
            for scorer in self.scorers:
                result = await scorer.analyze(url)
                results.append(result)
        
        # Calculate weighted average
        total_weight = sum(r.weight for r in results)
        weighted_sum = sum(r.weighted_score for r in results)
        
        overall_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        # Apply penalties for critical issues
        critical_penalties = 0
        for result in results:
            # SSL failures are critical
            if result.name == "SSL Certificate" and result.score < 30:
                critical_penalties += 10
            # Multiple errors reduce confidence
            if len(result.errors) > 0:
                critical_penalties += 5
        
        overall_score = max(0, overall_score - critical_penalties)
        
        risk_level = self._calculate_risk_level(overall_score)
        summary = self._generate_summary(overall_score, results)
        
        report = LegitimacyReport(
            url=url,
            overall_score=overall_score,
            risk_level=risk_level,
            results=results,
            summary=summary,
        )
        
        # Cache the result
        if use_cache:
            await analysis_cache.set(url, report.to_dict())
        
        return report
    
    async def quick_check(self, url: str) -> dict[str, Any]:
        """
        Perform a quick legitimacy check with just essential scorers.
        
        Faster than full analyze() but less comprehensive.
        """
        quick_scorers = [
            URLAnalyzerScorer(weight=1.0),
            SSLScorer(weight=1.0),
        ]
        
        tasks = [scorer.analyze(url) for scorer in quick_scorers]
        results = await asyncio.gather(*tasks)
        
        total_weight = sum(r.weight for r in results)
        weighted_sum = sum(r.weighted_score for r in results)
        overall_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        return {
            "url": url,
            "score": round(overall_score, 1),
            "risk_level": self._calculate_risk_level(overall_score),
            "quick_check": True,
        }
