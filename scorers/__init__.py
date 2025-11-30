"""Scoring modules for website legitimacy analysis."""

from .domain_age import DomainAgeScorer
from .ssl_checker import SSLScorer
from .url_analyzer import URLAnalyzerScorer
from .content_analyzer import ContentAnalyzerScorer
from .dns_analyzer import DNSAnalyzerScorer
from .aggregator import LegitimacyScorer

__all__ = [
    "DomainAgeScorer",
    "SSLScorer",
    "URLAnalyzerScorer",
    "ContentAnalyzerScorer",
    "DNSAnalyzerScorer",
    "LegitimacyScorer",
]
