"""Base class for all scorers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScoreResult:
    """Result of a scoring operation."""
    
    name: str
    score: float  # 0.0 (suspicious) to 100.0 (legitimate)
    weight: float  # Importance of this score in final calculation
    details: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    
    @property
    def weighted_score(self) -> float:
        """Calculate the weighted score."""
        return self.score * self.weight


class BaseScorer(ABC):
    """Abstract base class for all scoring modules."""
    
    def __init__(self, weight: float = 1.0):
        self.weight = weight
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this scorer."""
        pass
    
    @abstractmethod
    async def analyze(self, url: str) -> ScoreResult:
        """
        Analyze a URL and return a score.
        
        Args:
            url: The URL to analyze
            
        Returns:
            ScoreResult with score from 0-100
        """
        pass
    
    def _create_result(
        self,
        score: float,
        details: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
        errors: list[str] | None = None,
    ) -> ScoreResult:
        """Helper to create a ScoreResult."""
        return ScoreResult(
            name=self.name,
            score=max(0.0, min(100.0, score)),  # Clamp between 0 and 100
            weight=self.weight,
            details=details or {},
            warnings=warnings or [],
            errors=errors or [],
        )
