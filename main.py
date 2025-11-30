from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request, Form, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator

from scorers import LegitimacyScorer
from i18n import get_all_translations, detect_language_from_header, SUPPORTED_LANGUAGES, DEFAULT_LANGUAGE
from security import (
    SecurityHeadersMiddleware,
    RateLimiter,
    RateLimitMiddleware,
    validate_url,
    sanitize_for_html,
    URLValidationError,
)
from http_client import close_http_client
from cache import analysis_cache, whois_cache, dns_cache

# Setup templates
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle - startup and shutdown."""
    # Startup
    yield
    # Shutdown - cleanup resources
    await close_http_client()
    await analysis_cache.clear()
    await whois_cache.clear()
    await dns_cache.clear()


app = FastAPI(
    title="Heimdall API",
    description="A website legitimacy scoring API - Analyze URLs for potential phishing and fraud indicators",
    version="0.1.0",
    lifespan=lifespan,
    # Disable docs in production (uncomment for prod)
    # docs_url=None,
    # redoc_url=None,
)

# Add security middleware
app.add_middleware(SecurityHeadersMiddleware)

# Add rate limiting (30 req/min, 200 req/hour)
rate_limiter = RateLimiter(requests_per_minute=30, requests_per_hour=200)
app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)

# Initialize the scorer
scorer = LegitimacyScorer()


def get_lang(request: Request, lang_param: str | None = None) -> str:
    """Get the language from query param, cookie, or Accept-Language header."""
    # Priority: query param > cookie > Accept-Language header
    if lang_param and lang_param in SUPPORTED_LANGUAGES:
        return lang_param
    
    # Check cookie
    cookie_lang = request.cookies.get("lang")
    if cookie_lang and cookie_lang in SUPPORTED_LANGUAGES:
        return cookie_lang
    
    # Fallback to Accept-Language header
    accept_lang = request.headers.get("Accept-Language")
    return detect_language_from_header(accept_lang)


class AnalyzeRequest(BaseModel):
    """Request model for URL analysis."""
    url: str
    
    @field_validator('url')
    @classmethod
    def validate_url_field(cls, v: str) -> str:
        """Validate and sanitize the URL."""
        try:
            return validate_url(v)
        except URLValidationError as e:
            raise ValueError(str(e))
    
    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example.com"
            }
        }


class ScoreDetail(BaseModel):
    """Individual score detail."""
    name: str
    score: float
    weight: float
    weighted_score: float
    details: dict
    warnings: list[str]
    errors: list[str]


class AnalyzeResponse(BaseModel):
    """Response model for URL analysis."""
    url: str
    overall_score: float
    risk_level: str
    summary: str
    scores: list[ScoreDetail]


class QuickCheckResponse(BaseModel):
    """Response model for quick check."""
    url: str
    score: float
    risk_level: str
    quick_check: bool


# ============== UI Routes ==============

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, lang: str | None = None):
    """Serve the main UI page."""
    current_lang = get_lang(request, lang)
    translations = get_all_translations(current_lang)
    
    response = templates.TemplateResponse(
        "index.html", 
        {
            "request": request,
            "t": translations,
            "lang": current_lang,
        }
    )
    # Set language cookie for future requests (secure flags)
    response.set_cookie(
        key="lang",
        value=current_lang,
        max_age=365*24*60*60,
        httponly=True,
        samesite="strict"
    )
    return response


@app.post("/api/analyze", response_class=HTMLResponse)
async def analyze_for_ui(request: Request, url: str = Form(...), lang: str | None = None):
    """
    Analyze URL and return HTML fragment for HTMX.
    """
    current_lang = get_lang(request, lang)
    translations = get_all_translations(current_lang)
    
    # Validate URL
    try:
        validated_url = validate_url(url)
    except URLValidationError as e:
        error_title = translations.get("error_title", "Validation Error")
        error_message = sanitize_for_html(str(e))
        error_html = f'''
        <div class="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6">
            <div class="flex items-center gap-3">
                <svg class="w-6 h-6 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
                <div>
                    <h3 class="text-yellow-400 font-semibold">{error_title}</h3>
                    <p class="text-yellow-300/80 text-sm mt-1">{error_message}</p>
                </div>
            </div>
        </div>
        '''
        return HTMLResponse(content=error_html)
    
    try:
        report = await scorer.analyze(validated_url)
        result = report.to_dict()
        return templates.TemplateResponse(
            "results.html",
            {
                "request": request, 
                "t": translations,
                "lang": current_lang,
                **result
            }
        )
    except Exception as e:
        error_title = translations.get("error_title", "Analysis Error")
        # Sanitize error message to prevent XSS
        error_message = sanitize_for_html(str(e))
        error_html = f'''
        <div class="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
            <div class="flex items-center gap-3">
                <svg class="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <div>
                    <h3 class="text-red-400 font-semibold">{error_title}</h3>
                    <p class="text-red-300/80 text-sm mt-1">{error_message}</p>
                </div>
            </div>
        </div>
        '''
        return HTMLResponse(content=error_html)


# ============== API Routes ==============

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/api/stats")
async def cache_stats():
    """Get cache and performance statistics."""
    return {
        "caches": {
            "analysis": analysis_cache.stats,
            "whois": whois_cache.stats,
            "dns": dns_cache.stats,
        },
        "status": "healthy",
    }


@app.post("/api/analyze/json", response_model=AnalyzeResponse)
async def analyze_url(request: AnalyzeRequest):
    """
    Perform a complete legitimacy analysis on a URL.
    
    This endpoint runs multiple scoring modules:
    - **Domain Age**: Checks WHOIS data for domain registration date
    - **SSL Certificate**: Validates SSL/TLS certificate
    - **URL Pattern**: Analyzes URL for suspicious patterns
    - **Content Analysis**: Examines page content for phishing indicators
    - **DNS Analysis**: Checks DNS configuration
    
    Returns an overall score (0-100) and risk level.
    """
    try:
        # URL is already validated by Pydantic validator
        report = await scorer.analyze(request.url)
        return report.to_dict()
    except Exception as e:
        # Generic error message to avoid leaking internal details
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed. Please verify the URL and try again."
        )


@app.get("/api/quick-check", response_model=QuickCheckResponse)
async def quick_check(
    url: str = Query(..., description="The URL to check", example="https://example.com")
):
    """
    Perform a quick legitimacy check on a URL.
    
    Faster than the full analysis but less comprehensive.
    Only checks URL patterns and SSL certificate.
    """
    # Validate URL
    try:
        validated_url = validate_url(url)
    except URLValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    try:
        result = await scorer.quick_check(validated_url)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Quick check failed. Please verify the URL and try again."
        )


@app.get("/api/analyze/{url:path}", response_model=AnalyzeResponse)
async def analyze_url_get(url: str):
    """
    Perform a complete legitimacy analysis on a URL (GET method).
    
    Alternative endpoint that accepts the URL as a path parameter.
    Note: URL should be properly encoded.
    """
    # Validate URL
    try:
        validated_url = validate_url(url)
    except URLValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    try:
        report = await scorer.analyze(validated_url)
        return report.to_dict()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed. Please verify the URL and try again."
        )
