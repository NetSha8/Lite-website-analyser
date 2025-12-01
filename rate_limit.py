"""Rate limiting middleware for Heimdall."""

import time
from collections import defaultdict
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple IP-based rate limiting."""
    
    def __init__(self, app, max_requests: int = 10, window: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            app: FastAPI app
            max_requests: Maximum requests per window
            window: Time window in seconds
        """
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window
        self.requests = defaultdict(list)
    
    async def dispatch(self, request: Request, call_next):
        """Check rate limit before processing request."""
        # Skip rate limiting for static files
        if request.url.path.startswith("/static"):
            return await call_next(request)
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Only rate limit /api/ endpoints
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        
        now = time.time()
        
        # Clean old requests
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip]
            if now - req_time < self.window
        ]
        
        # Check if rate limit exceeded
        if len(self.requests[client_ip]) >= self.max_requests:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Maximum {self.max_requests} requests per {self.window} seconds."
            )
        
        # Add current request
        self.requests[client_ip].append(now)
        
        response = await call_next(request)
        return response
