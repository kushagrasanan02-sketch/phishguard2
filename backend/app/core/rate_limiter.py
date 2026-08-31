import time
from typing import Dict, List, Tuple
from fastapi import Request, HTTPException, status

# Simple in-memory sliding window rate limiter
# IP -> List of timestamps
_request_history: Dict[str, List[float]] = {}

DEFAULT_MAX_REQUESTS = 30 # max 30 requests
DEFAULT_WINDOW_SECONDS = 60 # per 60 seconds

def check_rate_limit(request: Request, max_requests: int = DEFAULT_MAX_REQUESTS, window_seconds: int = DEFAULT_WINDOW_SECONDS):
    """
    Validates client IP request rate within a sliding time window.
    Raises HTTP 429 Too Many Requests if threshold is exceeded.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()

    if client_ip not in _request_history:
        _request_history[client_ip] = []

    # Filter out timestamps outside the current window
    history = [t for t in _request_history[client_ip] if now - t < window_seconds]
    _request_history[client_ip] = history

    if len(history) >= max_requests:
        retry_after = int(window_seconds - (now - history[0]))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {max_requests} requests per {window_seconds}s.",
            headers={"Retry-After": str(max(1, retry_after))}
        )

    _request_history[client_ip].append(now)
