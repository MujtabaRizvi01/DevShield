"""
middleware/auth.py — API key authentication backed by MongoDB.

CHANGES FROM JSON-FILE VERSION
--------------------------------
- resolve_user() is now async and queries MongoDB via Motor.
- No file locking, no race conditions on concurrent registrations.
- The upsert in db/users.py handles simultaneous registrations atomically.
- A small in-process LRU cache (128 keys) avoids hitting MongoDB on every
  single request for already-seen keys.  Cache entries expire after 5 minutes
  so revoked keys stop working quickly.
"""

import re
import time
from functools import lru_cache
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.db.connection import get_db
from app.db import users as users_db

KEY_PATTERN = re.compile(r"^ds_[0-9a-f]{40}$")

# Simple time-based cache: {api_key: (user_id, cached_at)}
_cache: dict[str, tuple[str, float]] = {}
CACHE_TTL = 300  # 5 minutes


def _get_cached_user_id(api_key: str) -> Optional[str]:
    entry = _cache.get(api_key)
    if entry and (time.time() - entry[1]) < CACHE_TTL:
        return entry[0]
    return None


def _set_cache(api_key: str, user_id: str) -> None:
    _cache[api_key] = (user_id, time.time())
    # Evict oldest entries if cache grows too large
    if len(_cache) > 500:
        oldest = sorted(_cache.items(), key=lambda x: x[1][1])[:100]
        for k, _ in oldest:
            del _cache[k]


def invalidate_cache(api_key: str) -> None:
    """
    Immediately remove a key from the in-process cache.
    Call this on revocation and rotation so the old key stops
    working instantly — before the 5-minute TTL expires.
    """
    _cache.pop(api_key, None)


class AuthMiddleware(BaseHTTPMiddleware):
    SKIP_PATHS = {"/", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        api_key = request.headers.get("X-API-Key", "").strip()

        if not api_key or not KEY_PATTERN.match(api_key):
            return JSONResponse(
                status_code=401,
                content={"error": "Missing or invalid API key. "
                         "Make sure your DevShield extension is active."}
            )

        # Check in-process cache first (avoids DB round-trip for every request)
        user_id = _get_cached_user_id(api_key)

        if user_id:
            # Cache hit — but still verify revocation status in MongoDB
            # This ensures rotated/revoked keys are rejected immediately
            # instead of waiting for the 5-min cache TTL to expire.
            db = get_db()
            revoked = await users_db.is_revoked(db, api_key)
            if revoked:
                invalidate_cache(api_key)
                return JSONResponse(status_code=401, content={"error": "Invalid or revoked API key"})
        else:
            # Cache miss — resolve from MongoDB (auto-registers if new)
            db = get_db()
            user_id = await users_db.resolve_user(db, api_key)
            if user_id:
                _set_cache(api_key, user_id)

        if not user_id:
            return JSONResponse(status_code=401, content={"error": "Invalid API key"})

        request.state.user_id = user_id
        return await call_next(request)