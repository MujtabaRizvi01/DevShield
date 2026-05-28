"""
DevShield FastAPI backend — Security hardened version.

Fixes applied in this file:
  - validate_secrets() called before server starts (Fix #5)
  - TrustedHostMiddleware added to reject requests with unexpected Host headers
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.config.settings import validate_secrets, IS_PRODUCTION
from app.db.connection import connect_db, close_db
from app.middleware.auth import AuthMiddleware
from app.routes.analysis_route import router as analysis_router
from app.routes.dast_route import router as dast_router

# ── Validate secrets before anything else ─────────────────────────────────────
# If required env vars are missing or misconfigured the server exits here
# with a clear error message instead of starting and failing silently.
validate_secrets()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title="DevShield Backend",
    description="Multi-user security analysis API",
    version="3.1.0",
    lifespan=lifespan,
    # Disable automatic /docs and /redoc in production
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
)

# ── Middleware (order matters — first added = outermost) ──────────────────────

# Reject requests with unexpected Host headers (host header injection)
if IS_PRODUCTION:
    import os
    allowed_hosts = os.getenv("ALLOWED_HOSTS", "yourdomain.com").split(",")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

app.add_middleware(AuthMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    # tighten to your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(analysis_router, prefix="/analyze", tags=["Analysis"])
app.include_router(dast_router)


@app.get("/")
def root():
    return {"message": "DevShield API running", "version": "3.1.0"}


@app.get("/me")
async def me(request: Request):
    from app.db.connection import get_db
    from app.db.users import get_user_stats
    db = get_db()
    stats = await get_user_stats(db, request.state.user_id)
    return stats


@app.post("/rotate-key")
async def rotate_api_key(request: Request):
    """
    Fix #7 — API key rotation.

    The extension calls this when the user chooses 'Rotate API Key' from
    the command palette. The current key is revoked and a new one is returned.
    The user must update their stored key (the extension does this automatically).

    The new key is returned ONCE in the response and never stored plain.
    """
    from app.db.connection import get_db
    from app.db.users import rotate_key
    from fastapi import HTTPException

    # We need the raw key to rotate — read from header
    raw_key = request.headers.get("X-API-Key", "").strip()
    db = get_db()
    new_key = await rotate_key(db, raw_key)

    if not new_key:
        raise HTTPException(status_code=400, detail="Key not found or already revoked.")

    return {
        "message": "Key rotated successfully. Update your stored key immediately.",
        "new_api_key": new_key,  # shown ONCE — save it now
    }


@app.get("/audit-logs")
async def get_audit_logs(request: Request, limit: int = 50):
    """Fix #9 — Return recent audit logs for the current user."""
    from app.db.connection import get_db
    db = get_db()
    cursor = db.audit_logs.find(
        {"user_id": request.state.user_id},
        sort=[("timestamp", -1)],
        limit=min(limit, 200),
        projection={"_id": 0}
    )
    logs = await cursor.to_list(length=200)
    return {"logs": logs}


@app.post("/rotate-key")
async def rotate_key(request: Request):
    """
    Generate a new API key for the current user.
    The old key is immediately invalidated.
    The new key is returned once — store it securely.
    """
    import secrets, re
    from app.db.connection import get_db
    from app.db.users import rotate_api_key

    user_id = request.state.user_id
    new_key = "ds_" + secrets.token_hex(20)

    db = get_db()
    success = await rotate_api_key(db, user_id, new_key)
    if not success:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "message": "API key rotated successfully. Update your extension with the new key.",
        "new_api_key": new_key,
        "warning": "This key will not be shown again. Store it immediately."
    }