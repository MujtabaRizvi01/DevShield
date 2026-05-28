"""
routes/analysis_route.py — SAST analysis with MongoDB storage.

NEW FEATURES vs file-based version
------------------------------------
1. CODE HASH CACHE: If the file content hasn't changed since the last
   analysis, we return the cached result instantly without calling Groq.
   Saves API quota when user presses Ctrl+S multiple times.

2. FULL HISTORY: Every analysis is stored as a new document.  The extension
   gets the latest result; a future dashboard can show trends over time.

3. STARTUP RESTORE: GET /analyze/all returns the latest result for every
   file the user has scanned — the extension calls this on activation to
   restore highlights without the user needing to re-save every file.

4. PERSISTENT RATE LIMITS: Rate limit counters survive server restarts
   and work correctly across multiple uvicorn workers.
"""

from fastapi import APIRouter, Request
import os
import json
import asyncio
from functools import partial

from app.models.code_payload import CodePayload
from app.services.analyzer_service import analyze_with_groq
from app.db.connection import get_db
from app.db import analyses as analyses_db
from app.db import users as users_db
from app.db.rate_limits import check_rate_limit

router = APIRouter()


@router.post("/")
@router.post("")
async def analyze_code(payload: CodePayload, request: Request):
    user_id: str = request.state.user_id
    db = get_db()

    filename = os.path.basename(payload.filename)

    # ── Rate limit check (MongoDB-backed, survives restarts) ──────────────────
    await check_rate_limit(db, user_id, endpoint="analyze")

    # ── Code hash cache — skip Groq if file hasn't changed ───────────────────
    cached = await analyses_db.get_cached(db, user_id, filename, payload.code)
    if cached is not None:
        return {
            "message": "Cached result",
            "filename": filename,
            "cached": True,
            "vulnerabilities": cached,
        }

    # ── Call Groq in thread pool (synchronous SDK, can take several seconds) ──
    loop = asyncio.get_event_loop()
    raw_result = await loop.run_in_executor(
        None, partial(analyze_with_groq, payload.code)
    )

    # ── Parse result ──────────────────────────────────────────────────────────
    try:
        data = json.loads(raw_result)
    except json.JSONDecodeError:
        data = {"vulnerabilities": []}

    if "error" in data:
        return {"vulnerabilities": [], "warning": data["error"]}

    vulns = data.get("vulnerabilities", [])

    # ── Persist to MongoDB (async, non-blocking) ──────────────────────────────
    await analyses_db.save_analysis(db, user_id, filename, payload.code, vulns)
    await users_db.increment_analysis_count(db, user_id)

    return {
        "message": "Analysis complete",
        "filename": filename,
        "cached": False,
        "vulnerabilities": vulns,
    }


@router.get("/results/{filename:path}")
async def get_result(filename: str, request: Request):
    """Return the most recent analysis result for a specific file."""
    user_id: str = request.state.user_id
    db = get_db()
    safe_name = os.path.basename(filename)
    result = await analyses_db.get_latest(db, user_id, safe_name)
    if not result:
        return {"vulnerabilities": []}
    return result


@router.get("/all")
async def get_all_results(request: Request):
    """
    Return the latest analysis for every file the user has scanned.
    The extension calls this on startup to restore all highlights
    without the user needing to re-save every file.
    """
    user_id: str = request.state.user_id
    db = get_db()
    results = await analyses_db.get_all_latest(db, user_id)
    return {"files": results}


@router.get("/history/{filename:path}")
async def get_history(filename: str, request: Request):
    """Return the last 10 analysis results for a file (for trend tracking)."""
    user_id: str = request.state.user_id
    db = get_db()
    safe_name = os.path.basename(filename)
    history = await analyses_db.get_history(db, user_id, safe_name)
    return {"filename": safe_name, "history": history}
