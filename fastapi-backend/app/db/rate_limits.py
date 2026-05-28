"""
db/rate_limits.py — Persistent sliding-window rate limiter using MongoDB.

FIX: MongoDB does not allow $pull and $push on the same field in one operation.
We split it into two atomic steps:
  1. $pull expired timestamps
  2. $push current timestamp + count remaining
"""

import time
from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.config.settings import SAST_RATE_LIMIT

WINDOW_SECONDS = 60


async def check_rate_limit(
    db: AsyncIOMotorDatabase,
    user_id: str,
    endpoint: str = "analyze",
    limit: int = SAST_RATE_LIMIT,
) -> None:
    now = time.time()
    cutoff = now - WINDOW_SECONDS

    # Step 1: Remove expired timestamps
    await db.rate_limits.update_one(
        {"user_id": user_id, "endpoint": endpoint},
        {
            "$pull": {"timestamps": {"$lt": cutoff}},
            "$setOnInsert": {"user_id": user_id, "endpoint": endpoint},
        },
        upsert=True,
    )

    # Step 2: Read current count after cleanup
    doc = await db.rate_limits.find_one(
        {"user_id": user_id, "endpoint": endpoint}
    )
    current_count = len(doc.get("timestamps", [])) if doc else 0

    if current_count >= limit:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit exceeded: max {limit} requests per minute. "
                "Please wait before analyzing another file."
            )
        )

    # Step 3: Add current timestamp
    await db.rate_limits.update_one(
        {"user_id": user_id, "endpoint": endpoint},
        {"$push": {"timestamps": now}},
    )
