"""
db/dast.py — DAST scan record storage with field-level encryption.

ENCRYPTED FIELDS: target_url, report_path, error
PLAIN FIELDS:     user_id, status, started_at, finished_at
"""

from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db.encryption import (
    encrypt_field,
    decrypt_document,
    DAST_ENCRYPTED_FIELDS,
)


def _decrypt(doc: Optional[dict]) -> Optional[dict]:
    if not doc:
        return doc
    return decrypt_document(doc, DAST_ENCRYPTED_FIELDS)


async def create_scan_record(
    db: AsyncIOMotorDatabase, user_id: str, target_url: str
) -> str:
    """
    Insert a running scan record.
    target_url is encrypted immediately — never stored plain.
    """
    result = await db.dast_scans.insert_one({
        "user_id":     user_id,
        "target_url":  encrypt_field(target_url),   # encrypted
        "report_path": None,
        "status":      "running",                    # plain — not sensitive
        "started_at":  datetime.now(timezone.utc),   # plain — timestamp
        "finished_at": None,
        "error":       None,
    })
    return str(result.inserted_id)


async def complete_scan_record(
    db: AsyncIOMotorDatabase, scan_id: str, report_path: str
) -> None:
    """Mark scan as done. report_path is encrypted before storage."""
    await db.dast_scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {
            "status":      "done",
            "report_path": encrypt_field(report_path),  # encrypted
            "finished_at": datetime.now(timezone.utc),
        }}
    )


async def fail_scan_record(
    db: AsyncIOMotorDatabase, scan_id: str, error: str
) -> None:
    """Mark scan as failed. Error message is encrypted before storage."""
    await db.dast_scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {
            "status":      "failed",
            "error":       encrypt_field(error),        # encrypted
            "finished_at": datetime.now(timezone.utc),
        }}
    )


async def get_recent_scans(
    db: AsyncIOMotorDatabase, user_id: str, limit: int = 5
) -> list:
    """Return recent scans with sensitive fields decrypted."""
    cursor = db.dast_scans.find(
        {"user_id": user_id},
        sort=[("started_at", -1)],
        limit=limit,
        projection={"_id": 0, "user_id": 0},
    )
    docs = await cursor.to_list(length=limit)
    return [_decrypt(d) for d in docs]


async def get_last_completed_scan(
    db: AsyncIOMotorDatabase, user_id: str
) -> Optional[dict]:
    """Return the most recent completed scan, decrypted."""
    doc = await db.dast_scans.find_one(
        {"user_id": user_id, "status": "done"},
        sort=[("finished_at", -1)],
        projection={"_id": 0, "user_id": 0},
    )
    return _decrypt(doc)
