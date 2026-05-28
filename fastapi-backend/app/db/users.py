"""
db/users.py — User registration and API key resolution.

FIX FOR: Critical Issue #2 — API keys stored in plain text in MongoDB.

WHAT CHANGED
────────────
Previously the raw api_key string (e.g. "ds_a3f8...") was stored directly
in the MongoDB document under the "api_key" field.  If the database was ever
breached, every user's key was immediately usable by the attacker.

Now we store ONLY the SHA-256 hash of the key under "api_key_hash".
The raw key is NEVER written to MongoDB.

HOW AUTHENTICATION STILL WORKS
────────────────────────────────
1. Extension sends X-API-Key: ds_a3f8...  (raw key in request header)
2. auth.py passes raw key to resolve_user()
3. resolve_user() computes SHA-256(raw_key) → api_key_hash
4. Queries MongoDB: find { api_key_hash: <hash> }
5. If found → return user_id.  If not → create new user document.

The raw key is never stored anywhere on the server — only the hash.
Even if an attacker reads the entire MongoDB users collection they get
only hashes, which cannot be reversed to the original keys.

MIGRATION NOTE
──────────────
If you have existing users stored with plain "api_key" fields you need
to migrate them.  Run this once against your database:

    from app.db.users import migrate_plain_keys_to_hashed
    await migrate_plain_keys_to_hashed(db)

This is included at the bottom of this file.

DOCUMENT SHAPE (new)
────────────────────
{
    "_id":            ObjectId (auto),
    "api_key_hash":   "sha256hex...",   # SHA-256 of the raw key — indexed unique
    "user_id":        "abc123def456",   # SHA-256[:16] of api_key — safe to expose
    "registered_at":  ISODate,
    "last_seen_at":   ISODate,
    "total_analyses": 0,
    "total_dast":     0
}
"""
"""
db/users.py

Fixes applied:
  #2  — API keys stored as SHA-256 hash only (never plain text)
  #7  — Key rotation: revoke_key() and rotate_key() added
"""

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase


def _hash_key(api_key: str) -> str:
    """SHA-256 of raw key. This is what gets stored — raw key never touches MongoDB."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def _user_id_from_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]


async def is_revoked(db: AsyncIOMotorDatabase, api_key: str) -> bool:
    """
    Returns True if the key exists in MongoDB and is marked revoked=True.
    Used by AuthMiddleware to check revocation even on cache hits,
    so rotated keys are rejected immediately without waiting for cache TTL.
    Returns False if the key is active or not found (new key → not revoked).
    """
    doc = await db.users.find_one(
        {"api_key_hash": _hash_key(api_key)},
        {"revoked": 1}
    )
    if doc is None:
        return False  # key not in DB yet — new key, not revoked
    return bool(doc.get("revoked", False))


async def resolve_user(db: AsyncIOMotorDatabase, api_key: str) -> Optional[str]:
    """
    Return user_id for the given api_key. Auto-registers if new.
    Returns None if the key has been revoked.

    FIX: Splits find + upsert into two operations to avoid DuplicateKeyError
    caused by the old "api_key_1" unique index (which indexed api_key: null
    on new documents that don't have the legacy api_key field).
    The old index is dropped in connect_db() on startup, but this two-step
    approach also protects against any timing window on first boot.
    """
    now          = datetime.now(timezone.utc)
    api_key_hash = _hash_key(api_key)
    user_id      = _user_id_from_key(api_key)

    # Step 1: Check if document already exists (active OR revoked)
    existing = await db.users.find_one({"api_key_hash": api_key_hash})

    if existing:
        # Key was revoked — permanently reject, never re-register
        if existing.get("revoked"):
            return None
        # Key exists and is active — just update last_seen_at
        await db.users.update_one(
            {"api_key_hash": api_key_hash},
            {"$set": {"last_seen_at": now}}
        )
        return existing.get("user_id", user_id)

    # Key not found at all — check if it was previously revoked and deleted
    # (edge case: doc was TTL-expired but key is still in circulation)
    # We don't allow registration of keys that look like rotated-away keys.
    # Since we never delete revoked docs (only mark revoked=True), if a key
    # is not found it is genuinely new — safe to register below.

    # Step 2: New key — insert fresh document (no upsert to avoid null-key collision)
    try:
        await db.users.insert_one({
            "api_key_hash":   api_key_hash,
            "user_id":        user_id,
            "registered_at":  now,
            "last_seen_at":   now,
            "total_analyses": 0,
            "total_dast":     0,
            "revoked":        False,
        })
    except Exception as e:
        # Race condition: another request inserted the doc between our find and insert.
        # Re-fetch and return the existing user_id safely.
        err_str = str(e)
        if "duplicate" in err_str.lower() or "E11000" in err_str:
            doc = await db.users.find_one({"api_key_hash": api_key_hash})
            if doc:
                if doc.get("revoked"):
                    return None
                await db.users.update_one(
                    {"api_key_hash": api_key_hash},
                    {"$set": {"last_seen_at": now}}
                )
                return doc.get("user_id", user_id)
        # Any other error — re-raise
        raise

    return user_id


async def revoke_key(db: AsyncIOMotorDatabase, api_key: str) -> bool:
    """
    Fix #7 — Revoke an API key so it can no longer authenticate.
    The key hash is kept in the database (marked revoked=True) so we know
    it was revoked. The raw key is never stored.
    Returns True if a key was found and revoked, False if not found.
    """
    result = await db.users.update_one(
        {"api_key_hash": _hash_key(api_key), "revoked": False},
        {"$set": {"revoked": True, "revoked_at": datetime.now(timezone.utc)}}
    )
    if result.modified_count > 0:
        # Immediately evict from in-process cache so key dies instantly
        try:
            from app.middleware.auth import invalidate_cache
            invalidate_cache(api_key)
        except Exception:
            pass
    return result.modified_count > 0


async def rotate_key(db: AsyncIOMotorDatabase, old_api_key: str) -> Optional[str]:
    """
    Fix #7 — Generate a new API key for the user and revoke the old one.
    Returns the new raw API key (shown to user once — never stored plain).
    Returns None if old key not found or already revoked.
    """
    api_key_hash = _hash_key(old_api_key)
    user_doc = await db.users.find_one({"api_key_hash": api_key_hash})

    if not user_doc or user_doc.get("revoked"):
        return None

    user_id = user_doc["user_id"]

    # Generate new key
    new_key      = "ds_" + secrets.token_hex(20)
    new_key_hash = _hash_key(new_key)
    now          = datetime.now(timezone.utc)

    # Revoke old key
    await db.users.update_one(
        {"api_key_hash": api_key_hash},
        {"$set": {"revoked": True, "revoked_at": now}}
    )

    # Insert new key document for same user_id
    await db.users.insert_one({
        "api_key_hash":  new_key_hash,
        "user_id":       user_id,       # same user_id — history preserved
        "registered_at": now,
        "total_analyses": user_doc.get("total_analyses", 0),
        "total_dast":     user_doc.get("total_dast", 0),
        "revoked":        False,
    })

    # Immediately invalidate the old key from the in-process auth cache
    # so it stops working right away — not after the 5-min TTL expires.
    try:
        from app.middleware.auth import invalidate_cache
        invalidate_cache(old_api_key)
    except Exception:
        pass  # middleware import may not be available in all contexts

    return new_key  # returned to user ONCE — never stored plain


async def increment_analysis_count(db: AsyncIOMotorDatabase, user_id: str) -> None:
    await db.users.update_one({"user_id": user_id, "revoked": False}, {"$inc": {"total_analyses": 1}})


async def increment_dast_count(db: AsyncIOMotorDatabase, user_id: str) -> None:
    await db.users.update_one({"user_id": user_id, "revoked": False}, {"$inc": {"total_dast": 1}})


async def get_user_stats(db: AsyncIOMotorDatabase, user_id: str) -> dict:
    doc = await db.users.find_one(
        {"user_id": user_id, "revoked": False},
        {"_id": 0, "api_key_hash": 0}
    )
    return doc or {}


async def migrate_plain_keys_to_hashed(db: AsyncIOMotorDatabase) -> int:
    migrated = 0
    async for doc in db.users.find({"api_key": {"$exists": True}}):
        raw_key  = doc["api_key"]
        key_hash = _hash_key(raw_key)
        await db.users.update_one(
            {"_id": doc["_id"]},
            {"$set": {"api_key_hash": key_hash, "revoked": False}, "$unset": {"api_key": ""}}
        )
        migrated += 1
    print(f"[Migration] Migrated {migrated} user documents to hashed keys.")
    return migrated


async def rotate_api_key(db: AsyncIOMotorDatabase, user_id: str, new_api_key: str) -> bool:
    """
    Replace the current API key hash with a new one for the given user_id.
    The old key immediately becomes invalid.
    Returns True if the user was found and updated, False otherwise.
    """
    new_hash = _hash_key(new_api_key)
    result = await db.users.update_one(
        {"user_id": user_id},
        {"$set": {
            "api_key_hash": new_hash,
            "key_rotated_at": __import__('datetime').datetime.now(
                __import__('datetime').timezone.utc
            ),
        }}
    )
    return result.modified_count > 0