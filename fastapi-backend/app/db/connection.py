"""
db/connection.py — MongoDB connection using Motor (async driver).
"""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config.settings import MONGODB_URI, DB_NAME

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None

TTL_SECONDS = 172800  # 2 days


async def _drop_index_if_exists(collection, index_name: str) -> None:
    """
    Drop an index by name if it exists.
    Used to replace old non-TTL indexes with TTL versions.
    Safe to call even if the index does not exist.
    """
    try:
        existing = await collection.index_information()
        if index_name in existing:
            await collection.drop_index(index_name)
            print(f"[DevShield] Dropped old index '{index_name}' for TTL migration")
    except Exception as e:
        print(f"[DevShield] Could not drop index '{index_name}': {e}")


async def connect_db() -> None:
    global _client, _db
    _client = AsyncIOMotorClient(MONGODB_URI)
    _db = _client[DB_NAME]

    # ── users ─────────────────────────────────────────────────────────────────
    # MIGRATION: Drop ALL legacy indexes from V4 that used the plain "api_key"
    # field. V5 stores only SHA-256 hashes under "api_key_hash". The old index
    # causes DuplicateKeyError (api_key: null) for every new user registration.
    # _drop_index_if_exists is safe to call even if the index does not exist.
    await _drop_index_if_exists(_db.users, "api_key_1")
    await _drop_index_if_exists(_db.users, "api_key_hash_1_api_key_1")
    # Also remove any existing null/corrupt documents before indexing
    try:
        await _db.users.delete_many({"api_key_hash": None})
    except Exception:
        pass
    await _db.users.create_index("api_key_hash", unique=True)

    # ── analyses ──────────────────────────────────────────────────────────────
    await _db.analyses.create_index([("user_id", 1), ("filename_hash", 1)])

    # Drop old non-TTL analyzed_at index if it exists, then recreate with TTL.
    # This handles the case where the index was created by an older version
    # without expireAfterSeconds — MongoDB rejects adding TTL to an existing
    # non-TTL index with the same name (IndexOptionsConflict error).
    await _drop_index_if_exists(_db.analyses, "analyzed_at_1")
    await _db.analyses.create_index(
        "analyzed_at",
        expireAfterSeconds=TTL_SECONDS   # auto-delete docs older than 2 days
    )



    # ── dast_scans ────────────────────────────────────────────────────────────
    await _db.dast_scans.create_index([("user_id", 1), ("started_at", -1)])

    # Same TTL migration pattern for dast_scans
    await _drop_index_if_exists(_db.dast_scans, "started_at_1")
    await _db.dast_scans.create_index(
        "started_at",
        expireAfterSeconds=TTL_SECONDS   # auto-delete scan records older than 2 days
    )

    # ── rate_limits ───────────────────────────────────────────────────────────
    await _db.rate_limits.create_index(
        [("user_id", 1), ("endpoint", 1)], unique=True
    )

    print(f"[DevShield] Connected to MongoDB: {DB_NAME}")
    print(f"[DevShield] TTL set: analyses + dast_scans auto-delete after 2 days")


async def close_db() -> None:
    global _client
    if _client:
        _client.close()
        print("[DevShield] MongoDB connection closed")


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("Database not initialised. Call connect_db() first.")
    return _db