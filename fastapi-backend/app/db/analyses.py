"""
db/analyses.py — Vulnerability analysis storage with field-level encryption.

ENCRYPTED FIELDS: filename, vulnerabilities
PLAIN FIELDS:     user_id, filename_hash, code_hash, vuln_count, analyzed_at

All encrypt/decrypt is transparent — routes see plain data, never ciphertext.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db.encryption import (
    encrypt_field,
    decrypt_document,
    ANALYSES_ENCRYPTED_FIELDS,
)


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _filename_hash(filename: str) -> str:
    """
    Deterministic hash of filename used for MongoDB queries.
    Because encryption uses a random nonce, the same filename encrypts
    differently each time — we cannot query by encrypted value.
    We store this plain hash alongside the encrypted filename for indexing.
    """
    return hashlib.sha256(filename.encode()).hexdigest()


def _decrypt(doc: Optional[dict]) -> Optional[dict]:
    if not doc:
        return doc
    return decrypt_document(doc, ANALYSES_ENCRYPTED_FIELDS)


async def get_latest(
    db: AsyncIOMotorDatabase, user_id: str, filename: str
) -> Optional[dict]:
    doc = await db.analyses.find_one(
        {"user_id": user_id, "filename_hash": _filename_hash(filename)},
        sort=[("analyzed_at", -1)],
        projection={"_id": 0, "user_id": 0},
    )
    return _decrypt(doc)


async def get_cached(
    db: AsyncIOMotorDatabase, user_id: str, filename: str, code: str
) -> Optional[list]:
    doc = await db.analyses.find_one(
        {
            "user_id":       user_id,
            "filename_hash": _filename_hash(filename),
            "code_hash":     _hash_code(code),
        },
        sort=[("analyzed_at", -1)],
    )
    if not doc:
        return None
    decrypted = _decrypt(doc)
    return decrypted.get("vulnerabilities", []) if decrypted else None


async def save_analysis(
    db: AsyncIOMotorDatabase,
    user_id: str,
    filename: str,
    code: str,
    vulnerabilities: list,
) -> None:
    """
    Insert analysis with sensitive fields encrypted.
    filename_hash stored plain for querying.
    filename and vulnerabilities stored encrypted.
    """
    await db.analyses.insert_one({
        "user_id":         user_id,
        "filename_hash":   _filename_hash(filename),       # plain — for queries
        "filename":        encrypt_field(filename),         # encrypted
        "vulnerabilities": encrypt_field(vulnerabilities),  # encrypted
        "vuln_count":      len(vulnerabilities),            # plain — just a number
        "code_hash":       _hash_code(code),                # plain — hash of code
        "analyzed_at":     datetime.now(timezone.utc),      # plain — timestamp
    })


async def get_history(
    db: AsyncIOMotorDatabase, user_id: str, filename: str, limit: int = 10
) -> list:
    cursor = db.analyses.find(
        {"user_id": user_id, "filename_hash": _filename_hash(filename)},
        sort=[("analyzed_at", -1)],
        limit=limit,
        projection={"_id": 0, "user_id": 0},
    )
    docs = await cursor.to_list(length=limit)
    return [_decrypt(d) for d in docs]


async def get_all_latest(db: AsyncIOMotorDatabase, user_id: str) -> list:
    pipeline = [
        {"$match": {"user_id": user_id}},
        {"$sort": {"analyzed_at": -1}},
        {"$group": {
            "_id":             "$filename_hash",
            "filename":        {"$first": "$filename"},
            "vulnerabilities": {"$first": "$vulnerabilities"},
            "vuln_count":      {"$first": "$vuln_count"},
            "analyzed_at":     {"$first": "$analyzed_at"},
        }},
        {"$project": {"_id": 0}},
    ]
    cursor = db.analyses.aggregate(pipeline)
    docs   = await cursor.to_list(length=100)
    return [_decrypt(d) for d in docs]
