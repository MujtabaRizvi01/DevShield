"""
app/db/encryption.py — Field-level encryption for sensitive MongoDB fields.

WHY FIELD-LEVEL ENCRYPTION?
────────────────────────────
MongoDB stores documents in plain text. If the database is breached,
all stored data is immediately readable. Field-level encryption ensures
that even with full database access, sensitive fields are unreadable
without the encryption key, which is never stored in MongoDB.

WHAT IS ENCRYPTED
──────────────────
analyses collection:
  - filename        (reveals codebase structure)
  - vulnerabilities (reveals exact security weaknesses — most sensitive)

dast_scans collection:
  - target_url      (reveals internal infrastructure being scanned)
  - report_path     (reveals server folder structure)
  - error           (may contain internal path or URL details)

NOT ENCRYPTED (safe to store plain)
─────────────────────────────────────
  - user_id         (already a SHA-256 hash, not reversible)
  - api_key_hash    (already a hash)
  - code_hash       (SHA-256 of code, not the code itself)
  - vuln_count      (just a number)
  - status          (running/done/failed — not sensitive)
  - timestamps      (dates — not sensitive)

HOW IT WORKS
─────────────
We use AES-256-GCM (Galois/Counter Mode) — the industry standard for
authenticated encryption. It provides:
  - Confidentiality: encrypted data is unreadable without the key
  - Integrity: tampering with the ciphertext is detected
  - Authentication: ensures the data came from someone with the key

Each field is encrypted with a unique random nonce (12 bytes) so
encrypting the same value twice produces different ciphertext.
The nonce is stored alongside the ciphertext (it is not secret).

STORED FORMAT (base64 string)
───────────────────────────────
  "<base64(nonce)>:<base64(ciphertext+tag)>"

This is stored as a plain string in MongoDB, replacing the original value.
When reading, the string is detected as encrypted and decrypted automatically.

ENCRYPTION KEY
───────────────
Add to .env:
  FIELD_ENCRYPTION_KEY=<32 random bytes as hex>

Generate a key:
  python -c "import secrets; print(secrets.token_hex(32))"

The key is NEVER stored in MongoDB. If lost, all encrypted data
becomes permanently unreadable — back it up securely.

KEY ROTATION
─────────────
To rotate the key:
1. Add NEW_FIELD_ENCRYPTION_KEY=<new key> to .env
2. Run the rotation script (provided below)
3. Rename NEW_FIELD_ENCRYPTION_KEY → FIELD_ENCRYPTION_KEY
4. Remove old key from .env
"""

import os
import json
import base64
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

# ── Load encryption key ───────────────────────────────────────────────────────
_RAW_KEY = os.getenv("FIELD_ENCRYPTION_KEY", "")

if not _RAW_KEY:
    raise RuntimeError(
        "FIELD_ENCRYPTION_KEY is not set in .env\n"
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "Then add to .env: FIELD_ENCRYPTION_KEY=<generated_value>"
    )

try:
    _KEY_BYTES = bytes.fromhex(_RAW_KEY)
    if len(_KEY_BYTES) != 32:
        raise ValueError("Key must be exactly 32 bytes (64 hex characters)")
except ValueError as e:
    raise RuntimeError(f"Invalid FIELD_ENCRYPTION_KEY: {e}")

_AESGCM = AESGCM(_KEY_BYTES)

# Prefix marker so we can detect already-encrypted values
_ENCRYPTED_PREFIX = "enc:"


def encrypt_field(value: Any) -> str:
    """
    Encrypt any JSON-serialisable value.
    Returns a string in the format: enc:<base64(nonce)>:<base64(ciphertext)>

    Always produces different output for the same input (random nonce).
    """
    if value is None:
        return None

    # Serialise to JSON bytes so we can encrypt any type (str, list, dict)
    plaintext = json.dumps(value, ensure_ascii=False).encode("utf-8")

    # 12-byte random nonce — unique per encryption operation
    nonce = secrets.token_bytes(12)

    # Encrypt with AES-256-GCM (includes authentication tag)
    ciphertext = _AESGCM.encrypt(nonce, plaintext, None)

    # Encode to base64 for safe storage in MongoDB string fields
    nonce_b64      = base64.b64encode(nonce).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()

    return f"{_ENCRYPTED_PREFIX}{nonce_b64}:{ciphertext_b64}"


def decrypt_field(value: Any) -> Any:
    """
    Decrypt a value previously encrypted by encrypt_field().
    Returns the original value in its original type.
    Returns the value unchanged if it is not encrypted
    (handles legacy plain-text documents gracefully).
    """
    if value is None:
        return None

    # If not a string or not encrypted, return as-is (backward compatibility)
    if not isinstance(value, str) or not value.startswith(_ENCRYPTED_PREFIX):
        return value

    try:
        # Strip prefix and split nonce from ciphertext
        _, rest = value.split(":", 1)
        nonce_b64, ciphertext_b64 = rest.split(":", 1)

        nonce      = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # Decrypt — raises InvalidTag if tampered
        plaintext = _AESGCM.decrypt(nonce, ciphertext, None)

        # Deserialise from JSON back to original type
        return json.loads(plaintext.decode("utf-8"))

    except Exception as e:
        raise ValueError(f"Decryption failed — data may be corrupted or key is wrong: {e}")


def encrypt_document(doc: dict, fields: list[str]) -> dict:
    """
    Encrypt specific fields in a document dict.
    Returns a new dict with the specified fields encrypted.
    Other fields are left unchanged.
    """
    result = dict(doc)
    for field in fields:
        if field in result:
            result[field] = encrypt_field(result[field])
    return result


def decrypt_document(doc: dict, fields: list[str]) -> dict:
    """
    Decrypt specific fields in a document dict.
    Returns a new dict with the specified fields decrypted.
    Safe to call on plain-text documents (no-op for unencrypted fields).
    """
    if not doc:
        return doc
    result = dict(doc)
    for field in fields:
        if field in result:
            result[field] = decrypt_field(result[field])
    return result


# ── Field lists — what gets encrypted in each collection ─────────────────────
ANALYSES_ENCRYPTED_FIELDS = ["filename", "vulnerabilities"]
DAST_ENCRYPTED_FIELDS     = ["target_url", "report_path", "error"]


# ─────────────────────────────────────────────────────────────────────────────
# KEY ROTATION HELPER
# Run this once when rotating to a new encryption key.
# ─────────────────────────────────────────────────────────────────────────────
async def rotate_encryption_key(
    db,
    new_key_hex: str,
    collections_fields: dict[str, list[str]],
) -> dict[str, int]:
    """
    Re-encrypt all sensitive fields with a new key.

    Usage:
        import asyncio
        from app.db.connection import connect_db, get_db
        from app.db.encryption import rotate_encryption_key, ANALYSES_ENCRYPTED_FIELDS, DAST_ENCRYPTED_FIELDS

        async def run():
            await connect_db()
            db = get_db()
            counts = await rotate_encryption_key(
                db,
                new_key_hex="<your new 64-char hex key>",
                collections_fields={
                    "analyses":   ANALYSES_ENCRYPTED_FIELDS,
                    "dast_scans": DAST_ENCRYPTED_FIELDS,
                }
            )
            print(counts)

        asyncio.run(run())
    """
    new_key   = bytes.fromhex(new_key_hex)
    new_aesgcm = AESGCM(new_key)
    counts = {}

    for collection_name, fields in collections_fields.items():
        collection = db[collection_name]
        migrated = 0
        async for doc in collection.find({}):
            updates = {}
            for field in fields:
                old_val = doc.get(field)
                if old_val is None:
                    continue
                # Decrypt with current key
                decrypted = decrypt_field(old_val)
                # Re-encrypt with new key
                plaintext  = json.dumps(decrypted, ensure_ascii=False).encode()
                nonce      = secrets.token_bytes(12)
                ciphertext = new_aesgcm.encrypt(nonce, plaintext, None)
                updates[field] = (
                    f"{_ENCRYPTED_PREFIX}"
                    f"{base64.b64encode(nonce).decode()}:"
                    f"{base64.b64encode(ciphertext).decode()}"
                )
            if updates:
                await collection.update_one({"_id": doc["_id"]}, {"$set": updates})
                migrated += 1
        counts[collection_name] = migrated
        print(f"[Rotation] {collection_name}: {migrated} documents re-encrypted")

    return counts
