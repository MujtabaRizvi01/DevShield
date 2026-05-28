"""
fix_atlas_index.py
==================
ONE-TIME script — run this ONCE from your fastapi-backend folder.
It connects directly to your MongoDB Atlas cluster and drops the
stale "api_key_1" index that is causing every new user to crash.

HOW TO RUN (from your fastapi-backend directory):
    python fix_atlas_index.py

That's it. Once it prints "SUCCESS", restart your FastAPI server normally.
You never need to run this again.
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

# ── Your Atlas credentials (taken from .env) ──────────────────────────────────
MONGODB_URI = "mongodb+srv://Mujtaba01:Kashif1234%40@loginsignup.f4w2k.mongodb.net/?appName=LoginSignup"
DB_NAME     = "Devshield01"

async def fix():
    print("[fix] Connecting to MongoDB Atlas...")
    client = AsyncIOMotorClient(MONGODB_URI)
    db     = client[DB_NAME]

    # ── Step 1: Show all current indexes on users collection ──────────────────
    print("\n[fix] Current indexes on 'users' collection:")
    indexes = await db.users.index_information()
    for name, info in indexes.items():
        print(f"   • {name}  →  key: {info.get('key')}")

    # ── Step 2: Drop the bad old index ────────────────────────────────────────
    if "api_key_1" in indexes:
        print("\n[fix] Found 'api_key_1' — dropping it now...")
        await db.users.drop_index("api_key_1")
        print("[fix] ✓ Dropped 'api_key_1'")
    else:
        print("\n[fix] 'api_key_1' not found — already dropped or never existed.")

    # ── Step 3: Drop any other legacy plain-key indexes that may exist ────────
    legacy_indexes = ["api_key_hash_1_api_key_1", "api_key_hash_1"]
    for idx_name in legacy_indexes:
        if idx_name in indexes:
            print(f"[fix] Found legacy index '{idx_name}' — dropping...")
            await db.users.drop_index(idx_name)
            print(f"[fix] ✓ Dropped '{idx_name}'")

    # ── Step 4: Ensure the correct index exists ───────────────────────────────
    print("\n[fix] Creating correct 'api_key_hash' unique index...")
    await db.users.create_index("api_key_hash", unique=True)
    print("[fix] ✓ 'api_key_hash' unique index is in place")

    # ── Step 5: Clean up any corrupt user docs with null api_key_hash ─────────
    print("\n[fix] Removing any corrupted user documents (api_key_hash: null)...")
    result = await db.users.delete_many({"api_key_hash": None})
    if result.deleted_count > 0:
        print(f"[fix] ✓ Removed {result.deleted_count} corrupted document(s)")
    else:
        print("[fix] ✓ No corrupted documents found")

    # ── Step 6: Show final index state ────────────────────────────────────────
    print("\n[fix] Final indexes on 'users' collection:")
    indexes = await db.users.index_information()
    for name, info in indexes.items():
        print(f"   • {name}  →  key: {info.get('key')}")

    client.close()
    print("\n" + "="*60)
    print("  SUCCESS — Atlas index fixed.")
    print("  Now restart your FastAPI server normally:")
    print("  uvicorn main:app --reload --port 8000")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(fix())
