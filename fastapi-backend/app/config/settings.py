"""
app/config/settings.py

FIX FOR: Critical Issue #5 — Database credentials in plain text .env file.

WHAT THIS FILE NOW DOES
────────────────────────
1. Reads .env as before.
2. validate_secrets() is called on startup — it checks that all required
   secrets are present and non-empty.  If any are missing the server
   refuses to start with a clear error message, preventing silent failures
   in misconfigured deployments.
3. For production (ENV=production), it additionally verifies that the
   MONGODB_URI uses TLS (mongodb+srv:// or ?tls=true) — plain mongodb://
   connections are rejected in production.

HOW TO HANDLE SECRETS IN PRODUCTION (instead of .env)
───────────────────────────────────────────────────────
Never put real credentials in a .env file on a production server.
Instead inject them as environment variables from your hosting platform:

  Railway:     Settings → Variables → add MONGODB_URI, GROQ_API_KEY
  Render:      Environment → add key/value pairs
  AWS ECS:     Task definition → environment variables (from Secrets Manager)
  Docker:      docker run -e MONGODB_URI=... -e GROQ_API_KEY=...
  Kubernetes:  kind: Secret + envFrom

The .env file is ONLY for local development.  It is in .gitignore and
should never be committed.
"""

import os
import sys
from dotenv import load_dotenv

load_dotenv()

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# ── MongoDB ───────────────────────────────────────────────────────────────────
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME     = os.getenv("DB_NAME", "devshield")

# ── Groq ──────────────────────────────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# ── Environment ───────────────────────────────────────────────────────────────
# Set ENV=production in your hosting platform to enable production checks.
ENV = os.getenv("ENV", "development").lower()
IS_PRODUCTION = ENV == "production"

# ── DAST ──────────────────────────────────────────────────────────────────────
DAST_REPORTS_DIR = os.path.join(PROJECT_ROOT, "storage", "dast_reports")
os.makedirs(DAST_REPORTS_DIR, exist_ok=True)

MAX_CONCURRENT_DAST = int(os.getenv("MAX_CONCURRENT_DAST", "3"))

# ── Field-level encryption ───────────────────────────────────────────────────
# 32-byte key as hex (64 chars). Generate with:
#   python -c "import secrets; print(secrets.token_hex(32))"
FIELD_ENCRYPTION_KEY = os.getenv("FIELD_ENCRYPTION_KEY", "")

# ── Rate limiting ─────────────────────────────────────────────────────────────
SAST_RATE_LIMIT = int(os.getenv("SAST_RATE_LIMIT", "20"))

# ── Input limits ─────────────────────────────────────────────────────────────
MAX_CODE_BYTES = int(os.getenv("MAX_CODE_BYTES", str(50 * 1024)))   # 50 KB default


def get_user_dast_dir(user_id: str) -> str:
    d = os.path.join(DAST_REPORTS_DIR, user_id)
    os.makedirs(d, exist_ok=True)
    return d


def validate_secrets() -> None:
    """
    Called once at startup.  Refuses to start if required secrets are missing
    or if production is misconfigured.

    This prevents silent failures like:
      - GROQ_API_KEY missing → every analysis returns an error
      - MONGODB_URI missing → server starts but crashes on first DB call
      - Plain mongodb:// in production → credentials in transit unencrypted
    """
    errors = []

    # Required in all environments
    if not GROQ_API_KEY:
        errors.append(
            "GROQ_API_KEY is not set. "
            "Get a key from https://console.groq.com and add it to .env"
        )

    if not MONGODB_URI or MONGODB_URI == "mongodb://localhost:27017" and IS_PRODUCTION:
        if IS_PRODUCTION:
            errors.append(
                "MONGODB_URI is still the default localhost value in production. "
                "Set MONGODB_URI to your Atlas connection string."
            )

    # Production-only checks
    if IS_PRODUCTION:
        # Enforce TLS on MongoDB connection in production
        uses_tls = (
            MONGODB_URI.startswith("mongodb+srv://") or
            "tls=true" in MONGODB_URI.lower() or
            "ssl=true" in MONGODB_URI.lower()
        )
        if not uses_tls:
            errors.append(
                "Production requires a TLS MongoDB connection. "
                "Use mongodb+srv:// (Atlas) or add ?tls=true to your URI. "
                "Plain mongodb:// is not allowed in production."
            )

    if not os.getenv("FIELD_ENCRYPTION_KEY"):
        errors.append(
            "FIELD_ENCRYPTION_KEY is not set. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "then add to .env: FIELD_ENCRYPTION_KEY=<value>"
        )

    if errors:
        print("\n" + "="*60)
        print("DevShield startup failed — missing or invalid secrets:")
        for e in errors:
            print(f"  ✗  {e}")
        print("="*60 + "\n")
        sys.exit(1)

    print(f"[DevShield] Secrets validated. Environment: {ENV}")
