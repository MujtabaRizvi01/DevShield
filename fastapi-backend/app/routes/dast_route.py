"""
routes/dast_route.py — DAST scanning with SSRF protection.

FIX FOR: Critical Issue #4 — SSRF vulnerability in DAST endpoint.

WHAT THE VULNERABILITY WAS
────────────────────────────
The /dast endpoint previously accepted any URL without validation.
An attacker could submit:
    { "target_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }

On AWS/GCP/Azure this endpoint returns cloud credentials and IAM role tokens.
The ZAP container would scan it and return the cloud metadata to the attacker.
This is a Server-Side Request Forgery (SSRF) attack.

HOW IT IS FIXED
────────────────
validate_url_for_ssrf() is called before any scan starts.  It:

1. Parses the URL and extracts the hostname.
2. Resolves the hostname to an IP address using socket.getaddrinfo().
3. Checks the resolved IP against a blocklist of private/internal ranges:
   - 127.0.0.0/8      loopback
   - 10.0.0.0/8       private (RFC 1918)
   - 172.16.0.0/12    private (RFC 1918)
   - 192.168.0.0/16   private (RFC 1918)
   - 169.254.0.0/16   link-local / AWS metadata endpoint
   - ::1              IPv6 loopback
   - fc00::/7         IPv6 unique local
4. If the resolved IP is in any blocked range → raise HTTP 422.
5. Only if all checks pass → proceed to scan.

WHY RESOLVE THE HOSTNAME?
──────────────────────────
Checking only the string "localhost" or "127.0.0.1" is not enough.
An attacker could use:
    http://localtest.me/         (resolves to 127.0.0.1)
    http://[::1]/                (IPv6 loopback)
    http://0x7f000001/           (hex-encoded 127.0.0.1)

By resolving the hostname to an IP first and then checking the IP,
we catch all of these variants.

ALLOWED HOSTS
──────────────
localhost and 127.0.0.1 are blocked for production use.
For local development where you run your app on localhost, the extension
rewrites those to host.docker.internal before sending the request —
so the actual URL reaching this endpoint should already use that hostname.
"""

import os
import uuid
import socket
import ipaddress
import subprocess
import asyncio
from functools import partial
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.config.settings import get_user_dast_dir, MAX_CONCURRENT_DAST, IS_PRODUCTION
from datetime import datetime, timezone
from app.db.connection import get_db
from app.db import dast as dast_db
from app.db import users as users_db

router = APIRouter(prefix="/dast", tags=["DAST"])


async def _audit(request: "Request", action: str, detail: dict = {}):
    """Write audit log. Never raises."""
    try:
        db = get_db()
        user_id = getattr(request.state, "user_id", "unknown")
        ip = request.headers.get("X-Forwarded-For",
             request.client.host if request.client else "unknown")
        await db.audit_logs.insert_one({
            "user_id":   user_id,
            "ip":        ip,
            "action":    action,
            "detail":    detail,
            "timestamp": datetime.now(timezone.utc),
        })
    except Exception:
        pass
DAST_NETWORK = "dast_network"

_dast_semaphore = asyncio.Semaphore(MAX_CONCURRENT_DAST)

# ── SSRF blocklist ────────────────────────────────────────────────────────────
# Networks always blocked (cloud metadata ranges)
_BLOCKED_NETWORKS_ALWAYS = [
    ipaddress.ip_network("169.254.0.0/16"),    # link-local / AWS + Azure metadata
    ipaddress.ip_network("100.64.0.0/10"),     # shared address space
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]

# Networks only blocked in production
# In development, localhost (127.x) is needed to scan locally running apps
_BLOCKED_NETWORKS_PRODUCTION = [
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("10.0.0.0/8"),        # private RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),     # private RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),    # private RFC 1918
    ipaddress.ip_network("0.0.0.0/8"),         # invalid
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 unique local
]

# Hosts always blocked regardless of environment
_BLOCKED_HOSTS_ALWAYS = {
    "metadata.google.internal",       # GCP metadata
    "169.254.169.254",                 # AWS/Azure metadata (string form)
}

# Hosts only blocked in production — localhost is allowed in development
_BLOCKED_HOSTS_PRODUCTION = {
    "localhost",
    "127.0.0.1",
}


def validate_url_for_ssrf(url: str) -> None:
    """
    Raise HTTPException(422) if the URL targets a blocked address.

    In DEVELOPMENT (ENV=development):
      - localhost and 127.x are ALLOWED (needed for scanning local test apps)
      - Cloud metadata endpoints (169.254.x) are still blocked

    In PRODUCTION (ENV=production):
      - All private/internal addresses are blocked including localhost
      - This prevents SSRF attacks against internal services and cloud metadata
    """
    try:
        parsed = urlparse(url)
        host   = parsed.hostname
        if not host:
            raise HTTPException(status_code=422, detail="Invalid URL: cannot extract hostname.")

        # Always block known dangerous hostnames
        if host.lower() in _BLOCKED_HOSTS_ALWAYS:
            raise HTTPException(
                status_code=422,
                detail=f"Blocked: '{host}' is a cloud metadata endpoint. "
                       "Scanning metadata services is not permitted."
            )

        # Block localhost-style hosts only in production
        if IS_PRODUCTION and host.lower() in _BLOCKED_HOSTS_PRODUCTION:
            raise HTTPException(
                status_code=422,
                detail=f"Blocked: '{host}' is an internal address. "
                       "In production, only publicly reachable URLs can be scanned."
            )

        # Resolve hostname to IP and check ranges
        try:
            results = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise HTTPException(status_code=422, detail=f"Cannot resolve hostname: {host}")

        # Build the active blocklist based on environment
        active_networks = list(_BLOCKED_NETWORKS_ALWAYS)
        if IS_PRODUCTION:
            active_networks += _BLOCKED_NETWORKS_PRODUCTION

        for _family, _type, _proto, _canonname, sockaddr in results:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            for blocked in active_networks:
                if ip in blocked:
                    raise HTTPException(
                        status_code=422,
                        detail=f"Blocked: '{host}' resolves to {ip_str} "
                               f"({blocked}). This address is not allowed for scanning."
                    )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"URL validation error: {str(e)}")


class DastUrlPayload(BaseModel):
    target_url: str


def _cleanup_old_reports(report_dir: str, keep: int = 5) -> None:
    """
    Keep only the `keep` most recent HTML reports in the user's report folder.
    Deletes the oldest reports (by modification time) when a new scan pushes
    the count over the limit. Also deletes the matching .json report file.
    This runs after every successful scan — no cron job needed.
    """
    try:
        reports = sorted(
            [os.path.join(report_dir, f) for f in os.listdir(report_dir) if f.endswith('.html')],
            key=os.path.getmtime,
        )
        for old_report in reports[:-keep]:
            os.remove(old_report)
            json_version = old_report.replace('.html', '.json')
            if os.path.exists(json_version):
                os.remove(json_version)
            print(f'[DAST] Deleted old report: {old_report}')
    except Exception as e:
        print(f'[DAST] Cleanup warning: {e}')


def _ensure_network() -> None:
    r = subprocess.run(
        f"docker network inspect {DAST_NETWORK}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if r.returncode != 0:
        subprocess.run(
            f"docker network create {DAST_NETWORK}",
            shell=True, check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def _run_blocking(cmd: str, allow_nonzero: tuple = ()) -> int:
    print(f"[DAST] {cmd}")
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    if proc.stdout:
        for line in proc.stdout:
            print(line, end="")
    proc.wait()
    if proc.returncode != 0 and proc.returncode not in allow_nonzero:
        raise RuntimeError(f"Command failed (exit {proc.returncode})")
    return proc.returncode


def _run_dast_scan(target_url: str, report_dir: str, report_base: str) -> str:
    docker_target = (
        target_url.strip().rstrip("/")
        .replace("localhost", "host.docker.internal")
        .replace("127.0.0.1", "host.docker.internal")
    )
    _ensure_network()
    cmd = (
        f"docker run --rm "
        f"--network {DAST_NETWORK} "
        f"--add-host=host.docker.internal:host-gateway "
        f"-v \"{os.path.abspath(report_dir)}:/zap/wrk/:rw\" "
        f"zaproxy/zap-stable zap-baseline.py "
        f"-t {docker_target} "
        f"-r {report_base}.html "
        f"-J {report_base}.json"
    )
    _run_blocking(cmd, allow_nonzero=(1, 2, 3))
    report_html = os.path.join(report_dir, f"{report_base}.html")
    if not os.path.exists(report_html):
        raise RuntimeError("ZAP did not produce an HTML report.")
    return report_html


@router.post("")
async def dast_scan_url(payload: DastUrlPayload, request: Request):
    user_id: str = request.state.user_id
    db = get_db()

    # ── SSRF check — must happen before anything else ─────────────────────────
    validate_url_for_ssrf(payload.target_url)

    # Fix #9 — audit log
    await _audit(request, "dast_start", {"target_url": payload.target_url})

    if _dast_semaphore._value <= 0:
        raise HTTPException(
            status_code=503,
            detail=f"Server busy: {MAX_CONCURRENT_DAST} scans already running. Try again soon."
        )

    report_dir  = get_user_dast_dir(user_id)
    report_base = f"report_{uuid.uuid4().hex}"    # full UUID — not just 12 chars

    scan_id = await dast_db.create_scan_record(db, user_id, payload.target_url)

    async with _dast_semaphore:
        loop = asyncio.get_event_loop()
        try:
            report_html = await loop.run_in_executor(
                None, partial(_run_dast_scan, payload.target_url, report_dir, report_base)
            )
        except Exception as exc:
            await dast_db.fail_scan_record(db, scan_id, str(exc))
            raise HTTPException(status_code=500, detail=str(exc))

    await dast_db.complete_scan_record(db, scan_id, report_html)
    await users_db.increment_dast_count(db, user_id)
    await _audit(request, "dast_complete", {"target_url": payload.target_url})

    # Keep only 5 most recent reports per user — delete oldest automatically
    _cleanup_old_reports(report_dir, keep=5)

    return FileResponse(report_html, media_type="text/html", filename="dast_report.html")


@router.get("/history")
async def scan_history(request: Request):
    user_id: str = request.state.user_id
    db = get_db()
    scans = await dast_db.get_recent_scans(db, user_id)
    return {"scans": scans}


@router.get("/last")
async def last_scan(request: Request):
    user_id: str = request.state.user_id
    db = get_db()
    scan = await dast_db.get_last_completed_scan(db, user_id)
    return scan or {"status": "none"}