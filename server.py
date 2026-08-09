from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

import subprocess
import os
import uuid
import signal
import urllib.parse
import requests
import time


app = FastAPI(title="Scanova Sandbox")

DISPLAY = ":99"

# Store active browser sessions
sessions = {}


class SandboxRequest(BaseModel):
    url: str


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "scanova-sandbox"
    }


# =========================================================
# URL VALIDATION
# =========================================================

def validate_url(url: str):
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(
            status_code=400,
            detail="Only HTTP and HTTPS URLs are allowed"
        )

    if not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="Invalid URL"
        )


# =========================================================
# FRONTEND
# =========================================================

@app.get("/")
def home():
    return FileResponse("/app/static/index.html")


# =========================================================
# START SANDBOX SESSION
# =========================================================

@app.post("/sandbox/session")
def create_session(request: SandboxRequest):

    validate_url(request.url)

    os.environ["DISPLAY"] = DISPLAY

    # Create unique session ID
    session_id = str(uuid.uuid4())

    # Create unique Chromium profile
    profile_dir = f"/tmp/chromium-{session_id}"

    # Start Chromium
    process = subprocess.Popen([
        "chromium",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--window-size=1280,720",
        "--disable-downloads",
        "--incognito",
        "--no-first-run",
        "--no-default-browser-check",
        f"--user-data-dir={profile_dir}",
        "--new-window",
        request.url
    ])

    # Save session
    sessions[session_id] = {
        "pid": process.pid,
        "url": request.url,
        "profile_dir": profile_dir
    }

    return {
        "status": "started",
        "session_id": session_id,
        "url": request.url,
        "novnc": "http://localhost:3000/vnc.html"
    }


# =========================================================
# URL ANALYSIS + SECURITY ANALYSIS
# =========================================================

@app.post("/sandbox/analyze")
def analyze_url(request: SandboxRequest):

    validate_url(request.url)

    parsed = urllib.parse.urlparse(request.url)

    start_time = time.time()

    try:

        response = requests.get(
            request.url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "SCANOVA-Sandbox/1.0"
            }
        )

        elapsed = round(
            (time.time() - start_time) * 1000,
            2
        )

        headers = response.headers

        # -------------------------------------------------
        # SECURITY HEADERS
        # -------------------------------------------------

        security_headers = {
            "content_security_policy": headers.get(
                "Content-Security-Policy"
            ),
            "strict_transport_security": headers.get(
                "Strict-Transport-Security"
            ),
            "x_frame_options": headers.get(
                "X-Frame-Options"
            ),
            "x_content_type_options": headers.get(
                "X-Content-Type-Options"
            ),
            "referrer_policy": headers.get(
                "Referrer-Policy"
            ),
            "permissions_policy": headers.get(
                "Permissions-Policy"
            )
        }

        # -------------------------------------------------
        # SECURITY FINDINGS
        # -------------------------------------------------

        security_findings = []

        # HTTPS
        if parsed.scheme != "https":
            security_findings.append({
                "type": "HTTPS",
                "severity": "medium",
                "message": "The URL does not use HTTPS."
            })

        # HSTS
        if not security_headers["strict_transport_security"]:
            security_findings.append({
                "type": "HSTS",
                "severity": "low",
                "message": "Strict-Transport-Security header is missing."
            })

        # CSP
        if not security_headers["content_security_policy"]:
            security_findings.append({
                "type": "CSP",
                "severity": "low",
                "message": "Content-Security-Policy header is missing."
            })

        # X-Frame-Options
        if not security_headers["x_frame_options"]:
            security_findings.append({
                "type": "Clickjacking",
                "severity": "low",
                "message": "X-Frame-Options header is missing."
            })

        # X-Content-Type-Options
        if not security_headers["x_content_type_options"]:
            security_findings.append({
                "type": "MIME Sniffing",
                "severity": "low",
                "message": "X-Content-Type-Options header is missing."
            })

        # -------------------------------------------------
        # REDIRECT INFORMATION
        # -------------------------------------------------

        redirect_chain = []

        for history_response in response.history:
            redirect_chain.append({
                "status_code": history_response.status_code,
                "url": history_response.url,
                "location": history_response.headers.get(
                    "Location"
                )
            })

        # -------------------------------------------------
        # FINAL RESPONSE
        # -------------------------------------------------

        return {
            "url": request.url,

            "scheme": parsed.scheme,

            "domain": parsed.netloc,

            "path": parsed.path or "/",

            "status_code": response.status_code,

            "final_url": response.url,

            "content_type": response.headers.get(
                "content-type",
                "unknown"
            ),

            "response_time_ms": elapsed,

            "server": response.headers.get(
                "server",
                "unknown"
            ),

            "redirects": {
                "count": len(response.history),
                "chain": redirect_chain
            },

            "security": {
                "https": parsed.scheme == "https",

                "headers": security_headers,

                "findings": security_findings,

                "risk_indicators": len(security_findings)
            }
        }

    except requests.RequestException as e:

        raise HTTPException(
            status_code=502,
            detail=f"Could not analyze URL: {str(e)}"
        )


# =========================================================
# CLOSE SESSION
# =========================================================

@app.delete("/sandbox/session/{session_id}")
def close_session(session_id: str):

    session = sessions.get(session_id)

    if not session:
        raise HTTPException(
            status_code=404,
            detail="Session not found"
        )

    pid = session["pid"]

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass

    del sessions[session_id]

    return {
        "status": "closed",
        "session_id": session_id
    }


# =========================================================
# LIST SESSIONS
# =========================================================

@app.get("/sandbox/sessions")
def list_sessions():

    return {
        "active_sessions": sessions
    }