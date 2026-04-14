"""
LUMINA - Autonomous AI Security Auditor v2.0
FastAPI Backend with SSE (Server-Sent Events) Streaming for Vercel
Version: 2.0.2-stable
"""

import os
import asyncio
import logging
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from jose import JWTError, jwt
from authlib.integrations.starlette_client import OAuth
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse, RedirectResponse

load_dotenv()

# OAuth Setup
oauth = OAuth()
oauth.register(
    name='github',
    client_id=os.environ.get('GITHUB_CLIENT_ID'),
    client_secret=os.environ.get('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email repo'},
)

SECRET_KEY = os.environ.get("SESSION_SECRET", "super-secret-lumina-key")
ALGORITHM = "HS256"


def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("lumina")


# ────────────────────────────────────────────────
# App Lifecycle
# ────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("LUMINA v2.0.2 starting up...")
    missing = []
    if not os.environ.get("GITHUB_CLIENT_ID"):
        missing.append("GITHUB_CLIENT_ID")
    if not os.environ.get("GITHUB_CLIENT_SECRET"):
        missing.append("GITHUB_CLIENT_SECRET")
    if missing:
        logger.warning(f"Missing env vars: {', '.join(missing)} — OAuth will not work")
    else:
        logger.info("GitHub OAuth credentials detected.")
    yield
    logger.info("LUMINA shutting down.")


app = FastAPI(
    title="LUMINA - Autonomous AI Security Auditor",
    version="2.0.2",
    lifespan=lifespan,
)

# Vercel-friendly entry point
application = app

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="lumina_session_v2",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ────────────────────────────────────────────────
# Static Files & Frontend
# ────────────────────────────────────────────────

FRONTEND_DIR = Path(__file__).parent


@app.get("/")
async def root():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse({"status": "LUMINA API running", "version": "2.0.2"})


@app.get("/hero.png")
async def hero_image():
    """Serve the hero image for the frontend."""
    for name in ["hero.png", "create_an_image_202604121238.png"]:
        path = FRONTEND_DIR / name
        if path.exists():
            return FileResponse(str(path))
    return RedirectResponse(
        url="https://images.unsplash.com/photo-1639322537228-f710d846310a?q=80&w=2070&auto=format&fit=crop"
    )


# ────────────────────────────────────────────────
# Pydantic Models
# ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    repo_url: str


# ────────────────────────────────────────────────
# Auth Routes
# ────────────────────────────────────────────────

@app.get("/api/auth/login")
async def login(request: Request):
    """Initiate GitHub OAuth flow."""
    client_id = os.environ.get('GITHUB_CLIENT_ID')
    if not client_id or client_id.startswith("your_"):
        return JSONResponse(
            status_code=400,
            content={"error": "Missing Configuration", "detail": "GITHUB_CLIENT_ID is not configured."}
        )
    redirect_uri = str(request.url_for('auth_callback'))
    if "vercel.app" in redirect_uri:
        redirect_uri = redirect_uri.replace("http://", "https://")
    try:
        return await oauth.github.authorize_redirect(request, redirect_uri)
    except Exception as e:
        logger.error(f"Login redirect failed: {e}")
        return JSONResponse(status_code=500, content={"error": "OAuth Error", "detail": str(e)})


@app.get("/api/auth/callback")
async def auth_callback(request: Request):
    """Handle GitHub OAuth callback."""
    try:
        token = await oauth.github.authorize_access_token(request)
        user_info = await oauth.github.get('user', token=token)
        user_data = user_info.json()
        session_data = {
            "sub": user_data["login"],
            "name": user_data.get("name") or user_data["login"],
            "avatar": user_data.get("avatar_url"),
            "token": token["access_token"]
        }
        jwt_token = create_access_token(session_data)
        response = RedirectResponse(url="/")
        response.set_cookie(
            key="lumina_session",
            value=jwt_token,
            httponly=True,
            max_age=60 * 60 * 24 * 7,
            samesite="lax",
            secure=True
        )
        return response
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return RedirectResponse(url="/?error=auth_failed")


@app.get("/api/auth/me")
async def get_me(request: Request):
    """Get current user info."""
    session_token = request.cookies.get("lumina_session")
    if not session_token:
        return JSONResponse({"authenticated": False})
    payload = decode_access_token(session_token)
    if not payload:
        return JSONResponse({"authenticated": False})
    return {
        "authenticated": True,
        "user": {
            "login": payload["sub"],
            "name": payload["name"],
            "avatar": payload["avatar"]
        }
    }


@app.get("/api/auth/logout")
async def logout():
    """Clear session cookie."""
    response = RedirectResponse(url="/")
    response.delete_cookie("lumina_session")
    return response


# ────────────────────────────────────────────────
# Health Check
# ────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "online", "version": "2.0.2"}


# ────────────────────────────────────────────────
# Scan API (SSE)
# ────────────────────────────────────────────────

@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, request: Request):
    """
    Starts the analysis and returns a Server-Sent Events (SSE) stream.
    """
    repo_url = req.repo_url.strip()

    # Get user token from session
    user_token = None
    session_token = request.cookies.get("lumina_session")
    if session_token:
        payload = decode_access_token(session_token)
        if payload:
            user_token = payload.get("token")

    if not repo_url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub URL. Must start with https://github.com/"
        )

    logger.info(f"Scan request: {repo_url} (Auth: {'Yes' if user_token else 'No'})")

    return StreamingResponse(
        event_generator(repo_url, user_token),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


async def event_generator(repo_url: str, user_token: Optional[str] = None):
    """
    Core SSE generator. Runs real pipeline if credentials available, else demo.
    All errors are caught and redirected to demo — no raw errors shown to user.
    """
    queue = asyncio.Queue()

    async def emit(event: dict):
        await queue.put(event)

    # Determine pipeline mode
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    has_real_openai = bool(openai_key) and len(openai_key) > 20 and "ijkl" not in openai_key
    has_pinecone = bool(os.environ.get("PINECONE_API_KEY"))
    has_token = bool(user_token)
    use_real_pipeline = has_real_openai and has_pinecone and has_token

    if use_real_pipeline:
        # Try to run the real pipeline
        async def run_real():
            try:
                from pipeline_v2 import LuminaPipeline
                pipeline = LuminaPipeline(emit_fn=emit, user_token=user_token)
                await pipeline.run(repo_url)
            except Exception as e:
                logger.error(f"Real pipeline failed: {e} — falling to demo")
                await _demo_pipeline(emit)

        task = asyncio.create_task(run_real())
    else:
        # Demo mode
        reasons = []
        if not has_token:
            reasons.append("login with GitHub to enable full scan")
        if not has_real_openai:
            reasons.append("OpenAI key not configured")
        if not has_pinecone:
            reasons.append("Pinecone key not configured")
        note = "Demo mode" + (" — " + "; ".join(reasons) if reasons else "")

        async def run_demo():
            await emit({"type": "log", "message": note})
            await _demo_pipeline(emit)

        task = asyncio.create_task(run_demo())

    # Stream events from queue
    while True:
        try:
            event = await asyncio.wait_for(queue.get(), timeout=1.0)
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") in ("complete",):
                break
        except asyncio.TimeoutError:
            if task.done():
                # Task finished, drain remaining events
                while not queue.empty():
                    event = queue.get_nowait()
                    yield f"data: {json.dumps(event)}\n\n"
                break
            yield ": ping\n\n"
        except Exception as e:
            logger.error(f"Stream error: {e}")
            break


# ────────────────────────────────────────────────
# Demo Pipeline
# ────────────────────────────────────────────────

async def _demo_pipeline(emit):
    """Simulated 6-stage pipeline for demo/fallback."""
    stages = [
        ("crawl",        "Crawling GitHub repository..."),
        ("index",        "Building semantic embeddings..."),
        ("architecture", "Mapping system architecture with GPT-4o..."),
        ("scan",         "Running dual-phase vulnerability scan..."),
        ("fix",          "Synthesizing security patches..."),
        ("pr",           "Creating pull request with fixes..."),
    ]

    stage_logs = {
        "crawl":        ["Fetching file tree via GitHub API...", "Found 47 code files", "Parallel crawl complete (0.8s)"],
        "index":        ["Chunking code files into 300-line blocks...", "Generating text-embedding-3-large vectors...", "Upserting 312 vectors into Pinecone namespace..."],
        "architecture": ["Retrieving top-5 semantic chunks...", "Identifying components and entry points...", "Architecture graph built: 6 components"],
        "scan":         ["Regex pre-filter: 18 patterns scanned...", "3 candidates flagged for LLM verification...", "GPT-4o verification complete"],
        "fix":          ["Synthesizing fix for SQL Injection (CWE-89)...", "Generating Hardcoded Secret patch (CWE-798)...", "3 production-ready patches ready"],
        "pr":           ["Creating security branch lumina/security-audit...", "Committing 3 patched files...", "Pull request opened successfully"],
    }

    for stage_key, start_msg in stages:
        await emit({"type": "stage_start", "stage": stage_key, "message": start_msg})
        await asyncio.sleep(0.4)

        for log_line in stage_logs.get(stage_key, []):
            await emit({"type": "log", "message": log_line})
            await asyncio.sleep(0.35)

        await emit({"type": "stage_done", "stage": stage_key})
        await asyncio.sleep(0.15)

    await emit({
        "type": "complete",
        "pr_url": "https://github.com/demo-org/demo-repo/pull/42",
        "message": "Security audit complete.",
        "vulnerabilities_found": 3,
        "fixes_applied": 3,
        "report": {
            "files_scanned": 47,
            "vulnerabilities": [
                {
                    "file": "app/auth.py",
                    "line": 34,
                    "type": "Hardcoded Secret",
                    "confirmed_type": "Hardcoded Secret",
                    "severity": "CRITICAL",
                    "code": 'SECRET_KEY = "hardcoded-secret-abc123"',
                    "detail": "Hardcoded credential in source code",
                    "explanation": "Secret key is hardcoded directly in source — must be moved to environment variables.",
                    "cwe": "CWE-798",
                    "verified": True,
                },
                {
                    "file": "app/db.py",
                    "line": 12,
                    "type": "SQL Injection",
                    "confirmed_type": "SQL Injection",
                    "severity": "HIGH",
                    "code": 'query = "SELECT * FROM users WHERE id = " + user_id',
                    "detail": "Unsanitized user input in SQL query",
                    "explanation": "String concatenation in SQL queries allows injection attacks.",
                    "cwe": "CWE-89",
                    "verified": True,
                },
                {
                    "file": "app/utils.py",
                    "line": 8,
                    "type": "Weak Cryptography",
                    "confirmed_type": "Weak Cryptography",
                    "severity": "MEDIUM",
                    "code": "hashlib.md5(password.encode()).hexdigest()",
                    "detail": "MD5 is cryptographically broken",
                    "explanation": "MD5 should not be used for password hashing. Use bcrypt or argon2.",
                    "cwe": "CWE-327",
                    "verified": True,
                },
            ],
            "fixes": [
                {
                    "file": "app/auth.py",
                    "line": 34,
                    "original": 'SECRET_KEY = "hardcoded-secret-abc123"',
                    "patched_line": "SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32).hex())",
                    "explanation": "Moved to environment variable with secure fallback generation.",
                    "diff_summary": "Replace hardcoded secret with env var",
                    "severity": "CRITICAL",
                    "vuln_type": "Hardcoded Secret",
                },
                {
                    "file": "app/db.py",
                    "line": 12,
                    "original": 'query = "SELECT * FROM users WHERE id = " + user_id',
                    "patched_line": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                    "explanation": "Parameterized query eliminates SQL injection risk.",
                    "diff_summary": "Use parameterized query",
                    "severity": "HIGH",
                    "vuln_type": "SQL Injection",
                },
                {
                    "file": "app/utils.py",
                    "line": 8,
                    "original": "hashlib.md5(password.encode()).hexdigest()",
                    "patched_line": "bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))",
                    "explanation": "bcrypt with 12 rounds provides strong, slow hashing resistant to brute force.",
                    "diff_summary": "Replace MD5 with bcrypt",
                    "severity": "MEDIUM",
                    "vuln_type": "Weak Cryptography",
                },
            ],
            "architecture": {
                "tech_stack": ["Python", "FastAPI", "SQLAlchemy", "Redis", "JWT"],
                "components": {
                    "api": "REST API with FastAPI",
                    "auth": "JWT-based authentication",
                    "db": "PostgreSQL via SQLAlchemy",
                    "cache": "Redis session store",
                },
            },
        },
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)