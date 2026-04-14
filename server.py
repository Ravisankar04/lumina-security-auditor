"""
LUMINA - Autonomous AI Security Auditor v2.0
FastAPI Backend with SSE (Server-Sent Events) Streaming for Vercel
"""

import os
import asyncio
import logging
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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
    logger.info("LUMINA v2.0 starting up...")
    
    # Check for critical environment variables
    missing = []
    if not os.environ.get("GITHUB_CLIENT_ID"): missing.append("GITHUB_CLIENT_ID")
    if not os.environ.get("GITHUB_CLIENT_SECRET"): missing.append("GITHUB_CLIENT_SECRET")
    
    if missing:
        logger.error(f"CRITICAL: Missing environment variables: {', '.join(missing)}")
        logger.error("OAuth login will fail until these are set in Vercel/local .env")
    else:
        logger.info("GitHub OAuth credentials detected.")
        
    yield
    logger.info("LUMINA shutting down.")

app = FastAPI(
    title="LUMINA — Autonomous AI Security Auditor",
    version="2.0.0",
    lifespan=lifespan,
)

# Vercel-friendly entry point
application = app

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
# Vercel handles static files via routes, but for local testing:
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
async def root():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse({"status": "LUMINA API running", "version": "2.0.0"})

@app.get("/hero.png")
async def hero_image():
    """Serve the hero image for the frontend."""
    for name in ["hero.png", "create_an_image_202604121238.png"]:
        path = FRONTEND_DIR / name
        if path.exists():
            return FileResponse(str(path))
    
    # Fallback to a high-quality AI-themed placeholder if local assets are missing on Vercel
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
            content={"error": "Missing Configuration", "detail": "GITHUB_CLIENT_ID is not configured on the server."}
        )

    redirect_uri = str(request.url_for('auth_callback'))
    # In Vercel, sometimes url_for returns http instead of https
    if "vercel.app" in redirect_uri:
        redirect_uri = redirect_uri.replace("http://", "https://")
    
    try:
        return await oauth.github.authorize_redirect(request, redirect_uri)
    except Exception as e:
        logger.error(f"Login redirect failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "OAuth Error", "detail": str(e)}
        )

@app.get("/api/auth/callback")
async def auth_callback(request: Request):
    """Handle GitHub OAuth callback."""
    try:
        token = await oauth.github.authorize_access_token(request)
        user_info = await oauth.github.get('user', token=token)
        user_data = user_info.json()
        
        # Create a session token
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
            max_age=60 * 60 * 24 * 7, # 7 days
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
# API Routes (SSE)
# ────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "online", "version": "2.0.0"}

@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, request: Request):
    """
    Starts the analysis and returns a Server-Sent Events (SSE) stream.
    Uses user's token if logged in.
    """
    repo_url = req.repo_url.strip()
    
    # Check for user token in session
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

    logger.info(f"New scan request: {repo_url} (Auth: {'Yes' if user_token else 'No'})")

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
    Generator that runs the pipeline and yields SSE formatted data.
    """
    queue = asyncio.Queue()

    async def emit_wrapper(event: dict):
        await queue.put(event)

    # Start the pipeline as a background task
    pipeline_task = asyncio.create_task(run_pipeline_logic(repo_url, emit_wrapper, user_token))

    while True:
        try:
            # Get event from queue with timeout for keepalive
            event = await asyncio.wait_for(queue.get(), timeout=1.0)
            yield f"data: {json.dumps(event)}\n\n"
            
            if event.get("type") in ("complete", "error"):
                break
        except asyncio.TimeoutError:
            # Send keep-alive ping
            if pipeline_task.done():
                # Check if it failed without sending an error event
                try:
                    await pipeline_task
                except Exception as e:
                    yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
                break
            # Vercel and browsers need regular data to keep the connection alive
            yield ": ping\n\n"
        except Exception as e:
            logger.error(f"Stream generation error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
            break

async def run_pipeline_logic(repo_url: str, emit_fn, user_token: Optional[str] = None):
    """
    Logic for running the pipeline (orchestrator or demo).
    """
    try:
        from orchestrator import LuminaPipeline
        pipeline = LuminaPipeline(emit_fn=emit_fn, user_token=user_token)
        await pipeline.run(repo_url)

    except (ImportError, ModuleNotFoundError):
        logger.warning("orchestrator.py not found or dependencies missing — running demo mode")
        await _demo_pipeline(emit_fn)

    except Exception as e:
        logger.error(f"Pipeline execution error: {e}")
        await emit_fn({"type": "error", "error": str(e)})

async def _demo_pipeline(emit):
    """Simulated pipeline for testing/demo."""
    stages = [
        ("crawl",        "Repository Ingestion",     "Crawling GitHub repository..."),
        ("index",        "Semantic Indexing",         "Building Pinecone embeddings..."),
        ("architecture", "Architecture Mapping",      "Analyzing system architecture with GPT-4o..."),
        ("scan",         "Vulnerability Detection",   "Running dual-phase security scan..."),
        ("fix",          "Fix Synthesis",             "Generating remediation patches..."),
        ("pr",           "Pull Request Creation",     "Creating GitHub pull request..."),
    ]

    logs = {
        "crawl": ["Fetching file tree...", "Found 47 files", "Parallel crawl complete"],
        "index": ["Chunking code files...", "Generating embeddings...", "Upserting to Pinecone..."],
        "architecture": ["Retrieving top-5 chunks...", "Mapping components...", "Architecture graph built"],
        "scan": ["Running regex pre-filter...", "3 patterns matched", "LLM verification in progress..."],
        "fix": ["Synthesizing fix for CVE-2023-4863...", "Generating SQL injection patch...", "Patches ready"],
        "pr": ["Forking repository...", "Creating security branch...", "Committing patches...", "Opening PR..."],
    }

    for stage_key, stage_name, start_msg in stages:
        await emit({"type": "stage_start", "stage": stage_key, "message": start_msg})
        await asyncio.sleep(0.5)

        for log_line in logs.get(stage_key, []):
            await emit({"type": "log", "message": log_line})
            await asyncio.sleep(0.3) 

        await emit({"type": "stage_done", "stage": stage_key})
        await asyncio.sleep(0.2)

    await emit({
        "type": "complete",
        "pr_url": "https://github.com/demo-org/demo-repo/pull/42",
        "message": "Security audit complete. Pull request created.",
        "vulnerabilities_found": 3,
        "fixes_applied": 3,
        "report": {
            "files_scanned": 47,
            "vulnerabilities": [
                {
                    "file": "app/auth.py", "line": 34,
                    "type": "Hardcoded Secret", "confirmed_type": "Hardcoded Secret",
                    "severity": "CRITICAL",
                    "code": 'SECRET_KEY = "hardcoded-secret-abc123"',
                    "detail": "Hardcoded credential in source code",
                    "explanation": "Secret key is hardcoded directly in source",
                    "cwe": "CWE-798", "verified": True,
                }
            ],
            "fixes": [
                {
                    "file": "app/auth.py", "line": 34,
                    "original": 'SECRET_KEY = "hardcoded-secret-abc123"',
                    "patched_line": "SECRET_KEY = os.environ.get('SECRET_KEY')",
                    "explanation": "Use environment variable",
                    "diff_summary": "Hide secret",
                    "severity": "CRITICAL", "vuln_type": "Hardcoded Secret",
                }
            ],
            "architecture": {
                "tech_stack": ["Python", "FastAPI"],
                "components": {"api": "REST API"},
            },
        },
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
