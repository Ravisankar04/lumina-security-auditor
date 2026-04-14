# LUMINA® — Autonomous AI Security Auditor v2.0

> Drop a GitHub URL. Get a security PR. In under 90 seconds.

---

## Architecture

```
GitHub URL
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│                  LUMINA Pipeline (LangGraph)             │
│                                                          │
│  Stage 1: Crawl → Stage 2: Index → Stage 3: Arch Map   │
│  Stage 4: Scan  → Stage 5: Fix   → Stage 6: PR         │
└─────────────────────────────────────────────────────────┘
    │
    ▼
GitHub Pull Request (auto-generated)
```

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure environment
Create a `.env` file:
```env
GITHUB_TOKEN=ghp_...
OPENAI_API_KEY=sk-...
PINECONE_API_KEY=pcsk_...
PINECONE_INDEX=lumina-security
```

### 3. Copy your hero image
```bash
cp /path/to/lumina-hero.png hero.png
```

### 4. Launch
```bash
python server.py
```

### 5. Open browser
Navigate to: `http://localhost:8000`

---

## File Structure

| File | Purpose |
|------|---------|
| `index.html` | Ultra-premium frontend with WebSocket support |
| `server.py` | FastAPI backend + WebSocket event streaming |
| `orchestrator.py` | LangGraph 6-stage pipeline orchestration |
| `pr_generator.py` | GitHub fork/commit/PR automation |
| `requirements.txt` | Python dependencies |

---

## Pipeline Stages

### Stage 1 — Repository Ingestion
- Parallel async GitHub REST API with `Semaphore(10)`
- Filters code files by extension
- Skips files > 200KB

### Stage 2 — Semantic Indexing
- Language-aware code chunking
- OpenAI `text-embedding-3-large` (3072-dim vectors)
- Batched Pinecone upsert

### Stage 3 — Architecture Mapping
- RAG retrieval: top-5 semantically relevant chunks
- GPT-4o structured JSON analysis
- Components, data flows, security surface

### Stage 4 — Vulnerability Detection
- **Phase 1:** 16 regex patterns (injection, secrets, deserialization, XSS, SSRF...)
- **Phase 2:** Concurrent LLM verification via `asyncio.gather`

### Stage 5 — Fix Synthesis
- RAG-augmented per-vulnerability fix generation
- `Semaphore(5)` controlled concurrency
- Preserves code style and indentation

### Stage 6 — Pull Request
- Fork if not owner
- Create `lumina-security-audit-{timestamp}` branch
- Concurrent file commits with `Semaphore(3)`
- Comprehensive PR with audit report

---

## WebSocket Event Protocol

Events emitted during pipeline execution:

```json
{"type": "stage_start", "stage": "crawl", "message": "..."}
{"type": "log", "message": "..."}
{"type": "stage_done", "stage": "crawl"}
{"type": "complete", "pr_url": "https://github.com/.../pull/42"}
{"type": "error", "error": "..."}
```

---

## Technology Stack

- **FastAPI** — Async web framework + WebSocket
- **LangGraph** — Pipeline orchestration
- **OpenAI GPT-4o** — Architecture analysis + fix synthesis
- **Pinecone** — Vector database for RAG
- **PyGithub** — GitHub automation
- **aiohttp** — Async HTTP client

---

*BCA Final Year Project — Department of Computer Science*
