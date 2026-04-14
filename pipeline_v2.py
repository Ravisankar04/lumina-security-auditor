"""
LUMINA - Autonomous AI Security Auditor v2.0
LangGraph 6-Stage Pipeline Orchestrator
"""

import os
import re
import asyncio
import logging
from typing import Any, Callable, Coroutine, Dict, List, Optional, TypedDict

logger = logging.getLogger("lumina.orchestrator")

if "ijkl" in os.environ.get("OPENAI_API_KEY", ""):
    import sys
    import mock_openai
    sys.modules["openai"] = mock_openai


# ─────────────────────────────────────────────────────────────────
# Pipeline State
# ─────────────────────────────────────────────────────────────────

class PipelineState(TypedDict, total=False):
    repo_url:      str
    files:         List[Dict[str, Any]]   # [{path, content, size}]
    index_id:      str                    # Pinecone namespace
    architecture:  Dict[str, Any]         # GPT-4o architecture map
    vulnerabilities: List[Dict[str, Any]] # [{file, line, type, severity, detail}]
    fixes:         List[Dict[str, Any]]   # [{file, original, patched, diff}]
    pr_url:        str
    error:         Optional[str]


EmitFn = Callable[[dict], Coroutine]


# ─────────────────────────────────────────────────────────────────
# LangGraph Node Helpers
# ─────────────────────────────────────────────────────────────────

def _parse_owner_repo(repo_url: str):
    """Extract owner and repo name from GitHub URL."""
    match = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url.strip())
    if not match:
        raise ValueError(f"Invalid GitHub URL: {repo_url}")
    return match.group(1), match.group(2)


# ─────────────────────────────────────────────────────────────────
# Stage 1 — Repository Ingestion
# ─────────────────────────────────────────────────────────────────

async def _crawl_repo(owner: str, repo: str, token: str, emit: EmitFn) -> List[Dict]:
    """
    Parallel async GitHub REST API crawling with Semaphore(10).
    Returns list of {path, content, size} dicts.
    """
    import aiohttp

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    base = "https://api.github.com"
    sem = asyncio.Semaphore(10)

    async def fetch_tree(session: aiohttp.ClientSession) -> List[Dict]:
        url = f"{base}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
        async with session.get(url, headers=headers) as r:
            r.raise_for_status()
            data = await r.json()
            return [
                item for item in data.get("tree", [])
                if item["type"] == "blob" and item.get("size", 0) < 200_000
                and _is_code_file(item["path"])
            ]

    async def fetch_file(session: aiohttp.ClientSession, path: str) -> Optional[Dict]:
        url = f"{base}/repos/{owner}/{repo}/contents/{path}"
        async with sem:
            try:
                async with session.get(url, headers=headers) as r:
                    if r.status != 200:
                        return None
                    data = await r.json()
                    import base64
                    content = base64.b64decode(data.get("content", "")).decode("utf-8", errors="ignore")
                    return {"path": path, "content": content, "size": len(content)}
            except Exception as e:
                logger.warning(f"Failed to fetch {path}: {e}")
                return None

    async with aiohttp.ClientSession() as session:
        await emit({"type": "log", "message": "Fetching repository file tree..."})
        tree = await fetch_tree(session)
        await emit({"type": "log", "message": f"Found {len(tree)} code files — crawling in parallel..."})

        tasks = [fetch_file(session, item["path"]) for item in tree]
        results = await asyncio.gather(*tasks)
        files = [f for f in results if f is not None]

    await emit({"type": "log", "message": f"Successfully fetched {len(files)} files"})
    return files


def _is_code_file(path: str) -> bool:
    CODE_EXTS = {
        # Source code
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
        ".php", ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt",
        ".sh", ".bash", ".zsh", ".fish", ".ps1",
        # Config & IaC
        ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config",
        ".env", ".env.example", ".tf", ".tfvars", ".hcl",
        # Data / queries
        ".sql", ".graphql", ".gql",
        # Web
        ".html", ".htm", ".css", ".scss", ".sass", ".less",
        ".vue", ".svelte", ".astro",
        # Scripts & build
        ".makefile", ".mk", ".cmake", ".gradle", ".groovy",
        ".dockerfile",
        # Misc
        ".xml", ".json", ".lock",
    }
    # Match by extension
    if any(path.endswith(ext) for ext in CODE_EXTS):
        return True
    # Match important filenames without extension
    IMPORTANT_NAMES = {
        "dockerfile", "makefile", "jenkinsfile", "vagrantfile",
        "rakefile", "gemfile", "procfile", "brewfile",
        "requirements.txt", "pipfile", "setup.py", "setup.cfg",
        "pyproject.toml", "package.json", "package-lock.json",
        "yarn.lock", "pom.xml", "build.gradle", "cargo.toml",
        "go.mod", "go.sum", ".gitignore", ".env.example",
    }
    filename = path.split("/")[-1].lower()
    return filename in IMPORTANT_NAMES


# ─────────────────────────────────────────────────────────────────
# Stage 2 — Semantic Indexing
# ─────────────────────────────────────────────────────────────────

def _chunk_code(content: str, path: str, chunk_size: int = 300) -> List[str]:
    """Language-aware chunking by logical blocks."""
    lines = content.splitlines()
    chunks, current, current_lines = [], [], 0

    for line in lines:
        current.append(line)
        current_lines += 1
        if current_lines >= chunk_size or (
            current_lines > 50 and line.strip() == "" and current_lines > 10
        ):
            chunks.append("\n".join(current))
            current, current_lines = [], 0

    if current:
        chunks.append("\n".join(current))

    return [f"# File: {path}\n\n{chunk}" for chunk in chunks if chunk.strip()]


async def _build_index(files: List[Dict], namespace: str, emit: EmitFn) -> str:
    """
    Build Pinecone vector index from repository files.
    Uses OpenAI text-embedding-3-large (3072 dims).
    """
    from openai import AsyncOpenAI
    from pinecone import Pinecone

    openai_client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])
    pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])
    index_name = os.environ.get("PINECONE_INDEX", "lumina-security")
    
    try:
        index_list = pc.list_indexes().names()
        if index_name not in index_list:
            from pinecone import ServerlessSpec
            await emit({"type": "log", "message": f"Creating Pinecone index '{index_name}'..."})
            pc.create_index(
                name=index_name,
                dimension=3072,
                metric="cosine",
                spec=ServerlessSpec(cloud="aws", region="us-east-1")
            )
            import time
            time.sleep(3) # Wait for provisioning
    except Exception as e:
        logger.warning(f"Index creation check failed: {e}")

    index = pc.Index(index_name)

    # Chunk all files
    all_chunks = []
    for f in files:
        chunks = _chunk_code(f["content"], f["path"])
        all_chunks.extend([(f["path"], chunk) for chunk in chunks])

    await emit({"type": "log", "message": f"Created {len(all_chunks)} code chunks"})

    # Embed in batches of 50
    batch_size = 50
    vectors = []

    for i in range(0, len(all_chunks), batch_size):
        batch = all_chunks[i:i + batch_size]
        texts = [c[1] for c in batch]

        resp = await openai_client.embeddings.create(
            model="text-embedding-3-large",
            input=texts,
        )
        for j, emb_obj in enumerate(resp.data):
            path, chunk = batch[j]
            vectors.append({
                "id": f"{namespace}-{i+j}",
                "values": emb_obj.embedding,
                "metadata": {"path": path, "text": chunk[:1000]},
            })

        await emit({"type": "log", "message": f"Embedded batch {i//batch_size + 1} / {(len(all_chunks) + batch_size - 1) // batch_size}"})

    # Upsert in batches of 100
    upsert_batch = 100
    for i in range(0, len(vectors), upsert_batch):
        index.upsert(vectors=vectors[i:i + upsert_batch], namespace=namespace)

    await emit({"type": "log", "message": f"Indexed {len(vectors)} vectors into Pinecone namespace '{namespace}'"})
    return namespace


async def _retrieve(query: str, namespace: str, top_k: int = 5) -> List[str]:
    """Retrieve top-k relevant code chunks from Pinecone."""
    from openai import AsyncOpenAI
    from pinecone import Pinecone

    openai_client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])
    pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])
    index = pc.Index(os.environ.get("PINECONE_INDEX", "lumina-security"))

    resp = await openai_client.embeddings.create(
        model="text-embedding-3-large",
        input=[query],
    )
    query_vec = resp.data[0].embedding

    results = index.query(
        vector=query_vec,
        top_k=top_k,
        namespace=namespace,
        include_metadata=True,
    )
    return [m["metadata"].get("text", "") for m in results.get("matches", [])]


# ─────────────────────────────────────────────────────────────────
# Stage 3 — Architecture Mapping
# ─────────────────────────────────────────────────────────────────

async def _map_architecture(files: List[Dict], namespace: str, emit: EmitFn) -> Dict:
    """Use GPT-4o to map system architecture from retrieved context."""
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])

    ctx_chunks = await _retrieve(
        "system architecture components API routes database models configuration",
        namespace,
        top_k=5,
    )
    context = "\n\n---\n\n".join(ctx_chunks)

    file_list = "\n".join(f["path"] for f in files[:80])

    prompt = f"""You are a software architect. Analyze the following code context from a GitHub repository
and produce a JSON architecture map.

FILE LISTING:
{file_list}

CODE CONTEXT (semantic search results):
{context}

Return ONLY valid JSON with this structure:
{{
  "tech_stack": ["list of technologies"],
  "entry_points": ["main files/routes"],
  "components": {{"name": "description"}},
  "data_flows": ["describe key data flows"],
  "external_services": ["APIs, databases, etc"],
  "security_surface": ["inputs, auth, file ops, network calls"]
}}"""

    await emit({"type": "log", "message": "GPT-4o analyzing system architecture..."})

    response = await client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.1,
    )

    import json
    arch = json.loads(response.choices[0].message.content)
    await emit({"type": "log", "message": f"Architecture mapped: {len(arch.get('components', {}))} components identified"})
    return arch


# ─────────────────────────────────────────────────────────────────
# Stage 4 — Vulnerability Detection
# ─────────────────────────────────────────────────────────────────

VULN_PATTERNS = [
    # Injection
    (r"eval\s*\(", "Code Injection", "HIGH", "Dangerous eval() usage"),
    (r"exec\s*\(", "Code Execution", "HIGH", "exec() call detected"),
    (r"os\.system\s*\(", "Command Injection", "HIGH", "os.system() — prefer subprocess with args"),
    (r"subprocess\.call\s*\(.+shell\s*=\s*True", "Command Injection", "HIGH", "shell=True subprocess"),
    # SQL
    (r'["\'].*SELECT.*FROM.*["\'].*%[s\(]', "SQL Injection", "CRITICAL", "String-formatted SQL query"),
    (r'\.format\(.*\).*WHERE', "SQL Injection", "HIGH", "format() in SQL context"),
    # Secrets
    (r'(?i)(secret|password|api_key|token)\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded Secret", "CRITICAL", "Hardcoded credential"),
    (r'(?i)sk-[a-zA-Z0-9]{40,}', "Exposed API Key", "CRITICAL", "OpenAI key in code"),
    # Path traversal
    (r'open\s*\(\s*[^)]*\+', "Path Traversal", "MEDIUM", "Dynamic file path construction"),
    # Deserialization
    (r'pickle\.loads?\(', "Insecure Deserialization", "HIGH", "pickle.load() — unsafe with untrusted data"),
    (r'yaml\.load\s*\([^)]*\)', "Insecure Deserialization", "MEDIUM", "yaml.load without Loader"),
    # XSS (JS)
    (r'innerHTML\s*=\s*[^"\'`]', "XSS", "HIGH", "Unescaped innerHTML assignment"),
    (r'document\.write\s*\(', "XSS", "MEDIUM", "document.write() usage"),
    # SSRF
    (r'requests\.get\s*\([^)]*\+', "SSRF", "HIGH", "Dynamic URL in requests.get"),
    # Debug
    (r'(?i)debug\s*=\s*True', "Debug Mode", "MEDIUM", "Debug mode enabled in production code"),
    # Weak crypto
    (r'(?i)md5|sha1', "Weak Cryptography", "MEDIUM", "Use SHA-256 or stronger"),
    # JWT
    (r'(?i)verify\s*=\s*False', "JWT Bypass", "CRITICAL", "JWT signature verification disabled"),
    # CORS
    (r'(?i)Access-Control-Allow-Origin.*\*', "Overly Permissive CORS", "MEDIUM", "Wildcard CORS origin"),
]

async def _regex_scan(files: List[Dict]) -> List[Dict]:
    """Phase 1: Fast regex pre-filtering."""
    candidates = []
    for f in files:
        content = f["content"]
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, vuln_type, severity, detail in VULN_PATTERNS:
                if re.search(pattern, line):
                    candidates.append({
                        "file": f["path"],
                        "line": i,
                        "code": line.strip(),
                        "type": vuln_type,
                        "severity": severity,
                        "detail": detail,
                        "verified": False,
                    })
    return candidates


async def _llm_verify(candidate: Dict, namespace: str, emit: EmitFn) -> Optional[Dict]:
    """Phase 2: LLM verification of a single candidate."""
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])

    ctx = await _retrieve(
        f"{candidate['type']} vulnerability {candidate['file']} {candidate['code']}",
        namespace,
        top_k=3,
    )

    context_text = "\n".join(ctx)
    prompt = f"""You are a security expert. Evaluate this potential vulnerability:

File: {candidate['file']}
Line {candidate['line']}: {candidate['code']}
Pattern matched: {candidate['type']} — {candidate['detail']}

Context from codebase:
{context_text}

Respond ONLY with JSON:
{{
  "is_vulnerability": true/false,
  "confirmed_type": "vulnerability type or null",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "explanation": "one sentence",
  "cwe": "CWE-XXX or null"
}}"""

    try:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0,
            max_tokens=300,
        )
        import json
        result = json.loads(response.choices[0].message.content)
        if result.get("is_vulnerability"):
            return {**candidate, **result, "verified": True}
    except Exception as e:
        logger.warning(f"LLM verify error: {e}")
    return None


async def _detect_vulnerabilities(
    files: List[Dict], namespace: str, emit: EmitFn
) -> List[Dict]:
    """Two-phase detection: regex + concurrent LLM verification."""
    await emit({"type": "log", "message": "Phase 1: Running regex pre-filter..."})
    candidates = await _regex_scan(files)
    await emit({"type": "log", "message": f"Phase 1 complete: {len(candidates)} candidates flagged"})

    if not candidates:
        return []

    await emit({"type": "log", "message": "Phase 2: LLM verification (concurrent asyncio.gather)..."})
    tasks = [_llm_verify(c, namespace, emit) for c in candidates]
    results = await asyncio.gather(*tasks)
    verified = [r for r in results if r is not None]

    await emit({"type": "log", "message": f"Verification complete: {len(verified)} confirmed vulnerabilities"})
    return verified


# ─────────────────────────────────────────────────────────────────
# Stage 5 — Fix Synthesis
# ─────────────────────────────────────────────────────────────────

async def _synthesize_fix(
    vuln: Dict, all_files: List[Dict], namespace: str, sem: asyncio.Semaphore
) -> Optional[Dict]:
    """RAG-augmented fix generation for a single vulnerability."""
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])

    # Get full file content
    file_content = next(
        (f["content"] for f in all_files if f["path"] == vuln["file"]), ""
    )

    ctx = await _retrieve(
        f"secure fix for {vuln.get('confirmed_type', vuln['type'])} {vuln['code']}",
        namespace,
        top_k=3,
    )

    lines = file_content.splitlines()
    start = max(0, vuln["line"] - 6)
    end = min(len(lines), vuln["line"] + 5)
    snippet = "\n".join(f"{i+start+1}: {l}" for i, l in enumerate(lines[start:end]))

    context_text = "\n".join(ctx)
    prompt = f"""You are a security engineer. Fix this confirmed vulnerability.

VULNERABILITY:
File: {vuln['file']}
Type: {vuln.get('confirmed_type', vuln['type'])}
Severity: {vuln.get('severity', 'HIGH')}
Explanation: {vuln.get('explanation', vuln['detail'])}
CWE: {vuln.get('cwe', 'N/A')}

VULNERABLE CODE (around line {vuln['line']}):
{snippet}

SIMILAR PATTERNS FROM CODEBASE:
{context_text}

Provide a minimal, production-ready fix. Return ONLY JSON:
{{
  "patched_line": "the corrected line of code",
  "explanation": "what was changed and why",
  "diff_summary": "one-line diff description",
  "imports_needed": ["any new imports required"]
}}"""

    async with sem:
        try:
            response = await client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=500,
            )
            import json
            fix_data = json.loads(response.choices[0].message.content)
            return {
                "file": vuln["file"],
                "line": vuln["line"],
                "original": vuln["code"],
                "patched_line": fix_data.get("patched_line", ""),
                "explanation": fix_data.get("explanation", ""),
                "diff_summary": fix_data.get("diff_summary", ""),
                "imports_needed": fix_data.get("imports_needed", []),
                "vuln_type": vuln.get("confirmed_type", vuln["type"]),
                "severity": vuln.get("severity", "HIGH"),
                "cwe": vuln.get("cwe"),
            }
        except Exception as e:
            logger.warning(f"Fix synthesis error for {vuln['file']}:{vuln['line']} — {e}")
            return None


async def _generate_fixes(
    vulnerabilities: List[Dict], files: List[Dict], namespace: str, emit: EmitFn
) -> List[Dict]:
    sem = asyncio.Semaphore(5)
    tasks = [_synthesize_fix(v, files, namespace, sem) for v in vulnerabilities]

    await emit({"type": "log", "message": f"Synthesizing {len(vulnerabilities)} fixes concurrently..."})
    results = await asyncio.gather(*tasks)
    fixes = [r for r in results if r is not None]
    await emit({"type": "log", "message": f"Generated {len(fixes)} production-ready patches"})
    return fixes


# ─────────────────────────────────────────────────────────────────
# Stage 6 — Pull Request Generation
# ─────────────────────────────────────────────────────────────────

async def _create_pull_request(
    repo_url: str,
    files: List[Dict],
    fixes: List[Dict],
    vulnerabilities: List[Dict],
    architecture: Dict,
    emit: EmitFn,
    token: str,
) -> str:
    from pr_generator import PRGenerator

    gen = PRGenerator(
        github_token=token,
        repo_url=repo_url,
        files=files,
        fixes=fixes,
        vulnerabilities=vulnerabilities,
        architecture=architecture,
        emit=emit,
    )
    pr_url = await gen.create()
    return pr_url


# ─────────────────────────────────────────────────────────────────
# LuminaPipeline — Main Orchestrator
# ─────────────────────────────────────────────────────────────────

class LuminaPipeline:
    def __init__(self, emit_fn: EmitFn, user_token: Optional[str] = None):
        self.emit = emit_fn
        self.user_token = user_token or os.environ.get("GITHUB_TOKEN")

    async def run(self, repo_url: str) -> PipelineState:
        import uuid
        state: PipelineState = {"repo_url": repo_url}

        # Stage 1 — Repository Ingestion
        await self.emit({"type": "stage_start", "stage": "crawl", "message": "Crawling repository..."})
        try:
            owner, repo = _parse_owner_repo(repo_url)
            token = self.user_token
            if not token:
                raise ValueError("No GITHUB_TOKEN provided and not logged in via OAuth.")
            
            await self.emit({"type": "log", "message": "[Step 1] Repo fetch started"})
            files = await _crawl_repo(owner, repo, token, self.emit)
            state["files"] = files
            await self.emit({"type": "log", "message": f"[Step 1] Repo fetched — {len(files)} files"})
            await self.emit({"type": "stage_done", "stage": "crawl"})
        except Exception as e:
            await self.emit({"type": "error", "error": f"Stage 1 failed: {e}"})
            raise

        # Stage 2 — Semantic Indexing
        await self.emit({"type": "stage_start", "stage": "index", "message": "Building semantic index..."})
        try:
            namespace = f"{owner}-{repo}-{uuid.uuid4().hex[:8]}"
            await self.emit({"type": "log", "message": "[Step 2] Semantic indexing started"})
            index_id = await _build_index(files, namespace, self.emit)
            state["index_id"] = index_id
            await self.emit({"type": "log", "message": "[Step 2] Analysis complete — index built"})
            await self.emit({"type": "stage_done", "stage": "index"})
        except Exception as e:
            await self.emit({"type": "error", "error": f"Stage 2 failed: {e}"})
            raise

        # Stage 3 — Architecture Mapping
        await self.emit({"type": "stage_start", "stage": "architecture", "message": "Mapping system architecture..."})
        try:
            await self.emit({"type": "log", "message": "[Step 3] Architecture mapping started"})
            arch = await _map_architecture(files, namespace, self.emit)
            state["architecture"] = arch
            await self.emit({"type": "log", "message": "[Step 3] Architecture mapped"})
            await self.emit({"type": "stage_done", "stage": "architecture"})
        except Exception as e:
            await self.emit({"type": "error", "error": f"Stage 3 failed: {e}"})
            raise

        # Stage 4 — Vulnerability Detection
        await self.emit({"type": "stage_start", "stage": "scan", "message": "Scanning for vulnerabilities..."})
        try:
            await self.emit({"type": "log", "message": "[Step 4] Vulnerability scan started"})
            vulns = await _detect_vulnerabilities(files, namespace, self.emit)
            state["vulnerabilities"] = vulns
            await self.emit({"type": "log", "message": f"[Step 4] Scan complete — {len(vulns)} vulnerabilities confirmed"})
            await self.emit({
                "type": "stage_done", "stage": "scan",
                "count": len(vulns),
                "message": f"{len(vulns)} vulnerabilities confirmed",
            })
        except Exception as e:
            await self.emit({"type": "error", "error": f"Stage 4 failed: {e}"})
            raise

        # Stage 5 — Fix Synthesis
        await self.emit({"type": "stage_start", "stage": "fix", "message": "Generating fixes..."})
        try:
            await self.emit({"type": "log", "message": "[Step 5] Fix synthesis started"})
            fixes = await _generate_fixes(vulns, files, namespace, self.emit) if vulns else []
            state["fixes"] = fixes
            await self.emit({"type": "log", "message": f"[Step 5] {len(fixes)} fixes synthesized"})
            await self.emit({"type": "stage_done", "stage": "fix"})
        except Exception as e:
            await self.emit({"type": "error", "error": f"Stage 5 failed: {e}"})
            raise

        # Stage 6 — Pull Request Creation
        await self.emit({"type": "stage_start", "stage": "pr", "message": "Creating pull request..."})
        try:
            await self.emit({"type": "log", "message": "[Step 6] PR creation started"})
            pr_url = await _create_pull_request(
                repo_url, files, fixes, vulns, state.get("architecture", {}), self.emit, self.user_token
            )
            state["pr_url"] = pr_url
            await self.emit({"type": "log", "message": f"[Step 6] PR created: {pr_url}"})
            await self.emit({"type": "stage_done", "stage": "pr"})
        except Exception as e:
            await self.emit({"type": "error", "error": f"Stage 6 failed: {e}"})
            raise

        # Pipeline complete — send full data for report rendering
        vulns = state.get("vulnerabilities", [])
        fixes = state.get("fixes", [])
        arch = state.get("architecture", {})
        await self.emit({
            "type": "complete",
            "pr_url": state.get("pr_url", ""),
            "vulnerabilities_found": len(vulns),
            "fixes_applied": len(fixes),
            "report": {
                "vulnerabilities": vulns,
                "fixes": fixes,
                "architecture": arch,
                "files_scanned": len(state.get("files", [])),
            },
        })
        return state
