"""
LUMINA - Autonomous AI Security Auditor v2.0
GitHub PR Generator — Fork / Branch / Commit / PR Automation
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger("lumina.pr_generator")

EmitFn = Callable[[dict], Coroutine]


class PRGenerator:
    """
    Automates:
      1. Fork repository (if not owner)
      2. Create 'lumina-security-audit' branch
      3. Apply fixes to file contents
      4. Concurrent file commits via Semaphore(3)
      5. Open a descriptive pull request
    """

    BRANCH_NAME = "fix/ai-auto-audit"

    def __init__(
        self,
        github_token: str,
        repo_url: str,
        files: List[Dict],
        fixes: List[Dict],
        vulnerabilities: List[Dict],
        architecture: Dict,
        emit: EmitFn,
    ):
        self.token = github_token
        self.repo_url = repo_url
        self.files = {f["path"]: f["content"] for f in files}
        self.fixes = fixes
        self.vulnerabilities = vulnerabilities
        self.architecture = architecture
        self.emit = emit

        # Parse owner/repo
        import re
        match = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url.strip())
        if not match:
            raise ValueError(f"Invalid GitHub URL: {repo_url}")
        self.owner = match.group(1)
        self.repo_name = match.group(2)

    # ──────────────────────────────────────────────
    # Public
    # ──────────────────────────────────────────────

    async def create(self) -> str:
        """Orchestrate the full PR creation flow."""
        from github import Github, GithubException

        g = Github(self.token)
        user = g.get_user()
        me = user.login
        await self.emit({"type": "log", "message": f"Authenticated as: {me}"})

        # Get target repo
        original_repo = g.get_repo(f"{self.owner}/{self.repo_name}")

        # Fork if we don't own it
        if me.lower() == self.owner.lower():
            target_repo = original_repo
            await self.emit({"type": "log", "message": "You own this repo — working directly."})
        else:
            await self.emit({"type": "log", "message": "Forking repository..."})
            target_repo = user.create_fork(original_repo)
            await asyncio.sleep(5)  # Allow fork to propagate
            await self.emit({"type": "log", "message": f"Fork created: {target_repo.full_name}"})

        # Get default branch SHA
        default_branch = target_repo.default_branch
        ref = target_repo.get_git_ref(f"heads/{default_branch}")
        sha = ref.object.sha

        # Create security branch
        branch_name = self.BRANCH_NAME
        await self.emit({"type": "log", "message": f"Creating branch: {branch_name}"})
        # Delete branch if already exists (idempotent)
        try:
            existing_ref = target_repo.get_git_ref(f"heads/{branch_name}")
            existing_ref.delete()
            await asyncio.sleep(1)
        except Exception:
            pass
            
        try:
            target_repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=sha)
        except GithubException as e:
            if e.status == 403:
                await self.emit({"type": "error", "error": "GitHub 403: Your GITHUB_TOKEN in .env lacks branch/repo write permissions."})
            raise

        # Apply fixes to files
        patched_files = self._apply_fixes()
        await self.emit({"type": "log", "message": f"Applied {len(patched_files)} file patches"})

        # Build and commit the audit report
        report_content = self._build_audit_report_md()
        patched_files["AI_AUDIT_REPORT.md"] = report_content
        await self.emit({"type": "log", "message": "AI_AUDIT_REPORT.md prepared"})

        # Concurrent commits
        await self._commit_files(target_repo, branch_name, patched_files)

        # Create PR (on fork → original, or on repo itself)
        pr_url = await self._open_pr(g, original_repo, target_repo, branch_name, me)

        return pr_url

    # ──────────────────────────────────────────────
    # Fix Application
    # ──────────────────────────────────────────────

    def _apply_fixes(self) -> Dict[str, str]:
        """
        Apply line-level patches to file contents.
        Groups fixes by file, applies patched_line replacements.
        """
        patched: Dict[str, str] = {}

        fixes_by_file: Dict[str, List[Dict]] = {}
        for fix in self.fixes:
            fixes_by_file.setdefault(fix["file"], []).append(fix)

        for file_path, file_fixes in fixes_by_file.items():
            if file_path not in self.files:
                continue
            lines = self.files[file_path].splitlines()
            changed = False

            for fix in sorted(file_fixes, key=lambda x: x["line"]):
                line_idx = fix["line"] - 1
                if 0 <= line_idx < len(lines):
                    # Preserve original indentation
                    indent = len(lines[line_idx]) - len(lines[line_idx].lstrip())
                    new_line = " " * indent + fix["patched_line"].lstrip()
                    lines[line_idx] = new_line
                    changed = True

            if changed:
                # Prepend imports if needed
                imports = []
                for fix in file_fixes:
                    for imp in fix.get("imports_needed", []):
                        if imp and imp not in "\n".join(lines[:20]):
                            imports.append(imp)
                if imports:
                    lines = imports + [""] + lines

                patched[file_path] = "\n".join(lines)

        return patched

    # ──────────────────────────────────────────────
    # Concurrent File Commits
    # ──────────────────────────────────────────────

    async def _commit_files(self, repo, branch_name: str, patched_files: Dict[str, str]):
        sem = asyncio.Semaphore(3)
        tasks = [
            self._commit_one(repo, branch_name, path, content, sem)
            for path, content in patched_files.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        committed = sum(1 for r in results if not isinstance(r, Exception))
        await self.emit({"type": "log", "message": f"Committed {committed}/{len(patched_files)} files"})

    async def _commit_one(self, repo, branch: str, path: str, content: str, sem: asyncio.Semaphore):
        async with sem:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._sync_commit, repo, branch, path, content)

    def _sync_commit(self, repo, branch: str, path: str, content: str):
        """Synchronous PyGithub commit (runs in executor thread)."""
        try:
            existing = repo.get_contents(path, ref=branch)
            repo.update_file(
                path=path,
                message=f"[LUMINA] Security fix: {path}",
                content=content,
                sha=existing.sha,
                branch=branch,
            )
        except Exception:
            repo.create_file(
                path=path,
                message=f"[LUMINA] Security fix: {path}",
                content=content,
                branch=branch,
            )

    # ──────────────────────────────────────────────
    # Pull Request
    # ──────────────────────────────────────────────

    async def _open_pr(self, g, original_repo, target_repo, branch_name: str, me: str) -> str:
        await self.emit({"type": "log", "message": "Opening pull request..."})

        body = self._build_pr_body()
        title = f"[LUMINA] Security Audit — {len(self.vulnerabilities)} vulnerabilities fixed"

        loop = asyncio.get_event_loop()

        if target_repo.full_name != original_repo.full_name:
            head = f"{me}:{branch_name}"
            pr = await loop.run_in_executor(
                None,
                lambda: original_repo.create_pull(
                    title=title,
                    body=body,
                    head=head,
                    base=original_repo.default_branch,
                ),
            )
        else:
            pr = await loop.run_in_executor(
                None,
                lambda: original_repo.create_pull(
                    title=title,
                    body=body,
                    head=branch_name,
                    base=original_repo.default_branch,
                ),
            )

        await self.emit({"type": "log", "message": f"Pull request opened: {pr.html_url}"})
        return pr.html_url

    def _build_audit_report_md(self) -> str:
        """Generate AI_AUDIT_REPORT.md committed alongside fixes."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            "# AI Audit Report — LUMINA Autonomous Security Auditor",
            f"\n**Generated:** {ts}  ",
            f"**Vulnerabilities Found:** {len(self.vulnerabilities)}  ",
            f"**Fixes Applied:** {len(self.fixes)}  ",
            f"**Branch:** `fix/ai-auto-audit`\n",
            "---\n",
            "## Vulnerabilities Found\n",
        ]
        if not self.vulnerabilities:
            lines.append("_No vulnerabilities detected._\n")
        for i, v in enumerate(self.vulnerabilities, 1):
            lines.append(
                f"### {i}. {v.get('confirmed_type', v.get('type', 'Unknown'))} "
                f"— {v.get('severity', 'UNKNOWN')}\n"
                f"- **File:** `{v['file']}` (line {v['line']})\n"
                f"- **CWE:** {v.get('cwe', 'N/A')}\n"
                f"- **Detail:** {v.get('explanation', v.get('detail', ''))}\n"
                f"- **Vulnerable code:** `{v.get('code', '').strip()}`\n"
            )

        lines.append("\n---\n\n## Fixes Applied\n")
        if not self.fixes:
            lines.append("_No fixes generated._\n")
        for i, f in enumerate(self.fixes, 1):
            lines.append(
                f"### Fix {i} — `{f['file']}` (line {f['line']})\n"
                f"**Before:**\n```\n{f.get('original', '').strip()}\n```\n"
                f"**After:**\n```\n{f.get('patched_line', '').strip()}\n```\n"
                f"**Explanation:** {f.get('explanation', '')}\n"
            )

        lines.append(
            "\n---\n\n> ⚠️ All AI-generated fixes must be reviewed by a security engineer before merging.\n"
            "\n*LUMINA v2.0 — Autonomous AI Security Auditor*\n"
        )
        return "\n".join(lines)

    def _build_pr_body(self) -> str:
        """Generate comprehensive PR description."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

        # Summary table
        severity_counts = {}
        for v in self.vulnerabilities:
            sev = v.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        sev_table = "\n".join(
            f"| {sev} | {count} |"
            for sev, count in sorted(severity_counts.items())
        )

        # Vulnerability list
        vuln_list = ""
        for i, v in enumerate(self.vulnerabilities, 1):
            vuln_list += (
                f"\n### {i}. {v.get('confirmed_type', v.get('type', 'Unknown'))} "
                f"({v.get('severity', 'UNKNOWN')})\n"
                f"- **File:** `{v['file']}` (line {v['line']})\n"
                f"- **CWE:** {v.get('cwe', 'N/A')}\n"
                f"- **Detail:** {v.get('explanation', v.get('detail', ''))}\n"
            )

        # Tech stack from architecture
        tech = ", ".join(self.architecture.get("tech_stack", []))
        components = len(self.architecture.get("components", {}))

        return f"""## 🔐 LUMINA Autonomous Security Audit Report

> **Generated:** {ts}  
> **Tool:** LUMINA — Autonomous AI Security Auditor v2.0  
> **Pipeline:** LangGraph + GPT-4o + Pinecone RAG

---

## 📊 Audit Summary

| Metric | Value |
|--------|-------|
| Total Vulnerabilities Found | **{len(self.vulnerabilities)}** |
| Fixes Applied | **{len(self.fixes)}** |
| Files Modified | **{len(set(f['file'] for f in self.fixes))}** |
| Tech Stack | {tech or 'Auto-detected'} |
| Components Mapped | {components} |

### Severity Breakdown

| Severity | Count |
|----------|-------|
{sev_table}

---

## 🛡️ Vulnerabilities Fixed

{vuln_list}

---

## 🔍 How LUMINA Works

This PR was automatically generated by LUMINA's 6-stage pipeline:

1. **Repository Ingestion** — Parallel async GitHub API crawling
2. **Semantic Indexing** — 3072-dim embeddings in Pinecone vector DB
3. **Architecture Mapping** — GPT-4o component & data-flow analysis
4. **Vulnerability Detection** — Regex pre-filter + concurrent LLM verification
5. **Fix Synthesis** — RAG-augmented production-ready patch generation
6. **Pull Request** — Automated fork / branch / commit / PR

---

> ⚠️ **Review Required:** All AI-generated fixes should be reviewed by a security engineer before merging.
> LUMINA provides remediation suggestions — human verification is essential for production deployments.

*LUMINA v2.0 — BCA Final Year Project | Department of Computer Science*
"""
