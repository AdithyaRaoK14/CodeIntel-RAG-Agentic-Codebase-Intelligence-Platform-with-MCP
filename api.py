"""
api.py  –  Codebase Intelligence REST API
──────────────────────────────────────────
Run:  uvicorn api:app --reload --port 8000

Changes (v3)
────────────
1.  Deprecated @app.on_event replaced with lifespan context manager
2.  API key authentication (X-API-Key header) on all mutating endpoints
3.  Path traversal validation on /load
4.  Stricter GitHub URL validation on /clone (SSRF prevention)
5.  /export now uses Jinja2 templates (XSS prevention)
6.  get_state() DI scaffold — _DEFAULT_STATE injectable / testable
7.  POST /impact — change impact analysis (multi-hop dependency tree)
8.  GET  /metrics — query telemetry (total queries, cache hits, latency)
"""

from __future__ import annotations
from agent_router import agent_router
from vulnerability_scanner import scan_chunks, scan_summary
from visualization.call_graph import (
    build_call_graph, draw_call_graph, draw_call_graph_interactive,
)
from retrieval.reranker import rerank
from retrieval.hybrid_retriever import build_bm25_index, hybrid_search
from pydantic import BaseModel
from parser.repo_loader import load_repository
from parser.dependency_analyzer import find_function_usage, get_full_dependency_tree
from parser.code_chunker import chunk_generic_code, chunk_python_code
from generator.response_generator import (
    build_messages, generate_answer, llm_available, stream_ollama,
)
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from embeddings.vector_store import clear_collection, store_chunks
from config import settings
import cache.query_cache as query_cache

import base64
import io
import json
import logging
import logging.config
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime

import matplotlib
matplotlib.use("Agg")


# ─────────────────────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Application state
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AppState:
    chunks:     list[dict] = field(default_factory=list)
    docs:       list[dict] = field(default_factory=list)
    repo:       str = ""
    temp_dirs:  list[str] = field(default_factory=list)
    bm25_index: object = None
    _lock:      threading.Lock = field(
        default_factory=threading.Lock, repr=False)


_DEFAULT_STATE = AppState()


def get_state() -> AppState:
    """FastAPI dependency — returns the shared application state."""
    return _DEFAULT_STATE


# ─────────────────────────────────────────────────────────────────────────────
#  Telemetry
# ─────────────────────────────────────────────────────────────────────────────

_METRICS: dict[str, float] = {
    "total_queries":    0,
    "cache_hits":       0,
    "total_latency_ms": 0.0,
    "rerank_calls":     0,
}


# ─────────────────────────────────────────────────────────────────────────────
#  Security helpers
# ─────────────────────────────────────────────────────────────────────────────

API_KEY: str = settings.api_key


def verify_api_key(request: Request) -> None:
    """Dependency: validates X-API-Key header when API_KEY is configured."""
    if not API_KEY:
        return
    key = request.headers.get("X-API-Key", "")
    if key != API_KEY:
        raise HTTPException(401, detail="Invalid or missing API key")


ALLOWED_REPO_BASE: str = os.getenv("REPO_BASE", settings.repo_base)
_PATH_BLOCKLIST = ("/etc", "/proc", "/sys", "C:\\Windows")


def _validate_repo_path(repo_path: str) -> str:
    """Resolve and validate a repo path. Raises HTTPException(400) on violation."""
    if ".." in repo_path:
        raise HTTPException(400, detail="Path not allowed")
    for blocked in _PATH_BLOCKLIST:
        if repo_path.startswith(blocked):
            raise HTTPException(400, detail="Path not allowed")

    real_path = os.path.realpath(repo_path)
    real_base = os.path.realpath(ALLOWED_REPO_BASE)
    real_cwd = os.path.realpath(".")

    if not (real_path.startswith(real_base) or real_path.startswith(real_cwd)):
        raise HTTPException(400, detail="Path not allowed")

    return real_path


_GITHUB_RE = re.compile(
    r'^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$'
)


def _validate_github_url(url: str) -> str:
    """Return validated .git URL or raise HTTPException(400)."""
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    if not _GITHUB_RE.match(url):
        log.warning("Rejected GitHub URL: %s", url)
        raise HTTPException(
            400,
            detail="Only well-formed GitHub URLs accepted: https://github.com/<owner>/<repo>",
        )

    for bad in ("@", "%", "?", "#"):
        if bad in url.replace("https://", ""):
            log.warning("Rejected GitHub URL with bad char '%s': %s", bad, url)
            raise HTTPException(400, detail="Path not allowed")

    return url + ".git"


# ─────────────────────────────────────────────────────────────────────────────
#  Security query filtering
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_WORDS = {
    "unsafe", "vulnerable", "vulnerability", "vulnerabilities",
    "injection", "eval", "exec", "hardcoded", "exploit",
    "dangerous", "insecure", "weakness", "malicious",
    "security", "secure",
}

# Maps query keywords → terms to search across all finding fields.
# None means show all findings (no filtering).
KEYWORD_FILTERS: dict[str, list[str] | None] = {
    "hardcoded":       ["hardcoded", "password", "secret", "credential"],
    "injection":       ["injection", "sql", "inject",
                        "unsanitized", "user input", "query"],
    "eval":            ["eval", "literal_eval", "exec",
                        "code execution", "arbitrary"],
    "exec":            ["exec", "code execution", "arbitrary"],
    "exploit":         ["exploit", "arbitrary", "remote", "rce"],
    "malicious":       ["malicious", "backdoor", "trojan"],
    "weakness":        ["weakness", "weak", "cwe"],
    "secure":          ["hash", "sha", "md5", "weak", "crypto",
                        "cipher", "ssl", "tls", "cert"],
    # General queries — show all findings, no filtering
    "unsafe":          None,
    "vulnerable":      None,
    "vulnerability":   None,
    "vulnerabilities": None,
    "dangerous":       None,
    "insecure":        None,
    "security":        None,
}


def _filter_findings(findings: list[dict], query_words: set[str]) -> tuple[list[dict], str | None]:
    """
    Filter findings based on query keywords.
    Returns (filtered_findings, label) where label is the matched keyword or None.
    Matches across description, function name, category and file fields so it
    works regardless of which scanner or repo produced the findings.
    """
    for kw, terms in KEYWORD_FILTERS.items():
        if kw not in query_words:
            continue
        if terms is None:
            # Keyword means "show everything"
            return findings, None

        filtered = [
            f for f in findings
            if any(
                t in (
                    f.get("description", "") + " " +
                    f.get("function",    "") + " " +
                    f.get("cwe_name",    "") + " " +
                    f.get("file",        "")
                ).lower()
                for t in terms
            )
        ]
        return filtered, kw

    return findings, None


# ─────────────────────────────────────────────────────────────────────────────
#  Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    default = os.getenv("REPO_PATH", settings.default_repo)
    if os.path.exists(default):
        _load_repo(default, _DEFAULT_STATE)

    yield

    for d in _DEFAULT_STATE.temp_dirs:
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
#  FastAPI app
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Codebase Intelligence API",
    version="3.0",
    lifespan=lifespan,
)
app.include_router(agent_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
    allow_credentials=True,
)

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


# ─────────────────────────────────────────────────────────────────────────────
#  Request schemas
# ─────────────────────────────────────────────────────────────────────────────

class LoadRequest(BaseModel):
    repo_path: str


class CloneRequest(BaseModel):
    github_url: str


class ChatRequest(BaseModel):
    query:   str
    history: list[dict] = []


class ImpactRequest(BaseModel):
    function_name: str


# ─────────────────────────────────────────────────────────────────────────────
#  Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_repo(repo_path: str, state: AppState) -> None:
    docs = load_repository(repo_path)
    chunks: list[dict] = []

    for doc in docs:
        if doc["file_name"].endswith(".py"):
            chunks.extend(chunk_python_code(doc["content"], doc["file_name"]))
        else:
            chunks.extend(chunk_generic_code(doc["content"], doc["file_name"]))

    clear_collection()
    store_chunks(chunks)
    query_cache.clear()
    query_cache._CACHE._repo = repo_path

    bm25 = build_bm25_index(chunks)

    with state._lock:
        state.docs = docs
        state.chunks = chunks
        state.repo = repo_path
        state.bm25_index = bm25

    log.info("Loaded repo: %s (%d functions, %d files)",
             repo_path, len(chunks), len(docs))


def _retrieve(query: str, state: AppState) -> list[dict]:
    """Two-stage retrieval with metrics tracking."""
    t0 = time.monotonic()
    _METRICS["total_queries"] += 1

    cached = query_cache.get(query)
    if cached:
        log.info("Cache hit: %s", query[:50])
        _METRICS["cache_hits"] += 1
        _METRICS["total_latency_ms"] += (time.monotonic() - t0) * 1000
        return cached

    candidates = hybrid_search(query, state.chunks, state.bm25_index)
    results = rerank(query, candidates[:settings.rerank_candidates])
    _METRICS["rerank_calls"] += 1
    query_cache.set(query, results)

    _METRICS["total_latency_ms"] += (time.monotonic() - t0) * 1000
    return results


def _graph_b64(query: str, results: list[dict], state: AppState) -> str | None:
    try:
        import matplotlib.pyplot as plt
        graph = build_call_graph(state.chunks, query, results)
        figure = draw_call_graph(graph)
        buf = io.BytesIO()
        figure.savefig(buf, format="png", bbox_inches="tight",
                       facecolor="#1E1E2E", dpi=120)
        buf.seek(0)
        b64 = base64.b64encode(buf.read()).decode()
        plt.close(figure)
        return b64
    except Exception as exc:
        log.warning("Could not render call graph: %s", exc)
        return None


def _format_results(results: list[dict]) -> list[dict]:
    out = []
    for r in results[:settings.top_k]:
        calls = r.get("calls", [])
        if isinstance(calls, str):
            try:
                calls = json.loads(calls)
            except Exception:
                calls = [c.strip() for c in calls.split(",") if c.strip()]
        out.append({
            "name":     r.get("name", ""),
            "file":     r.get("file", ""),
            "line":     r.get("line", 0),
            "calls":    calls,
            "code":     r.get("code", ""),
            "language": r.get("language", ""),
        })
    return out


def _lang_counts(chunks: list[dict]) -> Counter:
    counts: Counter = Counter()
    for c in chunks:
        f = c.get("file", "")
        if f.endswith(".py"):
            counts["Python"] += 1
        elif f.endswith(".java"):
            counts["Java"] += 1
        elif f.endswith(".js"):
            counts["JavaScript"] += 1
        elif f.endswith(".cpp"):
            counts["C++"] += 1
        elif f.endswith(".ts"):
            counts["TypeScript"] += 1
    return counts


# ─────────────────────────────────────────────────────────────────────────────
#  Unauthenticated endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def serve_ui():
    if os.path.exists("static/index.html"):
        return FileResponse("static/index.html")
    return {"message": "Codebase Intelligence API v3.0"}


@app.get("/health")
def health(state: AppState = Depends(get_state)):
    return {
        "status":    "ok",
        "llm":       llm_available(),
        "repo":      state.repo,
        "functions": len(state.chunks),
        "files":     len(state.docs),
    }


@app.get("/stats")
def stats(state: AppState = Depends(get_state)):
    return {
        "total_functions": len(state.chunks),
        "total_files":     len(state.docs),
        "languages":       dict(_lang_counts(state.chunks)),
        "repo":            state.repo,
    }


@app.get("/metrics")
def metrics():
    total = _METRICS["total_queries"]
    avg = _METRICS["total_latency_ms"] / total if total > 0 else 0.0
    return {**_METRICS, "avg_latency_ms": round(avg, 2)}


# ─────────────────────────────────────────────────────────────────────────────
#  Authenticated endpoints
# ─────────────────────────────────────────────────────────────────────────────

_AUTH = [Depends(verify_api_key)]


@app.post("/load", dependencies=_AUTH)
async def load_repo(req: LoadRequest, state: AppState = Depends(get_state)):
    validated = _validate_repo_path(req.repo_path)
    if not os.path.exists(validated):
        raise HTTPException(400, detail="Repository path not found")
    import asyncio
    await asyncio.to_thread(_load_repo, validated, state)
    with state._lock:
        return {"status": "loaded", "repo": state.repo,
                "functions": len(state.chunks), "files": len(state.docs)}


@app.post("/clone", dependencies=_AUTH)
async def clone_github(req: CloneRequest, state: AppState = Depends(get_state)):
    import asyncio
    url = _validate_github_url(req.github_url)

    temp_dir = tempfile.mkdtemp(prefix="codeintel_")
    with state._lock:
        state.temp_dirs.append(temp_dir)

    def _do_clone():
        result = subprocess.run(
            ["git", "clone", "--depth=1", url, temp_dir],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr[:200]}")

    try:
        await asyncio.to_thread(_do_clone)
    except RuntimeError as exc:
        raise HTTPException(400, detail=str(exc))
    except FileNotFoundError:
        raise HTTPException(500, detail="git is not installed.")
    except subprocess.TimeoutExpired:
        raise HTTPException(
            408, detail="Clone timed out — repo may be too large")

    await asyncio.to_thread(_load_repo, temp_dir, state)
    repo_name = url.split("/")[-1].replace(".git", "")
    with state._lock:
        return {"status": "cloned", "repo": repo_name,
                "functions": len(state.chunks), "files": len(state.docs)}


@app.post("/upload", dependencies=_AUTH)
async def upload_zip(
    file: UploadFile = File(...),
    state: AppState = Depends(get_state),
):
    if not file.filename.endswith(".zip"):
        raise HTTPException(400, detail="Only .zip files are supported")

    temp_dir = tempfile.mkdtemp(prefix="codeintel_")
    state.temp_dirs.append(temp_dir)
    zip_path = os.path.join(temp_dir, "repo.zip")
    extract_dir = os.path.join(temp_dir, "repo")
    os.makedirs(extract_dir, exist_ok=True)

    content = await file.read()
    with open(zip_path, "wb") as fh:
        fh.write(content)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)
    except zipfile.BadZipFile:
        raise HTTPException(400, detail="Invalid zip file")

    entries = os.listdir(extract_dir)
    if len(entries) == 1 and os.path.isdir(os.path.join(extract_dir, entries[0])):
        extract_dir = os.path.join(extract_dir, entries[0])

    _load_repo(extract_dir, state)
    return {"status": "uploaded", "repo": file.filename,
            "functions": len(state.chunks), "files": len(state.docs)}


@app.post("/chat", dependencies=_AUTH)
async def chat(req: ChatRequest, state: AppState = Depends(get_state)):
    import asyncio
    if not state.chunks:
        raise HTTPException(400, detail="No repository loaded")

    query = req.query.strip()
    query_words = set(re.sub(r'[^\w]', '', w) for w in query.lower().split())

    # ── Security query routing ────────────────────────────────────────────────
    # Uses <br> tags so the typewriter takes the HTML fast-path and bullets
    # render on separate lines. Retrieval still runs so chips/callers/graph
    # appear normally in the UI.
    if query_words & SECURITY_WORDS:
        all_findings = scan_chunks(state.chunks, repo_path=state.repo)
        findings, matched_kw = _filter_findings(all_findings, query_words)

        # ── File-specific filtering ───────────────────────────────────────────
        # If the query mentions a filename (e.g. "in sessions.py"), narrow
        # findings to only that file.
        file_filter = next(
            (w for w in query_words if w.endswith("py") or w.endswith("js")
             or w.endswith("ts") or w.endswith("java") or w.endswith("cpp")),
            None,
        )
        if file_filter:
            file_findings = [
                f for f in findings
                if file_filter in os.path.basename(f.get("file", "")).lower()
            ]
            # Only apply if it actually narrows results, otherwise keep all
            if file_findings:
                findings = file_findings
        # ── end file filtering ────────────────────────────────────────────────

        if not all_findings:
            answer = "✅ No security vulnerabilities detected by the scanner."
        elif not findings:
            # Specific category was requested but nothing matched
            answer = (
                f"✅ No {matched_kw}-related issues found in this repository. "
                f"However, {len(all_findings)} other issue(s) exist — "
                f"try asking 'Where is unsafe code?' to see all findings."
            )
        else:
            lines = [f"Security scan found {len(findings)} issue(s):<br>"]
            for f in findings[:10]:
                lines.append(
                    f"• [{f['severity']}] <b>{f['function']}()</b>"
                    f" in <code>{f['file']}</code>"
                    f" line {f['line']}: {f['description']}"
                )
            answer = "<br>".join(lines)

        # Still run retrieval so chips / callers / graph render normally
        results = await asyncio.to_thread(_retrieve, query, state)
        graph = await asyncio.to_thread(_graph_b64, query, results, state)
        callers = []
        if results:
            raw = find_function_usage(state.chunks, results[0]["name"])
            callers = [{"function": c["function"], "file": c["file"]}
                       for c in raw]

        return {
            "answer":   answer,
            "results":  _format_results(results),
            "callers":  callers,
            "graph":    graph,
            "llm_used": False,
        }
    # ── end security routing ──────────────────────────────────────────────────

    results = await asyncio.to_thread(_retrieve, query, state)
    answer = await asyncio.to_thread(generate_answer, query, results, req.history)
    graph = await asyncio.to_thread(_graph_b64, query, results, state)

    callers = []
    if results:
        raw = find_function_usage(state.chunks, results[0]["name"])
        callers = [{"function": c["function"], "file": c["file"]} for c in raw]

    return {
        "answer":   answer,
        "results":  _format_results(results),
        "callers":  callers,
        "graph":    graph,
        "llm_used": llm_available(),
    }


@app.post("/chat/stream", dependencies=_AUTH)
async def chat_stream(req: ChatRequest, state: AppState = Depends(get_state)):
    if not state.chunks:
        raise HTTPException(400, detail="No repository loaded")

    query = req.query.strip()
    results = _retrieve(query, state)
    messages = build_messages(query, results, req.history)

    return StreamingResponse(
        stream_ollama(messages),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/graph/interactive", response_class=HTMLResponse)
def interactive_graph(query: str = "", state: AppState = Depends(get_state)):
    if not state.chunks:
        raise HTTPException(400, detail="No repository loaded")
    if not query:
        raise HTTPException(400, detail="Provide a ?query= parameter")

    results = _retrieve(query, state)
    graph = build_call_graph(state.chunks, query, results)
    html = draw_call_graph_interactive(graph)

    if html is None:
        return HTMLResponse(content="<p>pyvis not installed — run: pip install pyvis</p>")
    return HTMLResponse(content=html)


@app.get("/vulnerabilities", dependencies=_AUTH)
def vulnerabilities(state: AppState = Depends(get_state)):
    if not state.chunks:
        raise HTTPException(400, detail="No repository loaded")
    findings = scan_chunks(state.chunks, repo_path=state.repo)
    summary = scan_summary(findings)
    return {"findings": findings, "summary": summary,
            "total": len(findings), "repo": state.repo}


@app.get("/export", response_class=HTMLResponse, dependencies=_AUTH)
def export_report(request: Request, state: AppState = Depends(get_state)):
    if not state.chunks:
        raise HTTPException(400, detail="No repository loaded")

    findings = scan_chunks(state.chunks, repo_path=state.repo)
    summary = scan_summary(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lc = _lang_counts(state.chunks)

    class _Row:
        def __init__(self, c: dict):
            self.name = c.get("name", "")
            self.file = c.get("file", "")
            self.line = c.get("line", "?")
            calls = c.get("calls", [])
            # Normalise: stored as JSON string or comma-separated string
            if isinstance(calls, str):
                try:
                    calls = json.loads(calls)
                except Exception:
                    calls = [x.strip() for x in calls.split(",") if x.strip()]
            # Ensure it's a flat list of plain strings
            if isinstance(calls, list):
                calls = [str(x) for x in calls if x]
            else:
                calls = []
            self.calls = calls
            self.calls_str = ", ".join(calls)

    return templates.TemplateResponse("report.html", {
        "request":       request,
        "repo":          state.repo,
        "now":           now,
        "num_functions": len(state.chunks),
        "num_files":     len(state.docs),
        "num_languages": len(lc),
        "num_findings":  len(findings),
        "summary":       summary,
        "findings":      findings,
        "chunks":        [_Row(c) for c in state.chunks],
    })


@app.post("/impact", dependencies=_AUTH)
def impact_analysis(req: ImpactRequest, state: AppState = Depends(get_state)):
    if not state.chunks:
        raise HTTPException(400, detail="No repository loaded")

    tree = get_full_dependency_tree(
        state.chunks, req.function_name, max_depth=3)

    def _count(node: dict, seen: set | None = None) -> int:
        if seen is None:
            seen = set()
        total = 0
        for caller in node.get("callers", []):
            fn = caller.get("function", "")
            if fn not in seen:
                seen.add(fn)
                total += 1 + _count(caller, seen)
        return total

    affected = _count(tree)
    risk = "HIGH" if affected > 10 else ("MEDIUM" if affected > 3 else "LOW")

    return {
        "function":           req.function_name,
        "affected_functions": affected,
        "tree":               tree,
        "risk_level":         risk,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Voice transcription
# ─────────────────────────────────────────────────────────────────────────────

_whisper_model = None


def _get_whisper():
    global _whisper_model
    if _whisper_model is None:
        try:
            from faster_whisper import WhisperModel
            _whisper_model = WhisperModel(
                "tiny", device="cpu", compute_type="int8")
        except ImportError:
            return None
    return _whisper_model


@app.post("/transcribe")
async def transcribe(audio: UploadFile = File(...)):
    model = _get_whisper()
    if model is None:
        raise HTTPException(500,
                            detail="faster-whisper not installed. Run: pip install faster-whisper")

    content = await audio.read()
    with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        segments, _ = model.transcribe(tmp_path, beam_size=1)
        transcript = " ".join(s.text for s in segments).strip()
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return {"transcript": transcript}
