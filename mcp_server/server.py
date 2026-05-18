"""
mcp_server/server.py
─────────────────────
FastMCP server that exposes all Codebase Intelligence tools via the
Model Context Protocol (MCP).

Transport: SSE (Server-Sent Events) — runs inside the existing FastAPI app.
Endpoint after mounting: GET /mcp/sse  and  POST /mcp/messages

Compatible clients (all free):
  • Any custom MCP client (see mcp_server/ollama_client.py for Ollama)
  • Cursor IDE  (Settings → MCP → add server URL)
  • Continue.dev VS Code extension
  • Open WebUI via mcpo proxy

HOW IT WORKS
────────────
When FastAPI starts (uvicorn api:app), this MCP server is mounted at /mcp.
Tools directly import the live AppState from api.py — zero HTTP overhead,
zero extra port, zero extra process.
"""

from __future__ import annotations

import json
import logging
import os

from mcp.server.fastmcp import FastMCP

log = logging.getLogger(__name__)

# ── Create the MCP server ─────────────────────────────────────────────────────

mcp = FastMCP(
    name="codebase-intelligence",
    instructions=(
        "Expert Codebase Intelligence tools for Python, Java, JavaScript, "
        "TypeScript and C++ repositories. "
        "Use search_codebase for general questions, scan_security for "
        "vulnerability audits, get_call_graph / impact_analysis for "
        "dependency analysis, and repo_overview for repo statistics. "
        "Always use a tool before answering — never guess about code."
    ),
)


# ── Shared state accessor ─────────────────────────────────────────────────────

def _state():
    """
    Lazy-import the live AppState from api.py.
    Works because the MCP server runs in the same uvicorn process.
    Returns None if somehow called outside that context.
    """
    try:
        from api import get_state  # noqa: PLC0415
        return get_state()
    except Exception as exc:
        log.warning("Cannot access AppState: %s", exc)
        return None


# ── Tool 1: Hybrid Code Search ────────────────────────────────────────────────

@mcp.tool()
def search_codebase(query: str) -> str:
    """
    Search the indexed codebase using hybrid BM25 + semantic retrieval with
    cross-encoder reranking.

    Use for:
    - "Where is authentication handled?"
    - "How does error handling work?"
    - "Find the database connection logic"
    - "What does login() call?"

    Args:
        query: Natural-language question about the codebase.

    Returns:
        Top matching functions with file, line number, call list, and code snippet.
    """
    state = _state()
    if state is None or not state.chunks:
        return "No repository loaded. Load one first via POST /load or POST /clone."

    from retrieval.hybrid_retriever import hybrid_search  # noqa: PLC0415
    from retrieval.reranker import rerank                # noqa: PLC0415
    from config import settings                          # noqa: PLC0415

    try:
        candidates = hybrid_search(query, state.chunks, state.bm25_index)
        results    = rerank(query, candidates[:settings.rerank_candidates])
    except Exception as exc:
        log.error("search_codebase error: %s", exc)
        return f"Search failed: {exc}"

    if not results:
        return "No relevant functions found for that query."

    lines = [f"Found {len(results)} relevant function(s):\n"]
    for i, r in enumerate(results[:5], 1):
        calls = r.get("calls", [])
        if isinstance(calls, str):
            try:
                calls = json.loads(calls)
            except Exception:
                calls = [c.strip() for c in calls.split(",") if c.strip()]
        calls_str = ", ".join(calls[:5]) or "none"

        lines.append(
            f"{i}. {r['name']}() in {r['file']} (line {r.get('line', '?')})\n"
            f"   Calls: {calls_str}\n"
            f"   Code:\n"
            f"   {r.get('code', '')[:300].strip()}\n"
        )
    return "\n".join(lines)


# ── Tool 2: Security Scanner ──────────────────────────────────────────────────

@mcp.tool()
def scan_security(focus: str = "") -> str:
    """
    Run a security vulnerability scan on the loaded repository.

    Detects:
    - eval/exec misuse, command injection, SQL injection
    - Hardcoded secrets, weak crypto, XSS, unsafe deserialization
    - Uses Bandit (Python AST analysis) + regex patterns for all languages

    Args:
        focus: Optional keyword to filter results, e.g. "hardcoded", "injection",
               "eval", "crypto". Leave empty "" to see all findings.

    Returns:
        List of findings with severity, function, file, line and description.
    """
    state = _state()
    if state is None or not state.chunks:
        return "No repository loaded."

    from vulnerability_scanner import scan_chunks, scan_summary  # noqa: PLC0415

    try:
        findings = scan_chunks(state.chunks, repo_path=state.repo)
    except Exception as exc:
        log.error("scan_security error: %s", exc)
        return f"Security scan failed: {exc}"

    if not findings:
        return "✅ No security vulnerabilities detected in the repository."

    if focus.strip():
        kw = focus.lower().strip()
        filtered = [
            f for f in findings
            if kw in (
                f.get("description", "") + " " +
                f.get("function",    "") + " " +
                f.get("cwe_name",    "") + " " +
                f.get("file",        "")
            ).lower()
        ]
        if not filtered:
            summary = scan_summary(findings)
            return (
                f"No '{focus}' issues found specifically. "
                f"However, {len(findings)} other issue(s) exist:\n"
                f"CRITICAL: {summary.get('CRITICAL', 0)}, "
                f"HIGH: {summary.get('HIGH', 0)}, "
                f"MEDIUM: {summary.get('MEDIUM', 0)}, "
                f"LOW: {summary.get('LOW', 0)}\n"
                "Call scan_security with no focus to see all findings."
            )
        findings = filtered

    summary = scan_summary(findings)
    lines = [
        f"Security scan: {len(findings)} finding(s)\n"
        f"CRITICAL: {summary.get('CRITICAL', 0)}, "
        f"HIGH: {summary.get('HIGH', 0)}, "
        f"MEDIUM: {summary.get('MEDIUM', 0)}, "
        f"LOW: {summary.get('LOW', 0)}\n"
    ]
    for f in findings[:15]:
        lines.append(
            f"[{f['severity']}] {f.get('function', '?')}() "
            f"in {f.get('file', '?')} line {f.get('line', '?')}: "
            f"{f.get('description', '')}"
        )
    if len(findings) > 15:
        lines.append(f"\n... and {len(findings) - 15} more finding(s).")
    return "\n".join(lines)


# ── Tool 3: Impact Analysis ───────────────────────────────────────────────────

@mcp.tool()
def impact_analysis(function_name: str) -> str:
    """
    Analyse the blast radius of changing a specific function.
    Finds all callers up to 3 hops deep (multi-hop dependency tree).

    Use for:
    - "What breaks if I change login()?"
    - "How many functions depend on get_db()?"
    - "What is the risk of modifying dispatch_request?"

    Args:
        function_name: Exact function name, e.g. "login", "dispatch_request".

    Returns:
        Dependency tree with callers, risk level (LOW/MEDIUM/HIGH), and
        total count of affected functions.
    """
    state = _state()
    if state is None or not state.chunks:
        return "No repository loaded."

    from parser.dependency_analyzer import get_full_dependency_tree  # noqa: PLC0415

    try:
        tree = get_full_dependency_tree(state.chunks, function_name, max_depth=3)
    except Exception as exc:
        log.error("impact_analysis error: %s", exc)
        return f"Impact analysis failed: {exc}"

    def _count(node: dict, seen: set | None = None) -> int:
        if seen is None:
            seen = set()
        total = 0
        for caller in node.get("callers", []):
            fn = caller.get("function", "")
            if fn and fn not in seen:
                seen.add(fn)
                total += 1 + _count(caller, seen)
        return total

    affected = _count(tree)
    risk = "HIGH" if affected > 10 else ("MEDIUM" if affected > 3 else "LOW")

    def _fmt(node: dict, indent: int = 0) -> list[str]:
        prefix = "  " * indent
        fn   = node.get("function", "?")
        file = node.get("file", "")
        out  = [f"{prefix}← {fn}" + (f" ({file})" if file else "")]
        for caller in node.get("callers", [])[:5]:
            out.extend(_fmt(caller, indent + 1))
        return out

    tree_lines = _fmt(tree)
    result = (
        f"Impact analysis for '{function_name}':\n"
        f"Affected functions: {affected}\n"
        f"Risk level: {risk}\n\n"
        "Dependency tree (← = caller):\n"
        + "\n".join(tree_lines[:30])
    )
    if len(tree_lines) > 30:
        result += f"\n... (truncated, {len(tree_lines) - 30} more lines)"
    return result


# ── Tool 4: Call Graph ────────────────────────────────────────────────────────

@mcp.tool()
def get_call_graph(function_name: str) -> str:
    """
    Show the call graph for a function — who calls it and what it calls.

    Use for:
    - "Who calls authenticate()?"
    - "What does full_dispatch_request() call?"
    - "Show callers of get_db()"

    Args:
        function_name: Function name to centre the graph on.

    Returns:
        List of callers (← direction) and callees (→ direction).
    """
    state = _state()
    if state is None or not state.chunks:
        return "No repository loaded."

    from parser.dependency_analyzer import (  # noqa: PLC0415
        find_function_usage, find_callees,
    )

    try:
        callers = find_function_usage(state.chunks, function_name)
        callees = find_callees(state.chunks, function_name)
    except Exception as exc:
        log.error("get_call_graph error: %s", exc)
        return f"Call graph failed: {exc}"

    lines = [f"Call graph for '{function_name}':\n"]

    if callers:
        lines.append(f"Callers ({len(callers)}) — call {function_name}():")
        for c in callers[:10]:
            lines.append(f"  ← {c['function']}() in {c['file']}")
    else:
        lines.append(
            f"No callers found for {function_name}(). "
            "It may be called via routing/dynamic dispatch or only from external code."
        )

    lines.append("")

    if callees:
        lines.append(f"Callees ({len(callees)}) — called by {function_name}():")
        for c in callees[:10]:
            lines.append(f"  → {c['function']}() in {c['file']}")
    else:
        lines.append(f"{function_name}() has no tracked callees.")

    return "\n".join(lines)


# ── Tool 5: Repository Overview ───────────────────────────────────────────────

@mcp.tool()
def repo_overview(dummy: str = "") -> str:
    """
    Get a high-level overview of the loaded repository.

    Use for:
    - "What's in this repo?"
    - "What languages does this project use?"
    - "How many functions are indexed?"

    Args:
        dummy: Ignored. Pass empty string "".

    Returns:
        Repo path, function count, file count, language breakdown, sample functions.
    """
    state = _state()
    if state is None or not state.chunks:
        return "No repository loaded."

    from collections import Counter  # noqa: PLC0415

    lang_counts: Counter = Counter()
    file_set: set = set()
    ext_map = {
        ".py": "Python", ".java": "Java", ".js": "JavaScript",
        ".cpp": "C++",   ".ts":   "TypeScript",
    }
    for c in state.chunks:
        f = c.get("file", "")
        file_set.add(f)
        for ext, lang in ext_map.items():
            if f.endswith(ext):
                lang_counts[lang] += 1
                break

    sample = [c["name"] for c in state.chunks[:20]]
    return "\n".join([
        f"Repository : {state.repo}",
        f"Functions  : {len(state.chunks)}",
        f"Files      : {len(file_set)}",
        f"Languages  : {dict(lang_counts)}",
        f"Sample fns : {', '.join(sample)}",
    ])
