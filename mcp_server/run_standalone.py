"""
mcp_server/run_standalone.py
─────────────────────────────
Run the MCP server as a STANDALONE process (separate from FastAPI).
Use this when you want to connect external MCP clients (Cursor, Continue.dev,
Open WebUI) WITHOUT starting the full FastAPI stack.

In standalone mode, MCP tools make HTTP calls to the running FastAPI API
(default: http://localhost:8000) instead of accessing AppState directly.

USAGE:
    # 1. Start FastAPI first (your main app)
    uvicorn api:app --reload

    # 2. In a SECOND terminal, start the standalone MCP server
    python -m mcp_server.run_standalone

    # MCP SSE endpoint: http://localhost:8001/sse
    # Configure this URL in Cursor / Continue.dev / Open WebUI

ENVIRONMENT VARIABLES:
    MCP_STANDALONE_PORT   port for this server (default: 8001)
    CODEINTEL_API_URL     FastAPI base URL    (default: http://localhost:8000)
    OLLAMA_HOST           Ollama URL          (default: http://localhost:11434)
    OLLAMA_MODEL          model name          (default: llama3.2:3b)
"""

from __future__ import annotations

import json
import logging
import os

import requests as _req
from mcp.server.fastmcp import FastMCP

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

_PORT = int(os.getenv("MCP_STANDALONE_PORT", "8001"))
_API = os.getenv("CODEINTEL_API_URL", "http://localhost:8000")

# ── Create a SEPARATE FastMCP instance for standalone mode ────────────────────
# (different from mcp_server/server.py which uses direct state access)

mcp_standalone = FastMCP(
    name="codebase-intelligence-standalone",
    instructions=(
        "Codebase Intelligence tools connected to a running CodeIntel API. "
        "The API must be running at "
        + _API
    ),
)


def _api_get(path: str) -> dict:
    r = _req.get(f"{_API}{path}", timeout=30)
    r.raise_for_status()
    return r.json()


def _api_post(path: str, body: dict) -> dict:
    r = _req.post(f"{_API}{path}", json=body, timeout=60)
    r.raise_for_status()
    return r.json()


@mcp_standalone.tool()
def search_codebase(query: str) -> str:
    """Search the indexed codebase via the CodeIntel API."""
    try:
        data = _api_post("/chat", {"query": query, "history": []})
        results = data.get("results", [])
        if not results:
            return "No results found."
        lines = [f"Found {len(results)} function(s):\n"]
        for i, r in enumerate(results[:5], 1):
            calls = r.get("calls", [])
            if isinstance(calls, str):
                try:
                    calls = json.loads(calls)
                except Exception:
                    calls = []
            lines.append(
                f"{i}. {r['name']}() in {r['file']} line {r.get('line', '?')}\n"
                f"   Calls: {', '.join(calls[:5]) or 'none'}\n"
                f"   Code: {r.get('code', '')[:200].strip()}\n"
            )
        return "\n".join(lines)
    except Exception as exc:
        return f"Search failed: {exc}. Is the API running at {_API}?"


@mcp_standalone.tool()
def scan_security(focus: str = "") -> str:
    """Run security scan via the CodeIntel API."""
    try:
        data = _api_get("/vulnerabilities")
        findings = data.get("findings", [])
        summary = data.get("summary", {})

        if not findings:
            return "✅ No vulnerabilities detected."

        if focus.strip():
            kw = focus.lower()
            findings = [
                f for f in findings
                if kw in (
                    f.get("description", "") + f.get("function", "") +
                    f.get("file", "")
                ).lower()
            ]
            if not findings:
                return f"No '{focus}' issues found. Total: {data.get('total', 0)} issues."

        lines = [
            f"Security scan: {len(findings)} finding(s)\n"
            f"CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, "
            f"MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)}\n"
        ]
        for f in findings[:15]:
            lines.append(
                f"[{f['severity']}] {f.get('function', '?')}() "
                f"in {f.get('file', '?')} line {f.get('line', '?')}: "
                f"{f.get('description', '')}"
            )
        return "\n".join(lines)
    except Exception as exc:
        return f"Scan failed: {exc}. Is the API running at {_API}?"


@mcp_standalone.tool()
def impact_analysis(function_name: str) -> str:
    """Analyse impact of changing a function via the CodeIntel API."""
    try:
        data = _api_post("/impact", {"function_name": function_name})
        tree = data.get("tree", {})
        affected = data.get("affected_count", 0)
        risk = "HIGH" if affected > 10 else (
            "MEDIUM" if affected > 3 else "LOW")
        return (
            f"Impact analysis for '{function_name}':\n"
            f"Affected functions: {affected}\n"
            f"Risk: {risk}\n"
            f"Tree: {json.dumps(tree, indent=2)[:1000]}"
        )
    except Exception as exc:
        return f"Impact analysis failed: {exc}. Is the API running at {_API}?"


@mcp_standalone.tool()
def get_call_graph(function_name: str) -> str:
    """Get call graph for a function via the CodeIntel API."""
    try:
        # Use the agent endpoint to get call graph info via search
        data = _api_post("/chat", {
            "query": f"What calls {function_name}? What does {function_name} call?",
            "history": [],
        })
        return data.get("answer", "No call graph info found.")
    except Exception as exc:
        return f"Call graph failed: {exc}. Is the API running at {_API}?"


@mcp_standalone.tool()
def repo_overview(dummy: str = "") -> str:
    """Get repository overview via the CodeIntel API."""
    try:
        data = _api_get("/health")
        return (
            f"Repository: {data.get('repo', 'unknown')}\n"
            f"Functions:  {data.get('functions', 0)}\n"
            f"Files:      {data.get('files', 0)}\n"
            f"LLM online: {data.get('llm', False)}\n"
        )
    except Exception as exc:
        return f"Overview failed: {exc}. Is the API running at {_API}?"


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Starting standalone MCP server on port %d", _PORT)
    log.info("Connecting to CodeIntel API at %s", _API)
    log.info("")
    log.info("SSE endpoint: http://localhost:%d/sse", _PORT)
    log.info("")
    log.info("Add this URL to your MCP client:")
    log.info("  Cursor    → Settings → MCP → Add → http://localhost:%d/sse", _PORT)
    log.info(
        "  Continue  → config.json → mcpServers → url: http://localhost:%d/sse", _PORT)
    log.info("")
    os.environ["PORT"] = "8001"
    mcp_standalone.run(transport="sse")
