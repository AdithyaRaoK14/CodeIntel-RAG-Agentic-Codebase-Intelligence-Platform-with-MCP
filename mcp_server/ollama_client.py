"""
mcp_server/ollama_client.py
────────────────────────────
Async MCP client that drives an Ollama model as a ReAct agent using your
MCP server's tools.  No Claude, no OpenAI, no paid API — pure local Ollama.

USAGE (standalone CLI):
    python -m mcp_server.ollama_client "Where is authentication handled?"

USAGE (from code / FastAPI endpoint):
    from mcp_server.ollama_client import run_agent_sync
    result = run_agent_sync("Find SQL injection vulnerabilities")
    print(result["answer"])

RECOMMENDED MODELS (best tool-calling support):
    qwen2.5:7b          ← best tool-calling quality, ~4 GB
    llama3.1:8b         ← solid, ~5 GB
    llama3.2:3b         ← your current model, works but less reliable for
                           multi-step tool use
    mistral:7b          ← good alternative

    To switch:  ollama pull qwen2.5:7b
    Then set:   OLLAMA_MODEL=qwen2.5:7b in your .env

HOW IT WORKS
────────────
1. Connect to MCP server at GET /mcp/sse (runs inside the FastAPI process)
2. List available tools → convert to Ollama tool-call format
3. ReAct loop:
      Ollama decides which tool(s) to call
      → call each via MCP session.call_tool()
      → feed observations back to Ollama
      → repeat until Ollama returns a final text answer (no tool_calls)
4. Return structured result with answer, tools_used, steps
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

import requests
from mcp import ClientSession
from mcp.client.sse import sse_client

log = logging.getLogger(__name__)

# ── Configuration (all overridable via environment variables) ─────────────────
OLLAMA_HOST   = os.getenv("OLLAMA_HOST",   "http://localhost:11434")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL",  "llama3.2:3b")
MCP_SSE_URL   = os.getenv("MCP_SSE_URL",   "http://localhost:8000/mcp/sse")
MAX_ITERS     = int(os.getenv("MCP_MAX_ITERS", "6"))
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

SYSTEM_PROMPT = """You are an expert Codebase Intelligence Agent.
You help developers understand, navigate, and audit software repositories.

You have access to these tools:
- search_codebase    : hybrid BM25 + semantic search for relevant functions
- scan_security      : Bandit + regex vulnerability scanner
- impact_analysis    : multi-hop dependency tree (what breaks if X changes)
- get_call_graph     : callers and callees of a function
- repo_overview      : repo statistics (languages, file count, function count)

RULES:
1. ALWAYS use a tool before answering — never guess about code you haven't searched.
2. For security questions, call scan_security.
3. For dependency or "what calls X" questions, use get_call_graph or impact_analysis.
4. For general "how does X work" questions, use search_codebase.
5. You may call multiple tools in one turn when needed.
6. Keep answers concise (under 200 words) and cite function names and file paths.
7. If no repo is loaded, tell the user to POST to /load or /clone first.
"""


# ── MCP tool → Ollama tool format conversion ──────────────────────────────────

def _to_ollama_tool(mcp_tool) -> dict:
    """Convert an MCP ToolDef to Ollama's tool calling schema."""
    schema: dict = mcp_tool.inputSchema or {}

    # Ensure the schema has the required "type" field
    if "type" not in schema:
        schema = {"type": "object", "properties": schema, "required": []}

    return {
        "type": "function",
        "function": {
            "name":        mcp_tool.name,
            "description": mcp_tool.description or "",
            "parameters":  schema,
        },
    }


# ── Ollama call ───────────────────────────────────────────────────────────────

def _call_ollama(messages: list[dict], tools: list[dict], model: str) -> dict:
    """POST to Ollama /api/chat and return the parsed response dict."""
    payload = {
        "model":    model,
        "messages": messages,
        "stream":   False,
    }
    if tools:
        payload["tools"] = tools

    resp = requests.post(
        f"{OLLAMA_HOST}/api/chat",
        json=payload,
        timeout=OLLAMA_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


# ── Core async agent loop ─────────────────────────────────────────────────────

async def run_mcp_ollama_agent(
    query:       str,
    history:     list[dict] | None = None,
    model:       str = OLLAMA_MODEL,
    max_iters:   int = MAX_ITERS,
    mcp_sse_url: str = MCP_SSE_URL,
) -> dict:
    """
    Drive an Ollama model through a ReAct loop using MCP tools.

    Returns:
    {
        "answer":     str,
        "tools_used": list[str],
        "steps":      list[{"tool": str, "input": str, "observation": str}],
        "error":      str | None
    }
    """
    history = history or []
    tools_used: list[str] = []
    steps:      list[dict] = []

    async with sse_client(mcp_sse_url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # ── Fetch tool definitions from MCP ──────────────────────────────
            mcp_tools_response = await session.list_tools()
            ollama_tools = [_to_ollama_tool(t) for t in mcp_tools_response.tools]
            log.info(
                "MCP server exposes %d tools: %s",
                len(ollama_tools),
                [t["function"]["name"] for t in ollama_tools],
            )

            # ── Build initial message list ────────────────────────────────────
            messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]

            for h in history[-6:]:
                role    = h.get("role", "")
                content = h.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})

            messages.append({"role": "user", "content": query})

            # ── ReAct loop ────────────────────────────────────────────────────
            for iteration in range(max_iters):
                log.debug("ReAct iteration %d/%d", iteration + 1, max_iters)

                try:
                    data = _call_ollama(messages, ollama_tools, model)
                except requests.RequestException as exc:
                    err = f"Ollama connection error: {exc}"
                    log.error(err)
                    return {
                        "answer":     err,
                        "tools_used": tools_used,
                        "steps":      steps,
                        "error":      str(exc),
                    }

                msg         = data.get("message", {})
                tool_calls  = msg.get("tool_calls", [])
                content     = msg.get("content", "").strip()

                if not tool_calls:
                    # Ollama gave a plain-text final answer — we're done
                    return {
                        "answer":     content or "No answer generated.",
                        "tools_used": list(dict.fromkeys(tools_used)),
                        "steps":      steps,
                        "error":      None,
                    }

                # ── Append assistant message (with tool_calls) ────────────────
                assistant_msg: dict[str, Any] = {
                    "role":       "assistant",
                    "content":    content,
                    "tool_calls": tool_calls,
                }
                messages.append(assistant_msg)

                # ── Execute each tool via MCP ─────────────────────────────────
                for tc in tool_calls:
                    fn         = tc.get("function", {})
                    tool_name  = fn.get("name", "")
                    tool_args  = fn.get("arguments", {})

                    # Ollama sometimes returns args as a JSON string
                    if isinstance(tool_args, str):
                        try:
                            tool_args = json.loads(tool_args)
                        except json.JSONDecodeError:
                            tool_args = {}

                    tools_used.append(tool_name)
                    log.info("Calling MCP tool: %s(%s)", tool_name, tool_args)

                    try:
                        mcp_result  = await session.call_tool(tool_name, tool_args)
                        observation = "\n".join(
                            block.text
                            for block in (mcp_result.content or [])
                            if hasattr(block, "text")
                        ) or "Tool returned no content."
                    except Exception as exc:
                        observation = f"Tool execution error: {exc}"
                        log.error("MCP tool %s failed: %s", tool_name, exc)

                    steps.append({
                        "tool":        tool_name,
                        "input":       str(tool_args),
                        "observation": observation[:500],
                    })

                    # Feed the tool result back to Ollama
                    messages.append({
                        "role":    "tool",
                        "content": observation,
                    })

            # Exceeded max_iters
            return {
                "answer": (
                    "Agent reached the maximum number of tool-call iterations "
                    "without producing a final answer. Try rephrasing your query "
                    "or increasing MCP_MAX_ITERS."
                ),
                "tools_used": list(dict.fromkeys(tools_used)),
                "steps":      steps,
                "error":      "max_iterations_reached",
            }


# ── Sync wrappers for FastAPI / threading ─────────────────────────────────────

def run_agent_sync(
    query:   str,
    history: list[dict] | None = None,
    model:   str = OLLAMA_MODEL,
) -> dict:
    """Blocking wrapper — safe to call from FastAPI route via asyncio.to_thread."""
    return asyncio.run(run_mcp_ollama_agent(query, history, model))


async def stream_mcp_agent(
    query:       str,
    history:     list[dict] | None = None,
    model:       str = OLLAMA_MODEL,
    mcp_sse_url: str = MCP_SSE_URL,
):
    """
    Async generator — yields SSE strings.

    data: {"tool": "search_codebase", "input": "..."}\n\n
    data: {"observation": "..."}\n\n
    data: {"token": "hello "}\n\n
    data: [DONE]\n\n
    """
    import json as _json

    history = history or []

    async with sse_client(mcp_sse_url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            mcp_tools_response = await session.list_tools()
            ollama_tools = [_to_ollama_tool(t) for t in mcp_tools_response.tools]

            messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
            for h in history[-6:]:
                role    = h.get("role", "")
                content = h.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})
            messages.append({"role": "user", "content": query})

            for _ in range(MAX_ITERS):
                try:
                    data = _call_ollama(messages, ollama_tools, model)
                except Exception as exc:
                    yield f"data: {_json.dumps({'error': str(exc)})}\n\n"
                    break

                msg        = data.get("message", {})
                tool_calls = msg.get("tool_calls", [])
                content    = msg.get("content", "").strip()

                if not tool_calls:
                    for word in content.split(" "):
                        yield f"data: {_json.dumps({'token': word + ' '})}\n\n"
                    break

                messages.append({
                    "role": "assistant", "content": content,
                    "tool_calls": tool_calls,
                })

                for tc in tool_calls:
                    fn        = tc.get("function", {})
                    tool_name = fn.get("name", "")
                    tool_args = fn.get("arguments", {})
                    if isinstance(tool_args, str):
                        try:
                            tool_args = _json.loads(tool_args)
                        except Exception:
                            tool_args = {}

                    yield f"data: {_json.dumps({'tool': tool_name, 'input': str(tool_args)})}\n\n"

                    try:
                        mcp_result  = await session.call_tool(tool_name, tool_args)
                        observation = "\n".join(
                            b.text for b in (mcp_result.content or [])
                            if hasattr(b, "text")
                        ) or "No content."
                    except Exception as exc:
                        observation = f"Tool error: {exc}"

                    yield f"data: {_json.dumps({'observation': observation[:300]})}\n\n"
                    messages.append({"role": "tool", "content": observation})

    yield "data: [DONE]\n\n"


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "What's in this repo?"
    print(f"\nQuery: {query}")
    print(f"Model: {OLLAMA_MODEL}  |  MCP: {MCP_SSE_URL}\n")

    result = asyncio.run(run_mcp_ollama_agent(query))

    if result["tools_used"]:
        print(f"Tools used: {', '.join(result['tools_used'])}")
        for step in result["steps"]:
            print(f"\n  [{step['tool']}]")
            print(f"  Input: {step['input']}")
            print(f"  Obs:   {step['observation'][:200]}")

    print(f"\n{'─'*60}")
    print(result["answer"])
    if result.get("error"):
        print(f"\nError: {result['error']}")
