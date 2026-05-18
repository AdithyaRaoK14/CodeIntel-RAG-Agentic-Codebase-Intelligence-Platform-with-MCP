"""
mcp_server/mcp_router.py
─────────────────────────
FastAPI router that adds /mcp-chat and /mcp-chat/stream endpoints.
These are identical in contract to /agent-chat and /agent-chat/stream but
use the MCP protocol internally — so any MCP-compatible client benefits
from the same logic.

Add to api.py (two lines):
    from mcp_server.mcp_router import mcp_chat_router
    app.include_router(mcp_chat_router)
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

log = logging.getLogger(__name__)

mcp_chat_router = APIRouter(tags=["MCP-Chat"])


class McpChatRequest(BaseModel):
    query:   str
    history: list[dict] = []
    model:   str = ""          # override OLLAMA_MODEL for this request


@mcp_chat_router.post("/mcp-chat")
async def mcp_chat(req: McpChatRequest):
    """
    Agentic chat endpoint powered by MCP + local Ollama.

    Identical response schema to /agent-chat:
    {
        "answer":     str,
        "tools_used": [str],
        "steps":      [{"tool": str, "input": str, "observation": str}],
        "error":      str | null
    }

    The agent calls your MCP server (mounted at /mcp/sse in the same process),
    which drives tool execution against the loaded repository.
    """
    from api import get_state                           # noqa: PLC0415
    from mcp_server.ollama_client import (              # noqa: PLC0415
        run_mcp_ollama_agent, OLLAMA_MODEL, MCP_SSE_URL,
    )

    state = get_state()
    if not state.chunks:
        raise HTTPException(400, "No repository loaded. POST /load or /clone first.")

    query = req.query.strip()
    if not query:
        raise HTTPException(400, "Query cannot be empty.")

    model = req.model.strip() or OLLAMA_MODEL
    log.info("MCP-chat [%s]: %s", model, query[:80])

    result = await asyncio.to_thread(
        asyncio.run,
        run_mcp_ollama_agent(
            query=query,
            history=req.history,
            model=model,
            mcp_sse_url=MCP_SSE_URL,
        ),
    )
    return result


@mcp_chat_router.post("/mcp-chat/stream")
async def mcp_chat_stream(req: McpChatRequest):
    """
    Streaming version of /mcp-chat.

    SSE events:
        data: {"tool": "search_codebase", "input": "..."}\n\n
        data: {"observation": "..."}\n\n
        data: {"token": "hello "}\n\n
        data: [DONE]\n\n
    """
    from api import get_state                           # noqa: PLC0415
    from mcp_server.ollama_client import (              # noqa: PLC0415
        stream_mcp_agent, OLLAMA_MODEL, MCP_SSE_URL,
    )

    state = get_state()
    if not state.chunks:
        raise HTTPException(400, "No repository loaded.")

    query = req.query.strip()
    if not query:
        raise HTTPException(400, "Query cannot be empty.")

    model = req.model.strip() or OLLAMA_MODEL
    log.info("MCP-stream [%s]: %s", model, query[:80])

    return StreamingResponse(
        stream_mcp_agent(
            query=query,
            history=req.history,
            model=model,
            mcp_sse_url=MCP_SSE_URL,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@mcp_chat_router.get("/mcp-chat/info")
def mcp_chat_info():
    """Describe the MCP-chat setup — useful for debugging."""
    from mcp_server.ollama_client import OLLAMA_HOST, OLLAMA_MODEL, MCP_SSE_URL  # noqa: PLC0415
    import requests as _req  # noqa: PLC0415

    ollama_ok = False
    try:
        ollama_ok = _req.get(OLLAMA_HOST, timeout=2).status_code == 200
    except Exception:
        pass

    return {
        "mcp_sse_url":   MCP_SSE_URL,
        "ollama_host":   OLLAMA_HOST,
        "ollama_model":  OLLAMA_MODEL,
        "ollama_online": ollama_ok,
        "endpoints": {
            "/mcp/sse":          "MCP SSE stream (for external clients)",
            "/mcp/messages":     "MCP message endpoint",
            "/mcp-chat":         "POST — Ollama+MCP agent (non-streaming)",
            "/mcp-chat/stream":  "POST — Ollama+MCP agent (streaming SSE)",
            "/mcp-chat/info":    "GET  — this page",
        },
    }
