"""
agent_router.py
────────────────
FastAPI router that adds /agent-chat and /agent-chat/stream endpoints.

HOW TO ADD TO api.py (one line at the end of the imports section):
    from agent_router import agent_router
    app.include_router(agent_router)

Your existing /chat and all other endpoints are completely untouched.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

log = logging.getLogger(__name__)

agent_router = APIRouter(tags=["Agent"])


# ── Request schema ────────────────────────────────────────────────────────────

class AgentChatRequest(BaseModel):
    query:   str
    history: list[dict] = []   # [{role: "user"|"assistant", content: "..."}]


# ── Import helpers from api.py (already loaded in same process) ───────────────
# We import get_state and verify_api_key at route-time to avoid circular
# imports — both are defined in api.py which imports agent_router.

def _get_state_dep():
    from api import get_state
    return Depends(get_state)


def _auth_dep():
    from api import verify_api_key
    return Depends(verify_api_key)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@agent_router.post("/agent-chat")
async def agent_chat(req: AgentChatRequest):
    """
    Agentic code Q&A endpoint.

    The agent reasons over your query, picks tools (search, scan, impact, graph),
    runs them against the loaded repo, and returns a synthesised answer.

    Multi-tool example:
        "Find authentication vulnerabilities and show who calls login()"
        → agent calls scan_security("auth") + get_call_graph("login")
        → returns a combined answer.

    Response schema:
    {
        "answer":     str,        # LLM-generated answer
        "tools_used": [str],      # tools the agent called
        "steps": [                # transparency: what the agent did
            {"tool": str, "input": str, "observation": str}
        ],
        "error": str | null
    }
    """
    import asyncio
    from api import get_state, verify_api_key
    from agent.agent_runner import run_agent

    # Get shared state
    state = get_state()

    if not state.chunks:
        raise HTTPException(
            400,
            detail="No repository loaded. POST to /load or /clone first."
        )

    query = req.query.strip()
    if not query:
        raise HTTPException(400, detail="Query cannot be empty.")

    log.info("Agent query: %s", query[:80])

    result = await asyncio.to_thread(run_agent, query, state, req.history)
    return result


@agent_router.post("/agent-chat/stream")
async def agent_chat_stream(req: AgentChatRequest):
    """
    Streaming version of /agent-chat.

    Returns a text/event-stream. Events:
        data: {"tool": "search_codebase", "input": "..."}\n\n   ← tool started
        data: {"observation": "..."}\n\n                         ← tool result
        data: {"token": "hello "}\n\n                           ← answer tokens
        data: [DONE]\n\n                                         ← finished
    """
    from api import get_state
    from agent.agent_runner import stream_agent

    state = get_state()

    if not state.chunks:
        raise HTTPException(400, detail="No repository loaded.")

    query = req.query.strip()
    if not query:
        raise HTTPException(400, detail="Query cannot be empty.")

    log.info("Agent stream query: %s", query[:80])

    return StreamingResponse(
        stream_agent(query, state, req.history),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@agent_router.get("/agent/tools")
def list_agent_tools():
    """
    List all tools available to the agent.
    Useful for debugging and frontend display.
    """
    return {
        "tools": [
            {
                "name":        "search_codebase",
                "description": "Hybrid search (BM25 + semantic) for relevant functions",
                "use_for":     "General code questions, 'how does X work', 'find Y function'",
            },
            {
                "name":        "scan_security",
                "description": "Bandit + regex vulnerability scanner",
                "use_for":     "Security questions, 'find vulnerabilities', 'unsafe code'",
            },
            {
                "name":        "impact_analysis",
                "description": "Multi-hop dependency tree (who calls what)",
                "use_for":     "'What breaks if I change X?', 'dependencies of Y'",
            },
            {
                "name":        "get_call_graph",
                "description": "Direct callers and callees of a function",
                "use_for":     "'Who calls login()?', 'what does dispatch_request() call?'",
            },
            {
                "name":        "repo_overview",
                "description": "Repository statistics (languages, file count, function count)",
                "use_for":     "'What's in this repo?', 'what languages does this use?'",
            },
        ]
    }
