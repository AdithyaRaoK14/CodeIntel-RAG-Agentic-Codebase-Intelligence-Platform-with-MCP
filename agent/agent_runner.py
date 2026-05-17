"""
agent/agent_runner.py
──────────────────────
Fixed for langchain>=1.3 / langgraph>=1.2.

Key change: create_react_agent now lives in langgraph.prebuilt (not langchain.agents).
The old ChatPromptTemplate-based ReAct loop is replaced by langgraph's built-in agent.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Generator

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent

from agent.prompts import AGENT_SYSTEM_PROMPT
from agent.tools import make_tools

log = logging.getLogger(__name__)

_OLLAMA_HOST = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")


def _get_llm() -> ChatOllama:
    return ChatOllama(
        model=_OLLAMA_MODEL,
        base_url=_OLLAMA_HOST,
        temperature=0.1,
        num_predict=1024,
    )


def _build_messages(query: str, history: list[dict]) -> list:
    """
    Build the message list for the agent.
    Includes both user AND assistant turns from history so the agent
    has full conversational context across multi-turn sessions.
    """
    msgs = [SystemMessage(content=AGENT_SYSTEM_PROMPT)]

    for h in history[-6:]:
        role = h.get("role", "")
        content = h.get("content", "")
        if not content:
            continue
        if role == "user":
            msgs.append(HumanMessage(content=content))
        elif role == "assistant":
            # Include previous assistant replies so the agent doesn't
            # repeat itself or lose track of what it already answered.
            msgs.append(AIMessage(content=content))

    msgs.append(HumanMessage(content=query))
    return msgs


# ── Public API ────────────────────────────────────────────────────────────────

def run_agent(query: str, state, history: list[dict] | None = None) -> dict:
    """
    Run the agent synchronously. Returns:
    {
        "answer":     str,
        "tools_used": list[str],
        "steps":      list[dict],
        "error":      str | None
    }
    """
    tools = make_tools(state)
    llm = _get_llm()

    agent = create_react_agent(
        model=llm, tools=tools, prompt=AGENT_SYSTEM_PROMPT)

    try:
        result = agent.invoke(
            {"messages": _build_messages(query, history or [])})
    except Exception as exc:
        log.error("Agent execution error: %s", exc, exc_info=True)
        return {
            "answer":     f"Agent error: {exc}",
            "tools_used": [],
            "steps":      [],
            "error":      str(exc),
        }

    messages = result.get("messages", [])
    steps = []
    tools_used = []

    for msg in messages:
        mtype = type(msg).__name__
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for tc in msg.tool_calls:
                tools_used.append(tc["name"])
                steps.append({
                    "tool":        tc["name"],
                    "input":       str(tc.get("args", "")),
                    "observation": "",
                })
        if mtype == "ToolMessage":
            obs = str(msg.content)[:500]
            tool_name = getattr(msg, "name", "")
            for step in reversed(steps):
                if step["tool"] == tool_name and not step["observation"]:
                    step["observation"] = obs
                    break

    # Final answer = last non-empty AIMessage without tool_calls
    answer = ""
    for msg in reversed(messages):
        if (
            type(msg).__name__ == "AIMessage"
            and msg.content
            and not getattr(msg, "tool_calls", None)
        ):
            answer = str(msg.content)
            break

    if not answer:
        answer = "The agent did not produce a final answer. Try rephrasing your query."

    return {
        "answer":     answer,
        "tools_used": list(dict.fromkeys(tools_used)),
        "steps":      steps,
        "error":      None,
    }


def stream_agent(
    query: str, state, history: list[dict] | None = None
) -> Generator[str, None, None]:
    """Stream agent events as SSE strings."""
    tools = make_tools(state)
    llm = _get_llm()

    agent = create_react_agent(
        model=llm, tools=tools, prompt=AGENT_SYSTEM_PROMPT)

    try:
        for chunk in agent.stream(
            {"messages": _build_messages(query, history or [])},
            stream_mode="updates",
        ):
            for _, node_data in chunk.items():
                for msg in node_data.get("messages", []):
                    mtype = type(msg).__name__
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        for tc in msg.tool_calls:
                            yield f"data: {json.dumps({'tool': tc['name'], 'input': str(tc.get('args', ''))})}\n\n"
                    if mtype == "ToolMessage":
                        yield f"data: {json.dumps({'observation': str(msg.content)[:300]})}\n\n"
                    if mtype == "AIMessage" and msg.content and not getattr(msg, "tool_calls", None):
                        for word in str(msg.content).split(" "):
                            yield f"data: {json.dumps({'token': word + ' '})}\n\n"
    except Exception as exc:
        log.error("Agent stream error: %s", exc, exc_info=True)
        yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    yield "data: [DONE]\n\n"
