"""
agent/tools.py
──────────────
LangChain tools that wrap the existing platform services.

Design: tools are created via make_tools(state) so they close over the
live AppState (chunks + bm25_index) without needing globals.
Call make_tools() once per /agent-chat request — it's cheap (no model loading).
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from langchain.tools import tool

if TYPE_CHECKING:
    pass  # AppState imported at call time to avoid circular imports

log = logging.getLogger(__name__)


def make_tools(state) -> list:
    """
    Build the tool list bound to the current AppState.
    Called per-request so tools always see the latest indexed repo.
    """

    # ── Tool 1: Code Search ───────────────────────────────────────────────────

    @tool
    def search_codebase(query: str) -> str:
        """
        Search the indexed codebase using hybrid retrieval (BM25 + semantic
        embeddings + cross-encoder reranking).

        Use this tool for questions like:
        - "Where is authentication handled?"
        - "What does login() call?"
        - "Find the request dispatching logic"
        - "How does error handling work?"

        Input:  a natural language query about the codebase.
        Output: top matching functions with file, line, and a code snippet.
        """
        if not state.chunks:
            return "No repository is loaded yet. Ask the user to load one first."

        from retrieval.hybrid_retriever import hybrid_search
        from retrieval.reranker import rerank
        from config import settings

        try:
            candidates = hybrid_search(query, state.chunks, state.bm25_index)
            results = rerank(query, candidates[:settings.rerank_candidates])
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
                f"   Code snippet:\n"
                f"   {r.get('code', '')[:300].strip()}\n"
            )

        return "\n".join(lines)

    # ── Tool 2: Security Scan ─────────────────────────────────────────────────

    @tool
    def scan_security(focus: str = "") -> str:
        """
        Run a security vulnerability scan on the loaded repository.
        Uses Bandit (Python) + regex patterns for all languages.
        Detects: eval/exec misuse, hardcoded secrets, weak crypto,
        command injection, SQL injection, XSS, unsafe deserialization.

        Input:  optional focus keyword to filter results
                (e.g. "hardcoded", "injection", "eval", or "" for all issues).
        Output: list of findings with severity, function, file, and description.
        """
        if not state.chunks:
            return "No repository is loaded yet."

        from vulnerability_scanner import scan_chunks, scan_summary

        try:
            findings = scan_chunks(state.chunks, repo_path=state.repo)
        except Exception as exc:
            log.error("scan_security error: %s", exc)
            return f"Security scan failed: {exc}"

        if not findings:
            return "✅ No security vulnerabilities detected in the repository."

        # Optional focus filter — search across description, function,
        # cwe_name and file so it works regardless of scanner phrasing.
        if focus.strip():
            kw = focus.lower().strip()
            filtered = [
                f for f in findings
                if kw in (
                    f.get("description", "") + " " +
                    f.get("function",    "") + " " +
                    # ← was "category" (always empty)
                    f.get("cwe_name",    "") + " " +
                    f.get("file",        "")
                ).lower()
            ]
            if not filtered:
                # Don't just say "not found" — show what WAS found so the
                # agent can use that information to give a useful answer.
                summary = scan_summary(findings)
                return (
                    f"No '{focus}' issues found specifically. "
                    f"However, {len(findings)} other issue(s) exist in this repo:\n"
                    f"CRITICAL: {summary.get('CRITICAL', 0)}, "
                    f"HIGH: {summary.get('HIGH', 0)}, "
                    f"MEDIUM: {summary.get('MEDIUM', 0)}, "
                    f"LOW: {summary.get('LOW', 0)}\n"
                    f"Call scan_security with no focus to see all findings."
                )
            findings = filtered

        summary = scan_summary(findings)
        lines = [
            f"Security scan: {len(findings)} finding(s)\n"
            f"Summary — CRITICAL: {summary.get('CRITICAL', 0)}, "
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

    # ── Tool 3: Impact / Dependency Analysis ──────────────────────────────────

    @tool
    def impact_analysis(function_name: str) -> str:
        """
        Analyse the impact of changing a specific function.
        Finds all callers up to 3 hops deep (multi-hop dependency tree).
        Useful for: "what breaks if I change login()?",
                    "how many functions depend on get_db()?"

        Input:  exact function name (e.g. "login", "dispatch_request").
        Output: dependency tree showing callers and their callers, plus risk level.
        """
        if not state.chunks:
            return "No repository is loaded yet."

        from parser.dependency_analyzer import get_full_dependency_tree

        try:
            tree = get_full_dependency_tree(
                state.chunks, function_name, max_depth=3)
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
        risk = "HIGH" if affected > 10 else (
            "MEDIUM" if affected > 3 else "LOW")

        def _format_tree(node: dict, indent: int = 0) -> list[str]:
            prefix = "  " * indent
            fn = node.get("function", "?")
            file = node.get("file", "")
            file_part = f" ({file})" if file else ""
            lines = [f"{prefix}← {fn}{file_part}"]
            for caller in node.get("callers", [])[:5]:
                lines.extend(_format_tree(caller, indent + 1))
            return lines

        tree_lines = _format_tree(tree)
        result = (
            f"Impact analysis for '{function_name}':\n"
            f"Affected functions: {affected}\n"
            f"Risk level: {risk}\n\n"
            f"Dependency tree (arrows show callers):\n"
            + "\n".join(tree_lines[:30])
        )

        if len(tree_lines) > 30:
            result += f"\n... (tree truncated, {len(tree_lines) - 30} more lines)"

        return result

    # ── Tool 4: Call Graph ────────────────────────────────────────────────────

    @tool
    def get_call_graph(function_name: str) -> str:
        """
        Get the call graph for a function — who calls it and what it calls.
        Useful for: "show callers of authenticate()",
                    "what does full_dispatch_request() call?"

        Input:  function name to center the graph on.
        Output: list of callers (functions that call it) and
                callees (functions it calls).
        """
        if not state.chunks:
            return "No repository is loaded yet."

        from parser.dependency_analyzer import find_function_usage, find_callees

        try:
            callers = find_function_usage(state.chunks, function_name)
            callees = find_callees(state.chunks, function_name)
        except Exception as exc:
            log.error("get_call_graph error: %s", exc)
            return f"Call graph failed: {exc}"

        lines = [f"Call graph for '{function_name}':\n"]

        if callers:
            lines.append(
                f"Callers ({len(callers)}) — functions that call {function_name}():")
            for c in callers[:10]:
                lines.append(f"  ← {c['function']}() in {c['file']}")
        else:
            lines.append(
                f"No callers found for {function_name}() in the indexed repo. "
                f"It may be called dynamically (e.g. via Flask routing) or "
                f"only from external code not in this repo."
            )

        lines.append("")

        if callees:
            lines.append(
                f"Callees ({len(callees)}) — functions that {function_name}() calls:")
            for c in callees[:10]:
                lines.append(f"  → {c['function']}() in {c['file']}")
        else:
            lines.append(f"{function_name}() has no tracked callees.")

        return "\n".join(lines)

    # ── Tool 5: Repository Overview ───────────────────────────────────────────

    @tool
    def repo_overview(dummy: str = "") -> str:
        """
        Get a high-level overview of the loaded repository.
        Shows: total functions, files, languages, and top function names.
        Use this when the user asks "what's in this repo?" or
        "what languages does this project use?"

        Input:  ignored (pass empty string "").
        Output: repo statistics and a sample of indexed functions.
        """
        if not state.chunks:
            return "No repository is loaded yet."

        from collections import Counter

        lang_counts: Counter = Counter()
        file_set = set()
        for c in state.chunks:
            f = c.get("file", "")
            file_set.add(f)
            if f.endswith(".py"):
                lang_counts["Python"] += 1
            elif f.endswith(".java"):
                lang_counts["Java"] += 1
            elif f.endswith(".js"):
                lang_counts["JavaScript"] += 1
            elif f.endswith(".cpp"):
                lang_counts["C++"] += 1
            elif f.endswith(".ts"):
                lang_counts["TypeScript"] += 1

        sample_fns = [c["name"] for c in state.chunks[:20]]

        lines = [
            f"Repository: {state.repo}",
            f"Functions indexed: {len(state.chunks)}",
            f"Files: {len(file_set)}",
            f"Languages: {dict(lang_counts)}",
            f"\nSample functions: {', '.join(sample_fns)}",
        ]

        return "\n".join(lines)

    return [
        search_codebase,
        scan_security,
        impact_analysis,
        get_call_graph,
        repo_overview,
    ]
