"""Turn Claude Code session transcripts (``~/.claude/projects/**/*.jsonl``) into a tool-call corpus.

Each assistant line carries ``message.content[]`` blocks; ``tool_use`` blocks are the
calls a PreToolUse hook would have seen. The matching ``tool_result`` (in a later user
line) tells us whether a hook blocked it at the time: Claude Code writes
``PreToolUse:<Tool> hook error: [<command>]: <stderr>`` for an exit-2 block.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from .model import ToolCall

DEFAULT_ROOT = Path.home() / ".claude" / "projects"
_BLOCK_MARKERS = (
    re.compile(r"^PreToolUse:\S+ hook (?:blocking )?error"),
    re.compile(r"hook PreToolUse:\S+ denied", re.I),
    re.compile(r"blocked by (?:a )?PreToolUse hook", re.I),
)


@dataclass(frozen=True)
class CorpusFilter:
    project: str | None = None  # substring of the project directory name
    tools: frozenset[str] | None = None
    since: datetime | None = None
    include_sidechains: bool = True


def find_transcripts(root: Path = DEFAULT_ROOT, project: str | None = None) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    files = sorted(root.rglob("*.jsonl"))
    if project:
        files = [f for f in files if project in str(f.relative_to(root))]
    return files


def _result_text(block: dict[str, Any]) -> str:
    content = block.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [c.get("text", "") for c in content if isinstance(c, dict)]
        return "\n".join(p for p in parts if isinstance(p, str))
    return ""


def is_hook_block(text: str) -> bool:
    return any(p.search(text) for p in _BLOCK_MARKERS)


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def calls_from_file(path: Path, flt: CorpusFilter = CorpusFilter()) -> Iterator[ToolCall]:
    """Yield every tool call in one transcript, annotated with its historical hook outcome."""
    pending: dict[str, ToolCall] = {}
    order: list[str] = []
    blocked: set[str] = set()
    try:
        handle = path.open(encoding="utf-8", errors="replace")
    except OSError:
        return
    with handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            message = entry.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, list):
                continue
            kind = entry.get("type")
            if kind == "assistant":
                if entry.get("isSidechain") and not flt.include_sidechains:
                    continue
                if flt.since is not None:
                    ts = _parse_ts(entry.get("timestamp"))
                    if ts is not None and ts.tzinfo is not None and flt.since.tzinfo is None:
                        ts = ts.replace(tzinfo=None)
                    if ts is not None and ts < flt.since:
                        continue
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_use":
                        continue
                    name = block.get("name")
                    tool_input = block.get("input")
                    if not isinstance(name, str) or not isinstance(tool_input, dict):
                        continue
                    if flt.tools is not None and name not in flt.tools:
                        continue
                    tid = str(block.get("id") or f"{path.name}:{lineno}")
                    pending[tid] = ToolCall(
                        tool_name=name,
                        tool_input=tool_input,
                        cwd=entry.get("cwd") if isinstance(entry.get("cwd"), str) else None,
                        session_id=entry.get("sessionId") if isinstance(entry.get("sessionId"), str) else None,
                        tool_use_id=tid,
                        source=f"{path}:{lineno}",
                    )
                    order.append(tid)
            elif kind == "user":
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("is_error"):
                        if is_hook_block(_result_text(block)):
                            blocked.add(str(block.get("tool_use_id")))
    for tid in order:
        call = pending[tid]
        yield replace(call, historical="blocked") if tid in blocked else call


def load_corpus(
    paths: Iterable[Path],
    flt: CorpusFilter = CorpusFilter(),
    *,
    dedupe: bool = True,
    limit: int | None = None,
) -> list[ToolCall]:
    """All calls from ``paths``; identical calls are merged and counted in ``occurrences``."""
    if not dedupe:
        out = [c for p in paths for c in calls_from_file(p, flt)]
        return out[:limit] if limit else out
    merged: dict[str, ToolCall] = {}
    for p in paths:
        for c in calls_from_file(p, flt):
            k = c.key()
            prev = merged.get(k)
            if prev is None:
                merged[k] = c
            else:
                merged[k] = replace(
                    prev,
                    occurrences=prev.occurrences + 1,
                    historical=prev.historical or c.historical,
                )
    out = list(merged.values())
    return out[:limit] if limit else out
