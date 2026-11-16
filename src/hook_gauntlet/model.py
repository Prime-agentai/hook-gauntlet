"""Core data types shared by every hook-gauntlet module."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

JSONDict = dict[str, Any]


class Verdict(str, Enum):
    """What a hook (or a set of hooks) decided about one tool call.

    ``NONE`` means the hook expressed no opinion (exit 0, no decision), so
    Claude Code falls through to its normal permission flow. ``ERROR`` is a
    non-blocking failure: the tool call still proceeds.
    """

    DENY = "deny"
    DEFER = "defer"
    ASK = "ask"
    ALLOW = "allow"
    NONE = "none"
    ERROR = "error"

    @property
    def blocks(self) -> bool:
        """True when the tool call does not run without a human."""
        return self in (Verdict.DENY, Verdict.ASK, Verdict.DEFER)

    @property
    def passes(self) -> bool:
        """True when the hook lets the call through (allow, no opinion, or a non-blocking error)."""
        return self in (Verdict.ALLOW, Verdict.NONE, Verdict.ERROR)


# Most restrictive wins when several hooks answer the same call.
PRECEDENCE: tuple[Verdict, ...] = (
    Verdict.DENY,
    Verdict.DEFER,
    Verdict.ASK,
    Verdict.ALLOW,
    Verdict.ERROR,
    Verdict.NONE,
)


def combine(verdicts: list[Verdict]) -> Verdict:
    """Fold several hook verdicts into the one Claude Code would act on."""
    for v in PRECEDENCE:
        if v in verdicts:
            return v
    return Verdict.NONE


@dataclass(frozen=True)
class Hook:
    """One command hook, as configured in a settings file or given with ``--hook``."""

    command: str
    args: tuple[str, ...] | None = None
    event: str = "PreToolUse"
    matcher: str | None = None
    if_rule: str | None = None
    timeout: float = 600.0
    on_failure: str = "continue"
    source: str = "--hook"

    @property
    def label(self) -> str:
        text = self.command if self.args is None else " ".join((self.command, *self.args))
        return text if len(text) <= 70 else "..." + text[-67:]  # keep the script name visible


@dataclass(frozen=True)
class ToolCall:
    """A single tool invocation to put in front of the hooks."""

    tool_name: str
    tool_input: JSONDict
    cwd: str | None = None
    session_id: str | None = None
    tool_use_id: str | None = None
    source: str = ""
    occurrences: int = 1
    historical: str | None = None  # "blocked" when the transcript shows a hook block

    def key(self) -> str:
        """Stable identity used for de-duplication and diffing."""
        return self.tool_name + "\x00" + json.dumps(self.tool_input, sort_keys=True, ensure_ascii=False)

    def summary(self) -> str:
        """Short, human-readable description of the call."""
        ti = self.tool_input
        for k in ("command", "file_path", "notebook_path", "url", "pattern", "path", "query", "prompt"):
            v = ti.get(k)
            if isinstance(v, str) and v:
                return v
        return json.dumps(ti, sort_keys=True, ensure_ascii=False)


@dataclass
class HookResult:
    """The raw and interpreted outcome of running one hook on one call."""

    hook: Hook
    verdict: Verdict
    reason: str = ""
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    stops_session: bool = False
    updated_input: JSONDict | None = None
    skipped: bool = False  # matcher / if-rule did not select this hook


@dataclass
class Outcome:
    """Combined decision of all selected hooks for one call."""

    call: ToolCall
    results: list[HookResult] = field(default_factory=list)

    @property
    def ran(self) -> list[HookResult]:
        return [r for r in self.results if not r.skipped]

    @property
    def verdict(self) -> Verdict:
        return combine([r.verdict for r in self.ran])

    @property
    def reason(self) -> str:
        v = self.verdict
        for r in self.ran:
            if r.verdict == v and r.reason:
                return r.reason
        return ""

    @property
    def duration_s(self) -> float:
        # Claude Code runs matching hooks in parallel, so wall time is the slowest one.
        return max((r.duration_s for r in self.ran), default=0.0)

    @property
    def errors(self) -> list[HookResult]:
        return [r for r in self.ran if r.verdict == Verdict.ERROR or r.timed_out]
