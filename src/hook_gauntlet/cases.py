"""Declarative hook test cases in TOML.

```toml
[[hook]]                      # optional: otherwise --hook / --settings / discovery
command = "python3 .claude/hooks/guard.py"
matcher = "Bash"

[[case]]
name   = "no recursive delete of root"
tool   = "Bash"
input  = { command = "rm -rf /" }
expect = "deny"               # deny | ask | defer | allow | none | pass | block
mutate = true                 # every semantics-preserving variant must be blocked too

[[case]]
name   = "reading docs is fine"
tool   = "Bash"
input  = { command = "cat README.md" }
expect = "pass"
```

``pass`` = the tool runs without a prompt (allow, no opinion, or a non-blocking error).
``block`` = it does not run without a human (deny, ask or defer).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import Hook, ToolCall, Verdict

EXPECTATIONS = ("deny", "ask", "defer", "allow", "none", "pass", "block")


class CaseError(Exception):
    pass


@dataclass(frozen=True)
class Case:
    name: str
    call: ToolCall
    expect: str
    mutate: bool = False
    reason_contains: str | None = None

    def satisfied_by(self, verdict: Verdict, reason: str = "") -> bool:
        return expectation_met(self.expect, verdict) and (
            self.reason_contains is None or self.reason_contains.lower() in reason.lower()
        )


def expectation_met(expect: str, verdict: Verdict) -> bool:
    if expect == "pass":
        return verdict.passes
    if expect == "block":
        return verdict.blocks
    return verdict.value == expect


def _hook(raw: Any, source: str) -> Hook:
    if not isinstance(raw, dict) or not isinstance(raw.get("command"), str):
        raise CaseError(f"{source}: every [[hook]] needs a string 'command'")
    args = raw.get("args")
    return Hook(
        command=raw["command"],
        args=tuple(str(a) for a in args) if isinstance(args, list) else None,
        matcher=raw.get("matcher") if isinstance(raw.get("matcher"), str) else None,
        if_rule=raw.get("if") if isinstance(raw.get("if"), str) else None,
        timeout=float(raw.get("timeout", 600)),
        on_failure=str(raw.get("onFailure", raw.get("on_failure", "continue"))),
        source=source,
    )


def load_cases(path: Path) -> tuple[list[Hook], list[Case]]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise CaseError(f"{path}: {exc}") from exc
    hooks = [_hook(h, f"{path}[hook {i}]") for i, h in enumerate(data.get("hook", []), 1)]
    cases: list[Case] = []
    for i, raw in enumerate(data.get("case", []), 1):
        where = f"{path}[case {i}]"
        if not isinstance(raw, dict):
            raise CaseError(f"{where}: must be a table")
        tool = raw.get("tool")
        tool_input = raw.get("input")
        expect = str(raw.get("expect", "")).lower()
        if not isinstance(tool, str) or not isinstance(tool_input, dict):
            raise CaseError(f"{where}: needs 'tool' (string) and 'input' (table)")
        if expect not in EXPECTATIONS:
            raise CaseError(f"{where}: expect must be one of {', '.join(EXPECTATIONS)}")
        name = str(raw.get("name") or f"case {i}")
        cases.append(
            Case(
                name=name,
                call=ToolCall(tool, dict(tool_input), cwd=raw.get("cwd"), source=where),
                expect=expect,
                mutate=bool(raw.get("mutate", False)),
                reason_contains=raw.get("reason_contains") if isinstance(raw.get("reason_contains"), str) else None,
            )
        )
    if not cases:
        raise CaseError(f"{path}: no [[case]] entries")
    return hooks, cases
