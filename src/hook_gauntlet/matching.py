"""Which hooks fire for which tool call: ``matcher`` and the ``if`` permission rule.

``matcher`` follows the documented rules exactly: empty / ``*`` / missing matches
everything; a string of letters, digits, ``_``, ``-``, spaces, ``,`` and ``|`` is
an exact name list; anything else is an unanchored regular expression.

``if`` uses Claude Code's permission-rule syntax (``Bash(git *)``, ``Edit(*.ts)``).
We implement the common forms; anything we cannot evaluate is treated as a match,
so a hook is never silently skipped. ``if_rule_supported`` reports which is which.
"""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse

from .model import Hook, ToolCall

_NAME_LIST = re.compile(r"[A-Za-z0-9_\- ,|]*")
_RULE = re.compile(r"^\s*([A-Za-z0-9_\-*]+)\s*(?:\((.*)\))?\s*$", re.S)
FILE_TOOLS = frozenset({"Edit", "Write", "Read", "MultiEdit", "NotebookEdit"})


def matcher_matches(matcher: str | None, tool_name: str) -> bool:
    if matcher is None or matcher.strip() in ("", "*"):
        return True
    if _NAME_LIST.fullmatch(matcher):
        names = {n.strip() for n in re.split(r"[|,]", matcher) if n.strip()}
        return tool_name in names
    try:
        return re.search(matcher, tool_name) is not None
    except re.error:
        return False


def _parse_rule(rule: str) -> tuple[str, str | None] | None:
    m = _RULE.match(rule)
    if not m:
        return None
    return m.group(1), m.group(2)


def if_rule_supported(rule: str) -> bool:
    parsed = _parse_rule(rule)
    if parsed is None:
        return False
    tool, pattern = parsed
    if pattern is None:
        return True
    return tool == "Bash" or tool in FILE_TOOLS or (tool == "WebFetch" and pattern.startswith("domain:"))


def if_rule_matches(rule: str | None, call: ToolCall) -> bool:
    if rule is None or not rule.strip():
        return True
    parsed = _parse_rule(rule)
    if parsed is None:
        return True  # unknown syntax: run the hook rather than hide it
    tool, pattern = parsed
    if not fnmatch.fnmatchcase(call.tool_name, tool):
        return False
    if pattern is None or pattern.strip() in ("", "*"):
        return True
    ti = call.tool_input

    if call.tool_name == "Bash":
        cmd = str(ti.get("command", "")).strip()
        if pattern.endswith(":*"):  # legacy prefix form: Bash(npm run test:*)
            return cmd.startswith(pattern[:-2])
        return fnmatch.fnmatchcase(cmd, pattern)

    if call.tool_name in FILE_TOOLS:
        path = str(ti.get("file_path") or ti.get("notebook_path") or "")
        if not path:
            return False
        pat = pattern[2:] if pattern.startswith("./") else pattern
        if pat.startswith("//"):
            pat = pat[1:]
        if "/" not in pat.rstrip("/"):
            return fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], pat)
        return fnmatch.fnmatchcase(path, pat) or fnmatch.fnmatchcase(path, "*/" + pat.lstrip("/"))

    if call.tool_name == "WebFetch" and pattern.startswith("domain:"):
        host = urlparse(str(ti.get("url", ""))).hostname or ""
        want = pattern[len("domain:"):]
        return host == want or host.endswith("." + want)

    return True


def selects(hook: Hook, call: ToolCall, event: str = "PreToolUse") -> bool:
    """True when Claude Code would run ``hook`` for ``call``."""
    return hook.event == event and matcher_matches(hook.matcher, call.tool_name) and if_rule_matches(hook.if_rule, call)
