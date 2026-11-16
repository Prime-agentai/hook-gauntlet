from __future__ import annotations

import json
from pathlib import Path

import pytest

from hook_gauntlet.config import ConfigError, discover, hooks_from_settings, unsupported_handlers
from hook_gauntlet.matching import if_rule_matches, if_rule_supported, matcher_matches, selects
from hook_gauntlet.model import Hook, ToolCall


@pytest.mark.parametrize("matcher,tool,ok", [
    (None, "Bash", True), ("", "Write", True), ("*", "Read", True),
    ("Bash", "Bash", True), ("Bash", "BashOutput", False),
    ("Edit|Write", "Write", True), ("Edit|Write", "Read", False), ("Edit, Write", "Edit", True),
    ("mcp__memory__.*", "mcp__memory__store", True), ("mcp__memory__.*", "mcp__github__x", False),
    ("Notebook.*", "NotebookEdit", True), ("[", "Bash", False),
])
def test_matcher(matcher: str | None, tool: str, ok: bool) -> None:
    assert matcher_matches(matcher, tool) is ok


def _bash(cmd: str) -> ToolCall:
    return ToolCall("Bash", {"command": cmd})


def _edit(path: str) -> ToolCall:
    return ToolCall("Edit", {"file_path": path})


@pytest.mark.parametrize("rule,call,ok", [
    (None, _bash("ls"), True),
    ("Bash", _bash("ls"), True),
    ("Bash(git *)", _bash("git push"), True),
    ("Bash(git *)", _bash("npm test"), False),
    ("Bash(npm run test:*)", _bash("npm run test -- -k x"), True),
    ("Bash(rm *)", _edit("/x/rm.txt"), False),
    ("Edit(*.ts)", _edit("/repo/src/a.ts"), True),
    ("Edit(*.ts)", _edit("/repo/src/a.py"), False),
    ("Edit(src/**)", _edit("/repo/src/deep/a.py"), True),
    ("WebFetch(domain:example.com)", ToolCall("WebFetch", {"url": "https://api.example.com/x"}), True),
    ("WebFetch(domain:example.com)", ToolCall("WebFetch", {"url": "https://evil.com/example.com"}), False),
    ("mcp__x__y(whatever)", ToolCall("mcp__x__y", {}), True),
])
def test_if_rule(rule: str | None, call: ToolCall, ok: bool) -> None:
    assert if_rule_matches(rule, call) is ok


def test_if_rule_supported() -> None:
    assert if_rule_supported("Bash(git *)") and if_rule_supported("Edit(*.ts)")
    assert not if_rule_supported("mcp__x__y(foo)") and not if_rule_supported("((")


def test_selects_checks_event_matcher_and_if() -> None:
    h = Hook("x", matcher="Bash", if_rule="Bash(git *)")
    assert selects(h, _bash("git status"))
    assert not selects(h, _bash("ls"))
    assert not selects(h, _bash("git status"), event="PostToolUse")


SETTINGS = {
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [
                {"type": "command", "command": "guard.sh", "timeout": 5, "if": "Bash(rm *)", "onFailure": "block"},
                {"type": "prompt", "prompt": "safe?"},
                {"type": "command"},  # no command: ignored
            ]},
            {"hooks": [{"command": "all.sh", "args": ["a", 1]}]},
        ],
        "PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "fmt.sh"}]}],
    }
}


def test_hooks_from_settings() -> None:
    hooks = hooks_from_settings(SETTINGS, source="s", event="PreToolUse")
    assert [h.command for h in hooks] == ["guard.sh", "all.sh"]
    g, a = hooks
    assert (g.matcher, g.timeout, g.if_rule, g.on_failure) == ("Bash", 5.0, "Bash(rm *)", "block")
    assert a.matcher is None and a.args == ("a", "1") and a.timeout == 600.0
    assert len(hooks_from_settings(SETTINGS, source="s", event=None)) == 3
    assert unsupported_handlers(SETTINGS) == ["PreToolUse: 'prompt' handler not executed (command hooks only)"]
    assert hooks_from_settings({"hooks": "nope"}, source="s") == []


def test_discover_precedence_and_errors(tmp_path: Path) -> None:
    home = tmp_path / "home"
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.json").write_text(json.dumps(
        {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "project.sh"}]}]}}))
    (proj / ".claude" / "settings.local.json").write_text(json.dumps(
        {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "local.sh"}]}]}}))
    hooks, _ = discover(proj, include_user=False)
    assert [h.command for h in hooks] == ["project.sh", "local.sh"]
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text((proj / ".claude" / "settings.json").read_text())
    from hook_gauntlet.config import settings_paths
    paths = settings_paths(proj, home=home)
    hooks, _ = discover(proj, explicit=paths)
    assert [h.command for h in hooks] == ["project.sh", "local.sh"]  # identical handler runs once
    with pytest.raises(ConfigError):
        discover(proj, explicit=[tmp_path / "missing.json"])
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    with pytest.raises(ConfigError):
        discover(proj, explicit=[bad])
    assert home  # user settings are opt-out via include_user
