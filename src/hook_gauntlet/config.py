"""Discover command hooks from Claude Code settings files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import Hook

DEFAULT_TIMEOUT = 600.0


class ConfigError(Exception):
    pass


def settings_paths(project_dir: Path, *, include_user: bool = True, home: Path | None = None) -> list[Path]:
    """The settings files Claude Code reads for a project, lowest precedence first."""
    paths: list[Path] = []
    if include_user:
        paths.append((home or Path.home()) / ".claude" / "settings.json")
    paths.append(project_dir / ".claude" / "settings.json")
    paths.append(project_dir / ".claude" / "settings.local.json")
    return paths


def hooks_from_settings(data: Any, *, source: str, event: str | None = None) -> list[Hook]:
    """Extract every ``type: command`` hook from a parsed settings object.

    Non-command handlers (http, prompt, agent, mcp_tool) cannot run offline; they are
    skipped here and reported by :func:`unsupported_handlers`.
    """
    out: list[Hook] = []
    if not isinstance(data, dict):
        return out
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return out
    for ev, groups in hooks.items():
        if event is not None and ev != event:
            continue
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            matcher = group.get("matcher")
            for h in group.get("hooks") or []:
                if not isinstance(h, dict) or h.get("type", "command") != "command":
                    continue
                cmd = h.get("command")
                if not isinstance(cmd, str) or not cmd.strip():
                    continue
                args = h.get("args")
                timeout = h.get("timeout")
                out.append(
                    Hook(
                        command=cmd,
                        args=tuple(str(a) for a in args) if isinstance(args, list) else None,
                        event=str(ev),
                        matcher=matcher if isinstance(matcher, str) else None,
                        if_rule=h.get("if") if isinstance(h.get("if"), str) else None,
                        timeout=float(timeout) if isinstance(timeout, (int, float)) and timeout > 0 else DEFAULT_TIMEOUT,
                        on_failure=str(h.get("onFailure") or "continue"),
                        source=source,
                    )
                )
    return out


def unsupported_handlers(data: Any) -> list[str]:
    """Human-readable notes on handlers hook-gauntlet does not execute."""
    notes: list[str] = []
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return notes
    for ev, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            for h in (group.get("hooks") or []) if isinstance(group, dict) else []:
                if isinstance(h, dict) and h.get("type", "command") != "command":
                    notes.append(f"{ev}: '{h.get('type')}' handler not executed (command hooks only)")
    return notes


def load_settings_file(path: Path, *, event: str | None = "PreToolUse") -> tuple[list[Hook], list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON ({exc})") from exc
    return hooks_from_settings(data, source=str(path), event=event), unsupported_handlers(data)


def discover(
    project_dir: Path,
    *,
    explicit: list[Path] | None = None,
    include_user: bool = True,
    event: str | None = "PreToolUse",
) -> tuple[list[Hook], list[str]]:
    """Hooks from explicit settings files, or from the standard locations if none were given."""
    paths = explicit if explicit else settings_paths(project_dir, include_user=include_user)
    hooks: list[Hook] = []
    notes: list[str] = []
    for p in paths:
        if not p.is_file():
            if explicit:
                raise ConfigError(f"{p}: no such settings file")
            continue
        h, n = load_settings_file(p, event=event)
        hooks.extend(h)
        notes.extend(n)
    # "If you define the same handler in more than one settings file, it runs once."
    seen: set[tuple[object, ...]] = set()
    unique: list[Hook] = []
    for hk in hooks:
        ident = (hk.event, hk.matcher, hk.if_rule, hk.command, hk.args)
        if ident not in seen:
            seen.add(ident)
            unique.append(hk)
    return unique, notes
