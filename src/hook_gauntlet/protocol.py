"""The Claude Code command-hook protocol: build the stdin payload, run the hook, read its answer.

Reference: https://code.claude.com/docs/en/hooks

* exit 2              -> blocking error; stderr is the reason fed back to the model
* exit 0 + JSON object -> ``hookSpecificOutput.permissionDecision`` (allow/deny/ask/defer),
                         or the older top-level ``decision`` ("block" / "approve")
* exit 0, anything else -> no opinion
* any other exit / timeout -> non-blocking error, unless the hook sets ``onFailure: "block"``
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Mapping

from .model import Hook, HookResult, JSONDict, ToolCall, Verdict

_DECISIONS = {
    "allow": Verdict.ALLOW,
    "deny": Verdict.DENY,
    "ask": Verdict.ASK,
    "defer": Verdict.DEFER,
}
_LEGACY = {"block": Verdict.DENY, "approve": Verdict.ALLOW}
MAX_CAPTURE = 20_000


def build_payload(
    call: ToolCall,
    *,
    event: str = "PreToolUse",
    cwd: str | None = None,
    session_id: str | None = None,
    permission_mode: str = "default",
    transcript_path: str = "",
) -> JSONDict:
    """The JSON object Claude Code writes to a tool hook's stdin."""
    return {
        "session_id": session_id or call.session_id or "hook-gauntlet",
        "transcript_path": transcript_path,
        "cwd": call.cwd or cwd or os.getcwd(),
        "permission_mode": permission_mode,
        "hook_event_name": event,
        "tool_name": call.tool_name,
        "tool_input": call.tool_input,
        "tool_use_id": call.tool_use_id or "toolu_gauntlet_" + uuid.uuid4().hex[:16],
    }


def parse_response(
    exit_code: int | None,
    stdout: str,
    stderr: str,
    *,
    timed_out: bool = False,
    on_failure: str = "continue",
) -> tuple[Verdict, str, bool, JSONDict | None]:
    """Interpret a hook's exit status and output.

    Returns ``(verdict, reason, stops_session, updated_input)``.
    """
    failure = Verdict.DENY if on_failure == "block" else Verdict.ERROR
    if timed_out:
        return failure, "hook timed out", False, None
    if exit_code == 2:
        return Verdict.DENY, stderr.strip(), False, None
    if exit_code != 0:
        return failure, (stderr.strip() or f"exit code {exit_code}"), False, None

    text = stdout.strip()
    if not text.startswith("{"):
        return Verdict.NONE, "", False, None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return Verdict.NONE, "", False, None
    if not isinstance(data, dict):
        return Verdict.NONE, "", False, None

    stops = data.get("continue") is False
    verdict = Verdict.NONE
    reason = ""
    updated: JSONDict | None = None

    hso = data.get("hookSpecificOutput")
    if isinstance(hso, dict):
        decision = hso.get("permissionDecision")
        if isinstance(decision, str) and decision in _DECISIONS:
            verdict = _DECISIONS[decision]
            reason = str(hso.get("permissionDecisionReason") or "")
        ui = hso.get("updatedInput")
        if isinstance(ui, dict):
            updated = ui

    if verdict == Verdict.NONE:
        legacy = data.get("decision")
        if isinstance(legacy, str) and legacy in _LEGACY:
            verdict = _LEGACY[legacy]
            reason = str(data.get("reason") or "")

    if stops and not reason:
        reason = str(data.get("stopReason") or "")
    return verdict, reason, stops, updated


def _expand(value: str, env: Mapping[str, str]) -> str:
    for name in ("CLAUDE_PROJECT_DIR", "CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA"):
        if name in env:
            value = value.replace("${" + name + "}", env[name]).replace("$" + name, env[name])
    return value


def run_hook(
    hook: Hook,
    payload: JSONDict,
    *,
    project_dir: str,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> HookResult:
    """Run one command hook exactly the way Claude Code would and interpret the answer."""
    run_env = dict(os.environ if env is None else env)
    run_env.setdefault("CLAUDE_PROJECT_DIR", project_dir)
    run_env["HOOK_GAUNTLET"] = "1"  # lets a hook detect a dry run and skip side effects

    limit = hook.timeout if timeout is None else min(timeout, hook.timeout)
    stdin = json.dumps(payload)

    if hook.args is not None:
        argv: list[str] | str = [_expand(hook.command, run_env), *(_expand(a, run_env) for a in hook.args)]
        shell = False
        executable = None
    else:
        argv = hook.command
        shell = True
        executable = shutil.which("bash") or None

    start = time.perf_counter()
    timed_out = False
    code: int | None
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            shell=shell,
            executable=executable,
            cwd=project_dir,
            env=run_env,
            timeout=limit,
            check=False,
        )
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        code = None
        out = _text(exc.stdout)
        err = _text(exc.stderr)
    except OSError as exc:
        code, out, err = 127, "", str(exc)
    duration = time.perf_counter() - start

    verdict, reason, stops, updated = parse_response(
        code, out, err, timed_out=timed_out, on_failure=hook.on_failure
    )
    return HookResult(
        hook=hook,
        verdict=verdict,
        reason=reason,
        exit_code=code,
        stdout=out[:MAX_CAPTURE],
        stderr=err[:MAX_CAPTURE],
        duration_s=duration,
        timed_out=timed_out,
        stops_session=stops,
        updated_input=updated,
    )


def _text(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw
