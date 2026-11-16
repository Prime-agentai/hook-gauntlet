from __future__ import annotations

import json
from pathlib import Path

import pytest

from hook_gauntlet.model import Hook, ToolCall, Verdict, combine
from hook_gauntlet.protocol import build_payload, parse_response, run_hook


def _deny_json(decision: str, reason: str = "r") -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                              "permissionDecision": decision,
                                              "permissionDecisionReason": reason}})


@pytest.mark.parametrize("decision,verdict", [("deny", Verdict.DENY), ("ask", Verdict.ASK),
                                              ("allow", Verdict.ALLOW), ("defer", Verdict.DEFER)])
def test_json_permission_decisions(decision: str, verdict: Verdict) -> None:
    v, reason, stops, _ = parse_response(0, _deny_json(decision, "because"), "")
    assert v == verdict and reason == "because" and not stops


def test_exit_2_is_deny_with_stderr_reason() -> None:
    assert parse_response(2, "", "Blocked: nope\n")[:2] == (Verdict.DENY, "Blocked: nope")


def test_exit_2_ignores_json_allow() -> None:
    assert parse_response(2, _deny_json("allow"), "x")[0] == Verdict.DENY


def test_other_exit_codes_are_non_blocking_errors() -> None:
    assert parse_response(1, "", "boom")[0] == Verdict.ERROR
    assert parse_response(1, "", "boom", on_failure="block")[0] == Verdict.DENY


def test_timeout() -> None:
    assert parse_response(None, "", "", timed_out=True)[0] == Verdict.ERROR
    assert parse_response(None, "", "", timed_out=True, on_failure="block")[0] == Verdict.DENY


def test_exit_0_plain_text_or_garbage_is_no_opinion() -> None:
    assert parse_response(0, "hello", "")[0] == Verdict.NONE
    assert parse_response(0, "{not json", "")[0] == Verdict.NONE
    assert parse_response(0, "[1, 2]", "")[0] == Verdict.NONE
    assert parse_response(0, "", "")[0] == Verdict.NONE


def test_legacy_top_level_decision() -> None:
    assert parse_response(0, '{"decision": "block", "reason": "old"}', "")[:2] == (Verdict.DENY, "old")
    assert parse_response(0, '{"decision": "approve"}', "")[0] == Verdict.ALLOW


def test_continue_false_and_updated_input() -> None:
    out = json.dumps({"continue": False, "stopReason": "halt",
                      "hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": {"command": "ls"}}})
    v, reason, stops, updated = parse_response(0, out, "")
    assert v == Verdict.NONE and stops and reason == "halt" and updated == {"command": "ls"}


def test_combine_most_restrictive_wins() -> None:
    assert combine([Verdict.ALLOW, Verdict.DENY, Verdict.ASK]) == Verdict.DENY
    assert combine([Verdict.ALLOW, Verdict.ASK]) == Verdict.ASK
    assert combine([Verdict.NONE, Verdict.ERROR]) == Verdict.ERROR
    assert combine([]) == Verdict.NONE
    assert Verdict.ERROR.passes and not Verdict.ERROR.blocks


def test_payload_shape() -> None:
    p = build_payload(ToolCall("Bash", {"command": "ls"}), cwd="/w")
    assert p["hook_event_name"] == "PreToolUse" and p["tool_name"] == "Bash"
    assert p["tool_input"] == {"command": "ls"} and p["cwd"] == "/w"
    assert p["tool_use_id"].startswith("toolu_") and p["permission_mode"] == "default"


def test_run_hook_sees_payload_and_env(make_hook, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    cmd = make_hook(
        "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',"
        " 'permissionDecisionReason': payload['tool_input']['command'] + '|' + os.environ['HOOK_GAUNTLET']"
        " + '|' + os.environ['CLAUDE_PROJECT_DIR'] + '|' + os.getcwd()}}))\n"
    )
    r = run_hook(Hook(cmd), build_payload(ToolCall("Bash", {"command": "ls"})), project_dir=str(tmp_path))
    assert r.verdict == Verdict.DENY
    assert r.reason == f"ls|1|{tmp_path}|{tmp_path}"
    assert r.exit_code == 0 and r.duration_s > 0


def test_run_hook_exec_form_expands_project_dir(tmp_path: Path) -> None:
    script = tmp_path / "h.py"
    script.write_text("import sys\nprint('nope', file=sys.stderr)\nsys.exit(2)\n", encoding="utf-8")
    import sys
    hook = Hook(command=sys.executable, args=("${CLAUDE_PROJECT_DIR}/h.py",))
    r = run_hook(hook, build_payload(ToolCall("Bash", {"command": "x"})), project_dir=str(tmp_path))
    assert (r.verdict, r.reason, r.exit_code) == (Verdict.DENY, "nope", 2)


def test_run_hook_timeout(make_hook, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    cmd = make_hook("time.sleep(5)\n")
    r = run_hook(Hook(cmd, timeout=0.5), build_payload(ToolCall("Bash", {"command": "x"})), project_dir=str(tmp_path))
    assert r.timed_out and r.verdict == Verdict.ERROR


def test_run_hook_missing_program(tmp_path: Path) -> None:
    hook = Hook(command="/nonexistent/hook-binary", args=())
    r = run_hook(hook, build_payload(ToolCall("Bash", {"command": "x"})), project_dir=str(tmp_path))
    assert r.verdict == Verdict.ERROR
