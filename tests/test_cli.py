from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from hook_gauntlet.cases import CaseError, expectation_met, load_cases
from hook_gauntlet.cli import main
from hook_gauntlet.model import Verdict
from hook_gauntlet.report import one_line, redact

from .conftest import EXAMPLES, HARDENED, NAIVE, ROOT

HISTORY = str(EXAMPLES / "history")


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    rc = main(list(argv))
    return rc, capsys.readouterr().out


def test_check_shows_each_hook(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out = run(capsys, "check", "Bash", "rm -rf /", "--hook", NAIVE, "--hook", HARDENED)
    assert rc == 0
    assert out.count("  DENY ") == 2 and "exit 2" in out and "exit 0" in out and out.rstrip().endswith("=> DENY")
    rc, out = run(capsys, "check", "Bash", "ls", "--hook", NAIVE, "--matcher", "Write")
    assert "skip" in out and out.rstrip().endswith("=> NONE")
    rc, out = run(capsys, "check", "Read", "--input", '{"file_path": "/a/.env"}', "--hook", HARDENED, "--json")
    data = json.loads(out)
    assert data["verdict"] == "deny" and data["hooks"][0]["reason"] == "secret file"


def test_test_command_passes_examples_and_writes_junit(capsys: pytest.CaptureFixture[str], tmp_path: Path,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    junit = tmp_path / "junit.xml"
    rc, out = run(capsys, "test", str(EXAMPLES / "cases.toml"), "--junit", str(junit), "--project-dir", str(ROOT))
    assert rc == 0, out
    assert "8/8 cases passed" in out and "mutants" in out
    assert 'failures="0"' in junit.read_text()


def test_test_command_fails_naive_guard(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    rc, out = run(capsys, "test", str(EXAMPLES / "cases.toml"), "--hook", NAIVE, "--json")
    assert rc == 1
    reports = {r["name"]: r for r in json.loads(out)}
    rm = reports["recursive force delete is denied, in any spelling"]
    assert not rm["ok"] and rm["verdict"] == "deny"
    assert {"flag-split", "quote-split"} <= {m["op"] for m in rm["failed_mutants"]}
    assert not reports["grepping for the pattern is not running it"]["ok"]  # false positive caught


def test_replay_history(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.jsonl"
    rc, out = run(capsys, "replay", "--history", HISTORY, "--hook", NAIVE, "--save-corpus", str(corpus))
    assert rc == 0
    assert "replayed 14 distinct calls (16 total, 1 sessions)" in out
    assert "historically blocked by a hook: 1 calls, 1 still blocked, 0 now pass" in out
    assert "grep -rn 'rm -rf' scripts/" in out and "hook latency per call" in out
    assert len(corpus.read_text().splitlines()) == 14

    rc, out = run(capsys, "replay", "--corpus", str(corpus), "--hook", HARDENED, "--fail-if-blocks", "--json")
    data = json.loads(out)
    assert rc == 1 and data["calls"] == 14 and data["occurrences"] == 16
    assert [o["tool_input"]["command"] for o in data["outcomes"]] == ["rm -rf build/ dist/"]

    rc, out = run(capsys, "replay", "--history", HISTORY, "--hook", NAIVE, "--tools", "Read", "--show", "deny")
    assert "replayed 2 distinct calls" in out


def test_replay_redacts_credentials(capsys: pytest.CaptureFixture[str], make_hook) -> None:  # type: ignore[no-untyped-def]
    deny_all = make_hook("sys.exit(2)\n")
    rc, out = run(capsys, "replay", "--history", HISTORY, "--hook", deny_all, "--top", "50")
    assert "sk-proj-FAKE" not in out and "[REDACTED]" in out
    rc, out = run(capsys, "replay", "--history", HISTORY, "--hook", deny_all, "--top", "50", "--no-redact")
    assert "sk-proj-FAKE" in out


def test_fuzz(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out = run(capsys, "fuzz", "--hook", NAIVE, "--seed", "rm -rf build", "--json")
    data = json.loads(out)
    assert rc == 1 and data["covered"] == 1 and data["mutants"] > 15
    assert {"flag-split", "flag-long", "quote-split"} <= {b["op"] for b in data["bypasses"]}

    rc, out = run(capsys, "fuzz", "--hook", HARDENED, "--pack", "destructive", "--pack", "git")
    assert rc == 0 and "bypasses: 0" in out and "NOT BLOCKED AT ALL" in out
    rc, out = run(capsys, "fuzz", "--hook", HARDENED, "--pack", "git", "--strict")
    assert rc == 1


def test_diff_two_commands(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out = run(capsys, "diff", "--history", HISTORY, "--old-hook", NAIVE, "--new-hook", HARDENED, "--json")
    data = json.loads(out)
    assert rc == 1 and data["calls"] == 14
    allowed = {r["tool_input"].get("command") or r["tool_input"].get("file_path") for r in data["newly_allowed"]}
    assert "grep -rn 'rm -rf' scripts/" in allowed and "/home/dev/app/.env.example" in allowed
    assert data["newly_blocked"] == []
    rc, _ = run(capsys, "diff", "--history", HISTORY, "--old-hook", NAIVE, "--new-hook", HARDENED,
                "--fail-on", "newly-blocked")
    assert rc == 0


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(repo), "PATH": "/usr/bin:/bin:/usr/local/bin"})


def test_diff_against_git_revision(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    hooks = repo / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "rules.py").write_text("WORDS = ['danger']\n")
    (hooks / "guard.py").write_text(
        "import json, sys\nsys.path.insert(0, __import__('os').path.dirname(__file__))\nfrom rules import WORDS\n"
        "cmd = json.load(sys.stdin)['tool_input'].get('command', '')\n"
        "sys.exit(2 if any(w in cmd for w in WORDS) else 0)\n")
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "v1")
    (hooks / "rules.py").write_text("WORDS = ['danger', 'pytest']\n")  # the "improvement" under review

    rc, out = run(capsys, "diff", "--against", "HEAD", "--hook", f"{sys.executable} hooks/guard.py",
                  "--project-dir", str(repo), "--history", HISTORY)
    assert rc == 1
    assert "1 decisions changed (@HEAD -> new)" in out
    assert "NEWLY BLOCKED" in out and "x3" in out and "python -m pytest -q" in out

    rc, out = run(capsys, "diff", "--against", "nope", "--hook", f"{sys.executable} hooks/guard.py",
                  "--project-dir", str(repo), "--history", HISTORY)
    assert rc == 2


def test_isolate_home(capsys: pytest.CaptureFixture[str], make_hook) -> None:  # type: ignore[no-untyped-def]
    real_home = str(Path.home())
    show_home = make_hook("print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse',"
                          " 'permissionDecision': 'deny', 'permissionDecisionReason': os.environ['HOME']}}))\n")
    rc, out = run(capsys, "check", "Bash", "ls", "--hook", show_home, "--json", "--isolate-home")
    home = json.loads(out)["hooks"][0]["reason"]
    assert home != real_home and "hook-gauntlet-home-" in home


def test_hooks_listing(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out = run(capsys, "hooks", "--no-user-settings", "--settings", str(EXAMPLES / "demo-hooks.json"))
    assert rc == 0 and "Bash(git *)" in out and "'prompt' handler not executed" in out


def test_usage_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["check", "Bash", "ls", "--project-dir", str(tmp_path), "--no-user-settings"]) == 2
    assert main(["replay", "--history", str(tmp_path), "--hook", "true"]) == 2
    assert main(["fuzz", "--hook", "true", "--pack", "nope"]) == 2
    assert main(["diff", "--history", HISTORY]) == 2
    assert "error" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "hook-gauntlet" in capsys.readouterr().out


def test_module_entrypoint() -> None:
    proc = subprocess.run([sys.executable, "-m", "hook_gauntlet", "check", "Bash", "rm -rf /", "--hook", NAIVE],
                          capture_output=True, text=True, cwd=ROOT,
                          env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 0 and "=> DENY" in proc.stdout


def test_cases_validation(tmp_path: Path) -> None:
    bad = tmp_path / "c.toml"
    bad.write_text('[[case]]\ntool = "Bash"\ninput = { command = "x" }\nexpect = "maybe"\n')
    with pytest.raises(CaseError):
        load_cases(bad)
    bad.write_text("")
    with pytest.raises(CaseError):
        load_cases(bad)
    bad.write_text("[[case]\n")
    with pytest.raises(CaseError):
        load_cases(bad)
    assert expectation_met("pass", Verdict.ERROR) and expectation_met("block", Verdict.ASK)
    assert not expectation_met("deny", Verdict.ASK)


def test_redaction() -> None:
    assert redact("key sk-ant-api03-abcdefghijklmnopqrstuv end") == "key [REDACTED] end"
    assert redact("ghp_" + "a" * 36) == "[REDACTED]"
    assert redact("AKIA" + "B" * 16) == "[REDACTED]"
    assert redact("password=hunter2hunter2") == "password=[REDACTED]"
    assert redact("TOKEN: 'abcdefghij'") == "TOKEN: '[REDACTED]'"
    assert redact("git status") == "git status"
    assert one_line("a\nb\tc", 100, do_redact=False) == "a\\nb\\tc"
    assert one_line("x" * 20, 10, do_redact=False) == "x" * 9 + "…"
