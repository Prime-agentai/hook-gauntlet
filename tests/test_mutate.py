"""Mutation operators: shape tests, plus an empirical check that mutants really mean the same thing.

The equivalence tests execute the original command and every mutant with bash inside
a fresh temporary directory and compare what happened (filesystem state + stdout).
Only harmless programs on temp files are used.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from hook_gauntlet.model import ToolCall
from hook_gauntlet.mutate import BASH_OPERATORS, mutate, mutate_once, operator_names


def _ops(cmd: str) -> dict[str, str]:
    return {m.op: m.call.tool_input["command"] for m in mutate_once(ToolCall("Bash", {"command": cmd}))}


def test_rm_operators() -> None:
    ops = _ops("rm -rf build")
    assert ops["flag-split"] == "rm -r -f build"
    assert ops["flag-reorder"] == "rm -fr build"
    assert ops["flag-long"] == "rm --recursive --force build"
    assert ops["flag-case"] == "rm -Rf build"
    assert ops["flags-last"] == "rm build -rf"
    assert ops["end-of-options"] == "rm -rf -- build"
    assert ops["quote-split"] == "r''m -rf build"
    assert ops["backslash"] == "\\rm -rf build"
    assert ops["var-indirection"] == "_g=rm; $_g -rf build"
    assert ops["bash-c"] == "bash -c 'rm -rf build'"
    assert ops["subshell"] == "( rm -rf build )"
    assert ops["brace-group"] == "{ rm -rf build; }"
    assert ops["newline-prefix"] == ":\nrm -rf build"
    assert "git-global-option" not in ops


def test_git_operators_and_gating() -> None:
    ops = _ops("git push -f origin main")
    assert ops["git-global-option"] == "git -C . push -f origin main"
    assert ops["flag-long"] == "git push --force origin main"
    assert "flag-case" not in ops and "flags-last" not in ops
    # find is not a getopt tool: never split -name into -n -a -m -e
    assert "flag-split" not in _ops("find . -name x -delete")


def test_complex_commands_only_get_wrapper_operators() -> None:
    ops = _ops("cat a.txt | grep 'x y'")
    assert "tab-separator" not in ops and "flag-split" not in ops
    assert ops["bash-c"] == "bash -c 'cat a.txt | grep '\"'\"'x y'\"'\"''"


def test_builtins_skip_program_rewrites() -> None:
    ops = _ops("cd /tmp")
    assert "env-prefix" not in ops and "abs-path" not in ops and "var-indirection" not in ops


def test_home_and_path_operators() -> None:
    assert _ops("rm -rf ~")["home-var"] == "rm -rf $HOME"
    assert _ops("rm -rf ~/x")["home-var"] == 'rm -rf "$HOME"/x'
    assert _ops("cat /etc/hosts")["path-dot"] == "cat /./etc/hosts"
    assert _ops("cat .env.local")["path-dot"] == "cat ./.env.local"


def test_file_tool_path_variants() -> None:
    call = ToolCall("Read", {"file_path": "/home/dev/app/.env"}, cwd="/home/dev/app")
    got = {m.op: m.call.tool_input["file_path"] for m in mutate_once(call)}
    assert got == {
        "path-dot-segment": "/home/dev/app/./.env",
        "path-double-slash": "/home/dev/app//.env",
        "path-parent-hop": "/home/dev/app/../app/.env",
        "path-relative": "./.env",
    }
    rel = {m.op: m.call.tool_input["file_path"] for m in mutate_once(ToolCall("Read", {"file_path": ".env"}, cwd="/w"))}
    assert rel == {"path-dot-segment": "./.env", "path-absolute": "/w/.env"}
    assert mutate_once(ToolCall("WebSearch", {"query": "x"})) == []


def test_mutants_are_distinct_and_depth_composes() -> None:
    call = ToolCall("Bash", {"command": "rm -rf build"}, occurrences=7, historical="blocked")
    d1 = mutate(call)
    d2 = mutate(call, depth=2)
    keys = [m.call.key() for m in d2]
    assert len(keys) == len(set(keys)) and call.key() not in keys
    assert len(d2) > len(d1) * 3
    assert any("+" in m.op for m in d2)
    assert all(m.call.occurrences == 1 and m.call.historical is None for m in d2)
    assert len(mutate(call, depth=3, limit=50)) == 50


def test_operator_names_unique() -> None:
    names = operator_names()
    assert len(names) == len(set(names))
    assert len(BASH_OPERATORS) >= 25


def _snapshot(root: Path) -> list[tuple[str, str]]:
    out = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        mode = oct(p.stat().st_mode & 0o777) if not p.is_symlink() else "link"
        out.append((rel, "dir" if p.is_dir() else mode + ":" + p.read_text()))
    return out


def _run(cmd: str, cwd: Path, home: Path) -> tuple[str, list[tuple[str, str]]]:
    env = {**os.environ, "HOME": str(home)}
    proc = subprocess.run(["bash", "-c", cmd], cwd=cwd, env=env, capture_output=True, text=True, timeout=20)
    return proc.stdout, _snapshot(cwd)


def _setup(root: Path) -> None:
    (root / "build" / "deep").mkdir(parents=True)
    (root / "build" / "deep" / "f.txt").write_text("x")
    (root / "keep.txt").write_text("keep")
    (root / ".env.local").write_text("A=1\n")


SEEDS = [
    "rm -rf build",
    "rm -r -f build/deep",
    "chmod -R 700 build",
    "mkdir -p out/a/b",
    "cat .env.local",
    "cp -r build copy",
    "mv -f keep.txt moved.txt",
    "printf '%s\\n' hello world",
]


@pytest.mark.skipif(shutil.which("bash") is None or os.name != "posix", reason="needs bash")
@pytest.mark.parametrize("seed", SEEDS)
def test_mutants_are_semantically_equivalent(seed: str, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    base = tmp_path / "base"
    base.mkdir()
    _setup(base)
    expected = _run(seed, base, home)
    mutants = mutate(ToolCall("Bash", {"command": seed}))
    assert mutants
    for i, m in enumerate(mutants):
        work = tmp_path / f"m{i}"
        work.mkdir()
        _setup(work)
        got = _run(m.call.tool_input["command"], work, home)
        assert got == expected, f"{m.op}: {m.call.tool_input['command']!r} behaved differently"
