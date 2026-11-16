from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from hook_gauntlet.transcripts import CorpusFilter, calls_from_file, find_transcripts, is_hook_block, load_corpus


def _assistant(tid: str, name: str, inp: dict[str, object], *, ts: str = "2026-11-01T10:00:00Z",
               side: bool = False) -> str:
    return json.dumps({"type": "assistant", "sessionId": "s1", "cwd": "/w", "timestamp": ts, "isSidechain": side,
                       "message": {"content": [{"type": "text", "text": "hi"},
                                               {"type": "tool_use", "id": tid, "name": name, "input": inp}]}})


def _result(tid: str, text: str | list[dict[str, str]], err: bool) -> str:
    return json.dumps({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": tid, "is_error": err, "content": text}]}})


def test_extracts_calls_and_historical_blocks(tmp_path: Path) -> None:
    f = tmp_path / "proj-a" / "s1.jsonl"
    f.parent.mkdir()
    f.write_text("\n".join([
        "not json",
        "",
        json.dumps({"type": "summary"}),
        _assistant("t1", "Bash", {"command": "ls"}),
        _result("t1", "ok", False),
        _assistant("t2", "Bash", {"command": "danger"}),
        _result("t2", [{"type": "text", "text": "PreToolUse:Bash hook error: [g.py]: Blocked"}], True),
        _assistant("t3", "Write", {"file_path": "/w/a", "content": "x"}),
        _result("t3", "File does not exist", True),
        _assistant("t4", "Bash", {"command": "ls"}),
        _assistant("t5", "Task", "not a dict"),  # type: ignore[arg-type]
    ]) + "\n")
    calls = list(calls_from_file(f))
    assert [c.tool_use_id for c in calls] == ["t1", "t2", "t3", "t4"]
    assert [c.historical for c in calls] == [None, "blocked", None, None]
    assert calls[0].cwd == "/w" and calls[0].session_id == "s1" and calls[0].source.endswith(":4")

    corpus = load_corpus([f])
    assert len(corpus) == 3
    ls = next(c for c in corpus if c.tool_input == {"command": "ls"})
    assert ls.occurrences == 2
    assert len(load_corpus([f], dedupe=False)) == 4
    assert len(load_corpus([f], limit=1)) == 1
    assert [c.tool_name for c in load_corpus([f], CorpusFilter(tools=frozenset({"Write"})))] == ["Write"]


def test_filters_sidechains_and_dates(tmp_path: Path) -> None:
    f = tmp_path / "s.jsonl"
    f.write_text("\n".join([
        _assistant("a", "Bash", {"command": "old"}, ts="2026-01-01T00:00:00Z"),
        _assistant("b", "Bash", {"command": "new"}, ts="2026-11-10T00:00:00Z"),
        _assistant("c", "Bash", {"command": "sub"}, ts="2026-11-10T00:00:00Z", side=True),
    ]))
    since = CorpusFilter(since=datetime(2026, 11, 1))
    assert [c.tool_input["command"] for c in calls_from_file(f, since)] == ["new", "sub"]
    no_side = CorpusFilter(include_sidechains=False)
    assert [c.tool_input["command"] for c in calls_from_file(f, no_side)] == ["old", "new"]


def test_find_transcripts(tmp_path: Path) -> None:
    (tmp_path / "-home-me-alpha" / "sub").mkdir(parents=True)
    (tmp_path / "-home-me-beta").mkdir()
    (tmp_path / "-home-me-alpha" / "1.jsonl").write_text("")
    (tmp_path / "-home-me-alpha" / "sub" / "2.jsonl").write_text("")
    (tmp_path / "-home-me-beta" / "3.jsonl").write_text("")
    assert len(find_transcripts(tmp_path)) == 3
    assert len(find_transcripts(tmp_path, project="alpha")) == 2
    assert find_transcripts(tmp_path / "1.jsonl") == []
    assert find_transcripts(tmp_path / "-home-me-beta" / "3.jsonl") == [tmp_path / "-home-me-beta" / "3.jsonl"]


def test_block_markers() -> None:
    assert is_hook_block("PreToolUse:Bash hook error: [x]: no")
    assert is_hook_block("PreToolUse:Write hook blocking error from command")
    assert is_hook_block("Hook PreToolUse:Bash denied this tool")
    assert not is_hook_block("Error: file not found")
