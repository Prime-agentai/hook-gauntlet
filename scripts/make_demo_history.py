#!/usr/bin/env python3
"""Regenerate examples/history/demo-session.jsonl: a small, synthetic transcript in Claude Code's shape.

Synthetic on purpose: a real transcript would leak paths, usernames and prompts.
The one credential-looking value is fake (it exists to show `replay` masking it).
"""

import json
from pathlib import Path

CALLS: list[tuple[str, dict[str, str]]] = [
    ("Bash", {"command": "git status"}),
    ("Bash", {"command": "ls -la src"}),
    ("Read", {"file_path": "/home/dev/app/README.md"}),
    ("Bash", {"command": "python -m pytest -q"}),
    ("Bash", {"command": "python -m pytest -q"}),
    ("Bash", {"command": "python -m pytest -q"}),
    ("Bash", {"command": "grep -rn 'rm -rf' scripts/"}),
    ("Bash", {"command": "rm -rf build/ dist/"}),
    ("Bash", {"command": "git commit -m 'docs: explain the .env setup'"}),
    ("Read", {"file_path": "/home/dev/app/.env.example"}),
    ("Write", {"file_path": "/home/dev/app/docs/setup.md", "content": "Copy the example file and fill it in."}),
    ("Bash", {"command": "python scripts/check_config.py --template .env.example"}),
    ("Bash", {"command": "git push origin feature/login"}),
    ("Bash", {"command": "npm run build && npm test"}),
    ("Edit", {"file_path": "/home/dev/app/src/app.py", "old_string": "a", "new_string": "b"}),
    ("Bash", {"command": "OPENAI_API_KEY=sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE python run.py"}),
]


def main() -> None:
    lines = []
    for i, (tool, ti) in enumerate(CALLS):
        tid = f"toolu_demo_{i:03d}"
        lines.append({
            "type": "assistant", "sessionId": "demo-session", "cwd": "/home/dev/app", "isSidechain": False,
            "timestamp": f"2026-11-01T10:{i:02d}:00Z",
            "message": {"role": "assistant", "content": [{"type": "tool_use", "id": tid, "name": tool, "input": ti}]},
        })
        blocked = tool == "Bash" and ti["command"].startswith("rm -rf")
        text = "PreToolUse:Bash hook error: [python3 guard.py]: Blocked: recursive force delete" if blocked else "ok"
        lines.append({
            "type": "user", "sessionId": "demo-session",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": tid, "is_error": blocked, "content": text}]},
        })
    out = Path(__file__).resolve().parent.parent / "examples" / "history" / "demo-session.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(CALLS)} tool calls)")


if __name__ == "__main__":
    main()
