#!/usr/bin/env python3
"""A typical first-draft PreToolUse safety hook: regexes over the raw command string.

It is deliberately ordinary: this is what most hooks in the wild look like. Run
`gauntlet fuzz --hook "python3 examples/hooks/naive_guard.py"` to see what slips past it,
and `gauntlet replay` to see what it blocks that it should not.
"""

import json
import re
import sys

RULES = [
    (r"\brm\s+-rf\b", "recursive force delete"),
    (r"git push (--force|-f)\b", "force push"),
    (r"git reset --hard", "hard reset"),
    (r"chmod -R 777", "world-writable tree"),
    (r"curl[^|]*\|\s*(ba)?sh", "pipe to shell"),
    (r"\.env\b", "dotenv file"),
]

payload = json.load(sys.stdin)
tool = payload.get("tool_name")
ti = payload.get("tool_input", {})
text = ti.get("command", "") if tool == "Bash" else ti.get("file_path", "")

for pattern, why in RULES:
    if re.search(pattern, text):
        print(f"Blocked: {why}", file=sys.stderr)
        sys.exit(2)
sys.exit(0)
