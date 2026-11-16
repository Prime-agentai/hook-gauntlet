#!/usr/bin/env python3
"""The same policy as naive_guard.py, written to survive `gauntlet fuzz`.

Instead of matching the raw string it tokenizes the command with shlex, splits it on
shell operators, unwraps `bash -c` / `sh -c` / `eval`, strips `env`, `command`,
backslashes, absolute paths and simple `X=prog; $X` indirection, and then checks the
*program and its flags* rather than their spelling. File tools are checked on the
normalized basename, so `./.env` and `a/../a/.env` are the same file as `.env`.

It answers with JSON (`permissionDecision: deny`) rather than exit 2, which also shows
that hook-gauntlet speaks both halves of the hook protocol.
"""

import json
import os.path
import re
import shlex
import sys

WRAPPERS = {"env", "command", "builtin", "exec", "nohup", "time", "sudo"}
SHELLS = {"bash", "sh", "zsh", "dash"}
SECRET_NAMES = re.compile(r"^\.env(\..*)?$|^id_(rsa|ed25519|ecdsa)$|^credentials$")
SECRET_ALLOW = {".env.example", ".env.sample", ".env.template"}


def deny(reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


def split_commands(cmd: str) -> list[list[str]]:
    # Newline is a command separator too, but only outside quotes: make it punctuation.
    lexer = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>\n")
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.whitespace = " \t\r"
    try:
        tokens = list(lexer)
    except ValueError:
        return [cmd.split()]
    out: list[list[str]] = [[]]
    for tok in tokens:
        if tok and set(tok) <= set(";&|()<>\n"):
            out.append([])
        elif tok in ("{", "}", "!") and not out[-1]:
            continue  # grouping / negation keywords are not programs
        else:
            out[-1].append(tok)
    return [c for c in out if c]


def normalize(words: list[str], variables: dict[str, str]) -> list[str]:
    words = list(words)
    while words:
        head = words[0]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", head):
            name, _, value = head.partition("=")
            variables[name] = value
            words = words[1:]
            continue
        if head.startswith("$"):
            words[0] = variables.get(head.lstrip("${").rstrip("}"), head)
            if words[0] == head:
                break
            continue
        base = os.path.basename(head.lstrip("\\"))
        if base in WRAPPERS:
            words = words[1:]
            continue
        words[0] = base
        break
    return words


def check_words(words: list[str], variables: dict[str, str], depth: int = 0) -> None:
    words = normalize(words, variables)
    if not words:
        return
    prog, args = words[0], words[1:]
    if prog in SHELLS and "-c" in args and depth < 5:
        i = args.index("-c")
        if i + 1 < len(args):
            check_command(args[i + 1], depth + 1)
        return
    if prog == "eval" and depth < 5:
        check_command(" ".join(args), depth + 1)
        return
    if prog == "rm":
        short = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        recursive = "r" in short or "R" in short or "--recursive" in args
        force = "f" in short or "--force" in args
        if recursive and force:
            deny("recursive force delete")
    if prog == "git":
        rest = [a for a in args]
        while rest and rest[0].startswith("-"):
            rest = rest[2:] if rest[0] in ("-C", "-c") else rest[1:]
        if rest[:1] == ["push"] and any(a in ("-f", "--force") or (a.startswith("-") and not a.startswith("--") and "f" in a) for a in rest[1:]):
            deny("force push")
        if rest[:1] == ["reset"] and "--hard" in rest:
            deny("hard reset")
    if prog == "chmod" and ("-R" in args or "--recursive" in args) and "777" in args:
        deny("world-writable tree")
    for a in args:
        if SECRET_NAMES.match(os.path.basename(a)) and os.path.basename(a) not in SECRET_ALLOW:
            deny("secret file")


HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n(.*?)^\s*\2\s*$", re.S | re.M)
FEEDS_SHELL = re.compile(r"(^|[;&|(\s])(\S*/)?(ba|z|da)?sh(\s+-s)?\s*$")


def strip_heredocs(cmd: str, depth: int) -> str:
    """A heredoc body fed to a program is data: keep the redirect, drop the body.

    The exception is a body fed to a shell (`bash <<EOF`), which is code and is checked.
    (`gauntlet replay` on real history showed heredocs are the biggest false-positive source.)
    """
    def repl(m: "re.Match[str]") -> str:
        line_start = cmd.rfind("\n", 0, m.start()) + 1
        if FEEDS_SHELL.search(cmd[line_start:m.start()].rstrip()) and depth < 5:
            check_command(m.group(3), depth + 1)
        return "<<" + m.group(2) + "\n"
    return HEREDOC.sub(repl, cmd)


def check_command(cmd: str, depth: int = 0) -> None:
    cmd = strip_heredocs(cmd, depth)
    variables: dict[str, str] = {}
    commands = split_commands(cmd)
    # Judge programs after normalization, never the raw spelling (c''url is curl).
    shared: dict[str, str] = {}
    progs = [(normalize(w, shared) or [""])[0] for w in commands]
    fetched = [i for i, p in enumerate(progs) if p in ("curl", "wget")]
    if fetched and any(p in SHELLS for p in progs[fetched[0] + 1:]):
        deny("pipe to shell")
    for words in commands:
        check_words(words, variables, depth)


payload = json.load(sys.stdin)
tool = payload.get("tool_name")
ti = payload.get("tool_input", {})
if tool == "Bash":
    check_command(ti.get("command", ""))
elif tool in ("Read", "Write", "Edit", "MultiEdit"):
    name = os.path.basename(os.path.normpath(ti.get("file_path", "")))
    if SECRET_NAMES.match(name) and name not in SECRET_ALLOW:
        deny("secret file")
sys.exit(0)
