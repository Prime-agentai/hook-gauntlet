"""Semantics-preserving mutations of tool calls, used to find guard bypasses.

Every operator rewrites a call into one that does *the same thing* (for bash, or for
the filesystem) but looks different to a string-matching guard. If the guard denies
the original and lets a mutant through, that mutant is a bypass.

Operators that only hold for some programs are gated on the program name (flag
splitting is only applied to getopt-style tools like ``rm``/``chmod``/``git``), and
operators whose equivalence depends on GNU behaviour are marked ``gnu`` in their
description. We would rather miss a bypass than report a fake one.
"""

from __future__ import annotations

import re
import shlex
import shutil
from collections.abc import Callable
from dataclasses import dataclass, replace

from .model import ToolCall

BashOp = Callable[[str], "str | None"]

SHELL_BUILTINS = frozenset(
    {"cd", "echo", "eval", "exec", "export", "source", ".", "set", "unset", "alias", "read", "printf", "test", "[", "true", "false", ":"}
)
GETOPT_PROGRAMS = frozenset({"rm", "cp", "mv", "chmod", "chown", "chgrp", "ln", "mkdir", "rmdir", "shred", "kill", "pkill", "git"})
LONG_FLAGS: dict[str, dict[str, str]] = {
    "rm": {"r": "--recursive", "R": "--recursive", "f": "--force", "v": "--verbose", "d": "--dir"},
    "cp": {"r": "--recursive", "R": "--recursive", "f": "--force"},
    "mv": {"f": "--force"},
    "chmod": {"R": "--recursive"},
    "chown": {"R": "--recursive"},
    "git push": {"f": "--force"},
    "git clean": {"f": "--force", "d": "-d", "x": "-x"},
}
_CASE_SWAP = {"rm": {"r": "R", "R": "r"}, "cp": {"r": "R", "R": "r"}}
_OPERATOR_CHARS = set("|&;<>()`$\n")
_HEAD = re.compile(r"^(\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*)([A-Za-z0-9_./+-]+)(?=\s|$)")


@dataclass(frozen=True)
class Mutant:
    op: str
    call: ToolCall


# --------------------------------------------------------------------------- helpers


def _head(cmd: str) -> tuple[str, str, str] | None:
    """Split ``cmd`` into (env-assignment prefix, program word, rest) when it starts plainly."""
    m = _HEAD.match(cmd)
    if not m:
        return None
    return m.group(1), m.group(2), cmd[m.end():]


def _program(cmd: str) -> str | None:
    h = _head(cmd)
    return h[1].rsplit("/", 1)[-1] if h else None


def _is_simple(cmd: str) -> bool:
    """No pipes, redirects, chaining, substitutions or quotes we would have to reason about."""
    return not (set(cmd) & _OPERATOR_CHARS) and "'" not in cmd and '"' not in cmd and "\\" not in cmd


def _words(cmd: str) -> list[str]:
    return cmd.split()


def _subcommand_key(words: list[str]) -> str:
    prog = words[0].rsplit("/", 1)[-1]
    if prog == "git":
        sub = next((w for w in words[1:] if not w.startswith("-")), "")
        return f"git {sub}".strip()
    return prog


def _replace_word(cmd: str, old: str, new: str) -> str | None:
    pat = re.compile(r"(?<!\S)" + re.escape(old) + r"(?!\S)")
    if not pat.search(cmd):
        return None
    return pat.sub(lambda _m: new, cmd, count=1)


def _short_flag_words(words: list[str]) -> list[str]:
    return [w for w in words[1:] if re.fullmatch(r"-[A-Za-z]{2,}", w)]


# --------------------------------------------------------------------------- bash operators


def op_env_prefix(cmd: str) -> str | None:
    h = _head(cmd)
    if not h or h[1] in SHELL_BUILTINS:
        return None
    return f"{h[0]}env {h[1]}{h[2]}"


def op_command_prefix(cmd: str) -> str | None:
    h = _head(cmd)
    return f"{h[0]}command {h[1]}{h[2]}" if h and h[1] not in (":", ".") else None


def op_backslash(cmd: str) -> str | None:
    h = _head(cmd)
    return f"{h[0]}\\{h[1]}{h[2]}" if h and "/" not in h[1] else None


def op_quote_split(cmd: str) -> str | None:
    h = _head(cmd)
    if not h or len(h[1]) < 2 or "/" in h[1]:
        return None
    w = h[1]
    return f"{h[0]}{w[0]}''{w[1:]}{h[2]}"


def op_abs_path(cmd: str) -> str | None:
    h = _head(cmd)
    if not h or "/" in h[1] or h[1] in SHELL_BUILTINS:
        return None
    path = shutil.which(h[1])
    return f"{h[0]}{path}{h[2]}" if path else None


def op_var_indirection(cmd: str) -> str | None:
    h = _head(cmd)
    if not h or h[0].strip() or h[1] in SHELL_BUILTINS:
        return None
    return f"_g={h[1]}; $_g{h[2]}"


def op_bash_c(cmd: str) -> str:
    return "bash -c " + shlex.quote(cmd)


def op_sh_c(cmd: str) -> str:
    return "sh -c " + shlex.quote(cmd)


def op_eval(cmd: str) -> str:
    return "eval " + shlex.quote(cmd)


def op_chain_prefix(cmd: str) -> str:
    return "true && " + cmd


def op_semicolon_prefix(cmd: str) -> str:
    return ": ; " + cmd


def op_newline_prefix(cmd: str) -> str:
    return ":\n" + cmd


def op_subshell(cmd: str) -> str:
    return "( " + cmd + " )"


def op_brace_group(cmd: str) -> str:
    return "{ " + cmd + "; }"


def op_tab_separator(cmd: str) -> str | None:
    if not _is_simple(cmd) or " " not in cmd.strip():
        return None
    return "\t".join(_words(cmd))


def op_double_space(cmd: str) -> str | None:
    if not _is_simple(cmd) or " " not in cmd.strip():
        return None
    return "  ".join(_words(cmd))


def op_flag_split(cmd: str) -> str | None:
    if not _is_simple(cmd) or _program(cmd) not in GETOPT_PROGRAMS:
        return None
    flags = _short_flag_words(_words(cmd))
    if not flags:
        return None
    return _replace_word(cmd, flags[0], " ".join("-" + c for c in flags[0][1:]))


def op_flag_reorder(cmd: str) -> str | None:
    if not _is_simple(cmd) or _program(cmd) not in GETOPT_PROGRAMS:
        return None
    flags = _short_flag_words(_words(cmd))
    if not flags or len(set(flags[0][1:])) < 2:
        return None
    return _replace_word(cmd, flags[0], "-" + flags[0][1:][::-1])


def op_flag_long(cmd: str) -> str | None:
    if not _is_simple(cmd):
        return None
    words = _words(cmd)
    table = LONG_FLAGS.get(_subcommand_key(words))
    if not table:
        return None
    for w in words[1:]:
        if re.fullmatch(r"-[A-Za-z]+", w) and all(c in table for c in w[1:]):
            longs: list[str] = []
            for c in w[1:]:
                if table[c] not in longs:
                    longs.append(table[c])
            return _replace_word(cmd, w, " ".join(longs))
    return None


def op_flag_case(cmd: str) -> str | None:
    if not _is_simple(cmd):
        return None
    swap = _CASE_SWAP.get(_program(cmd) or "")
    if not swap:
        return None
    for w in _words(cmd)[1:]:
        if re.fullmatch(r"-[A-Za-z]+", w) and any(c in swap for c in w[1:]):
            return _replace_word(cmd, w, "-" + "".join(swap.get(c, c) for c in w[1:]))
    return None


def op_flags_last(cmd: str) -> str | None:
    """GNU getopt permutes arguments: ``rm -rf x`` == ``rm x -rf``."""
    if not _is_simple(cmd) or _program(cmd) not in {"rm", "cp", "mv", "chmod", "chown"}:
        return None
    words = _words(cmd)
    flags = [w for w in words[1:] if w.startswith("-")]
    operands = [w for w in words[1:] if not w.startswith("-")]
    if not flags or not operands or "--" in words:
        return None
    return " ".join([words[0], *operands, *flags])


def op_end_of_options(cmd: str) -> str | None:
    if not _is_simple(cmd) or _program(cmd) not in {"rm", "cp", "mv", "chmod", "chown", "shred"}:
        return None
    words = _words(cmd)
    if "--" in words:
        return None
    for i, w in enumerate(words[1:], 1):
        if not w.startswith("-"):
            return " ".join([*words[:i], "--", *words[i:]])
    return None


def op_home_var(cmd: str) -> str | None:
    for w in _words(cmd):
        if w == "~":
            return _replace_word(cmd, w, "$HOME")
        if w.startswith("~/"):
            return _replace_word(cmd, w, '"$HOME"/' + w[2:])
    return None


def op_path_dot(cmd: str) -> str | None:
    for w in _words(cmd)[1:]:
        if re.fullmatch(r"/[A-Za-z0-9_.~/-]+", w) and w != "/":
            return _replace_word(cmd, w, "/." + w)
        if re.fullmatch(r"\.?[A-Za-z0-9_][A-Za-z0-9_./-]*", w) and not w.startswith("-") and "/" not in w and "." in w:
            return _replace_word(cmd, w, "./" + w)
    return None


def op_git_global_option(cmd: str) -> str | None:
    h = _head(cmd)
    if not h or h[1] != "git" or not h[2].startswith(" "):
        return None
    return f"{h[0]}git -C .{h[2]}"


@dataclass(frozen=True)
class Operator:
    name: str
    description: str
    fn: BashOp


BASH_OPERATORS: tuple[Operator, ...] = (
    Operator("env-prefix", "run through env: `env rm ...`", op_env_prefix),
    Operator("command-prefix", "`command rm ...` (skips aliases and functions)", op_command_prefix),
    Operator("backslash", "`\\rm ...` (skips aliases)", op_backslash),
    Operator("quote-split", "`r''m ...` (empty quotes inside the word)", op_quote_split),
    Operator("abs-path", "absolute program path from PATH: `/usr/bin/rm ...`", op_abs_path),
    Operator("var-indirection", "`_g=rm; $_g ...`", op_var_indirection),
    Operator("bash-c", "wrap in `bash -c '...'`", op_bash_c),
    Operator("sh-c", "wrap in `sh -c '...'` (POSIX commands)", op_sh_c),
    Operator("eval", "wrap in `eval '...'`", op_eval),
    Operator("chain-prefix", "`true && ...`", op_chain_prefix),
    Operator("semicolon-prefix", "`: ; ...`", op_semicolon_prefix),
    Operator("newline-prefix", "`:` then a newline", op_newline_prefix),
    Operator("subshell", "`( ... )`", op_subshell),
    Operator("brace-group", "`{ ...; }`", op_brace_group),
    Operator("tab-separator", "tabs instead of spaces", op_tab_separator),
    Operator("double-space", "two spaces between words", op_double_space),
    Operator("flag-split", "`-rf` -> `-r -f` (getopt tools)", op_flag_split),
    Operator("flag-reorder", "`-rf` -> `-fr` (getopt tools)", op_flag_reorder),
    Operator("flag-long", "`-rf` -> `--recursive --force`", op_flag_long),
    Operator("flag-case", "`rm -r` -> `rm -R`", op_flag_case),
    Operator("flags-last", "options after operands: `rm x -rf` (gnu)", op_flags_last),
    Operator("end-of-options", "insert `--` before operands", op_end_of_options),
    Operator("home-var", "`~` -> `$HOME`", op_home_var),
    Operator("path-dot", "`/etc/x` -> `/./etc/x`, `.env` -> `./.env`", op_path_dot),
    Operator("git-global-option", "`git push` -> `git -C . push`", op_git_global_option),
)


# --------------------------------------------------------------------------- file-path operators

PATH_FIELDS = ("file_path", "notebook_path")


def _path_variants(path: str, cwd: str | None) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    head, sep, base = path.rpartition("/")
    if sep:
        out.append(("path-dot-segment", f"{head}/./{base}"))
        out.append(("path-double-slash", f"{head}//{base}"))
        parent = head.rsplit("/", 1)[-1]
        if parent and parent not in (".", ".."):
            out.append(("path-parent-hop", f"{head}/../{parent}/{base}"))
    else:
        out.append(("path-dot-segment", f"./{path}"))
    if path.startswith("/") and cwd and path.startswith(cwd.rstrip("/") + "/"):
        out.append(("path-relative", "./" + path[len(cwd.rstrip("/")) + 1:]))
    elif not path.startswith("/") and cwd:
        out.append(("path-absolute", cwd.rstrip("/") + "/" + path.removeprefix("./")))
    return out


# --------------------------------------------------------------------------- driver


def mutate_once(call: ToolCall, operators: tuple[Operator, ...] = BASH_OPERATORS) -> list[Mutant]:
    seen = {call.key()}
    out: list[Mutant] = []

    def add(op: str, new_input: dict[str, object]) -> None:
        m = replace(call, tool_input=new_input, occurrences=1, historical=None, source=f"mutant:{op}")
        if m.key() not in seen:
            seen.add(m.key())
            out.append(Mutant(op, m))

    if call.tool_name == "Bash":
        cmd = call.tool_input.get("command")
        if isinstance(cmd, str) and cmd.strip():
            for op in operators:
                new = op.fn(cmd)
                if new is not None and new != cmd:
                    add(op.name, {**call.tool_input, "command": new})
    else:
        for fld in PATH_FIELDS:
            path = call.tool_input.get(fld)
            if isinstance(path, str) and path:
                for name, new_path in _path_variants(path, call.cwd):
                    add(name, {**call.tool_input, fld: new_path})
    return out


def mutate(call: ToolCall, *, depth: int = 1, limit: int = 500) -> list[Mutant]:
    """All distinct mutants up to ``depth`` composed operators (``op1+op2``)."""
    frontier = mutate_once(call)
    result = list(frontier)
    seen = {call.key(), *(m.call.key() for m in result)}
    for _ in range(depth - 1):
        nxt: list[Mutant] = []
        for parent in frontier:
            for child in mutate_once(parent.call):
                if child.call.key() in seen:
                    continue
                seen.add(child.call.key())
                nxt.append(Mutant(f"{parent.op}+{child.op}", replace(child.call, source=f"mutant:{parent.op}+{child.op}")))
        result.extend(nxt)
        frontier = nxt
        if len(result) >= limit:
            break
    return result[:limit]


def operator_names() -> list[str]:
    return [o.name for o in BASH_OPERATORS] + ["path-dot-segment", "path-double-slash", "path-parent-hop", "path-relative", "path-absolute"]
