"""Run a corpus of tool calls through a set of hooks, in parallel."""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from .matching import selects
from .model import Hook, HookResult, Outcome, ToolCall, Verdict
from .protocol import build_payload, run_hook


class Runner:
    """Evaluates tool calls against hooks the way Claude Code's PreToolUse stage would."""

    def __init__(
        self,
        hooks: list[Hook],
        *,
        project_dir: Path,
        jobs: int = 0,
        timeout: float | None = 30.0,
        env: Mapping[str, str] | None = None,
        event: str = "PreToolUse",
        permission_mode: str = "default",
    ) -> None:
        self.hooks = hooks
        self.project_dir = project_dir
        self.jobs = jobs or min(16, (os.cpu_count() or 2) * 2)
        self.timeout = timeout
        self.env = env
        self.event = event
        self.permission_mode = permission_mode

    def evaluate(self, call: ToolCall) -> Outcome:
        payload = build_payload(call, event=self.event, cwd=str(self.project_dir), permission_mode=self.permission_mode)
        results: list[HookResult] = []
        for hook in self.hooks:
            if not selects(hook, call, self.event):
                results.append(HookResult(hook=hook, verdict=Verdict.NONE, skipped=True))
                continue
            results.append(
                run_hook(hook, payload, project_dir=str(self.project_dir), env=self.env, timeout=self.timeout)
            )
        return Outcome(call=call, results=results)

    def evaluate_all(
        self, calls: Iterable[ToolCall], progress: Callable[[int, int], None] | None = None
    ) -> list[Outcome]:
        items = list(calls)
        if not items:
            return []
        out: list[Outcome | None] = [None] * len(items)
        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            futures = {pool.submit(self.evaluate, c): i for i, c in enumerate(items)}
            done = 0
            for fut in futures:
                out[futures[fut]] = fut.result()
                done += 1
                if progress:
                    progress(done, len(items))
        return [o for o in out if o is not None]


# --------------------------------------------------------------------------- hook at a git revision


class RevisionError(Exception):
    pass


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)


def hooks_at_revision(hooks: list[Hook], rev: str, repo: Path, workdir: Path) -> list[Hook]:
    """Rewrite each hook so every git-tracked file it references is the version at ``rev``.

    The old files are written under ``workdir`` (same relative layout, whole directory of
    each referenced file), so a hook script that imports its siblings still finds them
    at that revision.
    """
    top = _git(["rev-parse", "--show-toplevel"], repo)
    if top.returncode != 0:
        raise RevisionError(f"{repo} is not inside a git repository")
    root = Path(top.stdout.decode().strip())
    if _git(["rev-parse", "--verify", "--quiet", rev + "^{commit}"], root).returncode != 0:
        raise RevisionError(f"unknown revision: {rev}")
    listing = _git(["ls-tree", "-r", "--name-only", rev], root)
    tracked = set(listing.stdout.decode().splitlines())
    materialized: set[str] = set()

    def materialize_dir(parent: str) -> None:
        if parent in materialized:
            return
        materialized.add(parent)
        prefix = "" if parent == "." else parent + "/"
        for name in tracked:
            if not name.startswith(prefix) or "/" in name[len(prefix):]:
                continue
            blob = _git(["show", f"{rev}:{name}"], root)
            if blob.returncode != 0:
                continue
            dest = workdir / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(blob.stdout)
            mode = _git(["ls-tree", rev, name], root).stdout.decode().split(" ", 1)[0]
            if mode == "100755":
                dest.chmod(0o755)

    def pin(token: str) -> str:
        expanded = token.replace("${CLAUDE_PROJECT_DIR}", str(repo)).replace("$CLAUDE_PROJECT_DIR", str(repo))
        p = Path(expanded)
        abs_p = p if p.is_absolute() else (repo / p)
        try:
            rel = abs_p.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return token
        if rel not in tracked:
            return token
        materialize_dir(str(Path(rel).parent))
        return str(workdir / rel)

    out: list[Hook] = []
    for h in hooks:
        if h.args is not None:
            out.append(replace(h, command=pin(h.command), args=tuple(pin(a) for a in h.args), source=f"{h.source}@{rev}"))
            continue
        try:
            tokens = shlex.split(h.command)
        except ValueError:
            out.append(replace(h, source=f"{h.source}@{rev}"))
            continue
        out.append(replace(h, command=shlex.join(pin(t) for t in tokens), source=f"{h.source}@{rev}"))
    return out


def revision_workdir() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix="hook-gauntlet-rev-")
