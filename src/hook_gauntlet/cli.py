"""``gauntlet``: put your Claude Code hooks through real history, mutations and version diffs."""

from __future__ import annotations

import argparse
import atexit
import json
import os
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .cases import Case, CaseError, expectation_met, load_cases
from .config import ConfigError, discover
from .engine import RevisionError, Runner, hooks_at_revision, revision_workdir
from .matching import if_rule_supported
from .model import Hook, Outcome, ToolCall, Verdict
from .mutate import mutate
from .packs import PACKS, pack_calls
from .report import SYMBOL, latency_ms, one_line, redact, table, verdict_counts
from .transcripts import DEFAULT_ROOT, CorpusFilter, find_transcripts, load_corpus

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


class UsageError(Exception):
    pass


# --------------------------------------------------------------------------- shared options


def _add_hook_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("hooks under test")
    g.add_argument("--hook", action="append", default=[], metavar="CMD",
                   help="hook command to test (repeatable). Default: hooks from settings files")
    g.add_argument("--matcher", default=None, help="matcher for --hook hooks (default: all tools)")
    g.add_argument("--settings", action="append", default=[], type=Path, metavar="FILE",
                   help="read hooks from this settings.json (repeatable)")
    g.add_argument("--project-dir", type=Path, default=Path.cwd(),
                   help="project root: hook cwd and $CLAUDE_PROJECT_DIR (default: .)")
    g.add_argument("--no-user-settings", action="store_true", help="ignore ~/.claude/settings.json during discovery")
    g.add_argument("--timeout", type=float, default=30.0, help="per-hook time limit in seconds (default 30)")
    g.add_argument("-j", "--jobs", type=int, default=0, help="parallel hook runs (default: 2x CPUs, max 16)")
    g.add_argument("--isolate-home", action="store_true",
                   help="run hooks with HOME set to a throwaway temp dir (keeps hook logs out of ~)")


def _add_corpus_args(p: argparse.ArgumentParser, *, default_history: bool) -> None:
    g = p.add_argument_group("corpus (the tool calls to replay)")
    g.add_argument("--history", nargs="?", const=DEFAULT_ROOT, default=DEFAULT_ROOT if default_history else None,
                   type=Path, metavar="PATH",
                   help=f"Claude Code transcripts dir or .jsonl file (default: {DEFAULT_ROOT})")
    g.add_argument("--project", default=None, help="only transcripts whose project path contains this text")
    g.add_argument("--corpus", action="append", default=[], type=Path, metavar="FILE",
                   help="saved corpus JSONL (from --save-corpus); replaces --history")
    g.add_argument("--cases", type=Path, default=None, help="use the calls in a cases TOML as corpus")
    g.add_argument("--pack", action="append", default=[], help=f"built-in calls: {', '.join(sorted(PACKS))}, all")
    g.add_argument("--tools", default=None, help="comma-separated tool names to keep (e.g. Bash,Write)")
    g.add_argument("--since", default=None, help="only calls on/after this date (YYYY-MM-DD)")
    g.add_argument("--limit", type=int, default=None, help="at most N distinct calls")


def _resolve_hooks(args: argparse.Namespace, *, case_hooks: list[Hook] | None = None) -> list[Hook]:
    hooks: list[Hook] = [Hook(command=c, matcher=args.matcher, source="--hook") for c in args.hook]
    if args.settings:
        found, _ = discover(args.project_dir, explicit=args.settings)
        hooks.extend(found)
    if hooks:
        return hooks
    if case_hooks:
        return case_hooks
    found, _ = discover(args.project_dir, include_user=not args.no_user_settings)
    if not found:
        raise UsageError(
            "no PreToolUse command hooks found. Pass --hook 'python3 path/to/guard.py', "
            "--settings path/to/settings.json, or run inside a project with .claude/settings.json"
        )
    return found


def _runner(args: argparse.Namespace, hooks: list[Hook]) -> Runner:
    env: dict[str, str] | None = None
    if args.isolate_home:
        home = tempfile.mkdtemp(prefix="hook-gauntlet-home-")
        atexit.register(shutil.rmtree, home, True)
        env = {**os.environ, "HOME": home}
    return Runner(hooks, project_dir=args.project_dir.resolve(), jobs=args.jobs, timeout=args.timeout, env=env)


def _read_corpus_file(path: Path) -> list[ToolCall]:
    out: list[ToolCall] = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError as exc:
            raise UsageError(f"{path}:{n}: invalid JSON ({exc})") from exc
        if not isinstance(d, dict) or not isinstance(d.get("tool_name"), str) or not isinstance(d.get("tool_input"), dict):
            raise UsageError(f"{path}:{n}: need 'tool_name' and 'tool_input'")
        out.append(ToolCall(d["tool_name"], d["tool_input"], cwd=d.get("cwd"),
                            occurrences=int(d.get("occurrences", 1)), source=f"{path}:{n}"))
    return out


def _build_corpus(args: argparse.Namespace) -> list[ToolCall]:
    tools = frozenset(t.strip() for t in args.tools.split(",") if t.strip()) if args.tools else None
    since = datetime.fromisoformat(args.since) if args.since else None
    calls: list[ToolCall] = []
    if args.corpus:
        for f in args.corpus:
            calls.extend(_read_corpus_file(f))
    elif args.history is not None:
        files = find_transcripts(args.history, args.project)
        if not files and not (args.cases or args.pack):
            raise UsageError(f"no transcripts found under {args.history}")
        calls.extend(load_corpus(files, CorpusFilter(project=args.project, tools=tools, since=since)))
    if args.cases:
        _, cases = load_cases(args.cases)
        calls.extend(c.call for c in cases)
    if args.pack:
        calls.extend(pack_calls(args.pack))
    if tools is not None:
        calls = [c for c in calls if c.tool_name in tools]
    if args.limit:
        calls = calls[: args.limit]
    if not calls:
        raise UsageError("corpus is empty (check --history / --corpus / --cases / --pack / filters)")
    return calls


def _progress(enabled: bool) -> Any:
    if not enabled or not sys.stderr.isatty():
        return None

    def show(done: int, total: int) -> None:
        if done == total or done % 25 == 0:
            sys.stderr.write(f"\r  {done}/{total} calls")
            if done == total:
                sys.stderr.write("\r" + " " * 30 + "\r")
            sys.stderr.flush()

    return show


def _scrub(value: Any, enabled: bool) -> Any:
    if not enabled:
        return value
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _scrub(v, enabled) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, enabled) for v in value]
    return value


def _outcome_json(o: Outcome, *, do_redact: bool) -> dict[str, Any]:
    return {
        "tool_name": o.call.tool_name,
        "tool_input": _scrub(o.call.tool_input, do_redact),
        "occurrences": o.call.occurrences,
        "historical": o.call.historical,
        "source": o.call.source,
        "verdict": o.verdict.value,
        "reason": _scrub(o.reason, do_redact),
        "duration_ms": round(o.duration_s * 1000, 1),
        "hooks": [
            {
                "hook": r.hook.label,
                "verdict": r.verdict.value,
                "exit_code": r.exit_code,
                "timed_out": r.timed_out,
                "duration_ms": round(r.duration_s * 1000, 1),
            }
            for r in o.ran
        ],
    }


def _print_hooks_header(hooks: list[Hook]) -> None:
    print(f"hooks under test ({len(hooks)}):")
    for h in hooks:
        extra = f" matcher={h.matcher!r}" if h.matcher else ""
        extra += f" if={h.if_rule!r}" if h.if_rule else ""
        print(f"  - {h.label}{extra}")


# --------------------------------------------------------------------------- commands


def cmd_hooks(args: argparse.Namespace) -> int:
    paths = args.settings or None
    hooks, notes = discover(args.project_dir, explicit=paths, include_user=not args.no_user_settings, event=None)
    if not hooks:
        print("no command hooks found")
        return EXIT_OK
    rows = [["EVENT", "MATCHER", "IF", "TIMEOUT", "COMMAND", "SOURCE"]]
    for h in hooks:
        rule = h.if_rule or ""
        if rule and not if_rule_supported(rule):
            rule += " (approx)"
        rows.append([h.event, h.matcher or "*", rule or "-", f"{h.timeout:g}s", h.label, h.source])
    print(table(rows, indent=""))
    for n in notes:
        print(f"note: {n}")
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    hooks = _resolve_hooks(args)
    if args.input:
        try:
            tool_input = json.loads(args.input)
        except json.JSONDecodeError as exc:
            raise UsageError(f"--input is not JSON: {exc}") from exc
        if not isinstance(tool_input, dict):
            raise UsageError("--input must be a JSON object")
    elif args.value is None:
        raise UsageError("give a value (command / file path / url) or --input JSON")
    elif args.tool == "Bash":
        tool_input = {"command": args.value}
    elif args.tool in ("WebFetch",):
        tool_input = {"url": args.value, "prompt": ""}
    elif args.tool == "Write":
        tool_input = {"file_path": args.value, "content": ""}
    elif args.tool == "Edit":
        tool_input = {"file_path": args.value, "old_string": "", "new_string": ""}
    else:
        tool_input = {"file_path": args.value}
    call = ToolCall(args.tool, tool_input, cwd=str(args.project_dir.resolve()))
    outcome = _runner(args, hooks).evaluate(call)
    if args.json:
        print(json.dumps(_outcome_json(outcome, do_redact=False) | {
            "hooks": [{"hook": r.hook.label, "skipped": r.skipped, "verdict": r.verdict.value, "exit_code": r.exit_code,
                       "reason": r.reason, "stdout": r.stdout, "stderr": r.stderr,
                       "duration_ms": round(r.duration_s * 1000, 1)} for r in outcome.results]}, indent=2))
        return EXIT_OK
    print(f"{args.tool}: {one_line(call.summary(), 120, do_redact=False)}")
    for r in outcome.results:
        if r.skipped:
            print(f"  skip   {r.hook.label}  (matcher/if did not select it)")
            continue
        code = "timeout" if r.timed_out else f"exit {r.exit_code}"
        print(f"  {SYMBOL[r.verdict]}  {r.hook.label}  [{code}, {r.duration_s * 1000:.0f} ms]")
        if r.reason:
            print(f"         {one_line(r.reason, 160, do_redact=False)}")
        if r.updated_input is not None:
            print(f"         rewrites input -> {json.dumps(r.updated_input)[:160]}")
        if r.stops_session:
            print("         sets continue=false (stops the session)")
    print(f"=> {outcome.verdict.value.upper()}")
    return EXIT_OK


@dataclass
class CaseReport:
    case: Case
    outcome: Outcome
    ok: bool
    failed_mutants: list[tuple[str, Outcome]]
    mutants_tried: int


def cmd_test(args: argparse.Namespace) -> int:
    case_hooks, cases = load_cases(args.file)
    hooks = _resolve_hooks(args, case_hooks=case_hooks)
    runner = _runner(args, hooks)
    reports: list[CaseReport] = []
    base = runner.evaluate_all([c.call for c in cases])
    for case, outcome in zip(cases, base):
        failed: list[tuple[str, Outcome]] = []
        tried = 0
        if case.mutate:
            mutants = mutate(case.call, depth=args.depth)
            tried = len(mutants)
            for m, mo in zip(mutants, runner.evaluate_all([m.call for m in mutants])):
                if not expectation_met(case.expect, mo.verdict):
                    failed.append((m.op, mo))
        ok = case.satisfied_by(outcome.verdict, outcome.reason) and not failed
        reports.append(CaseReport(case, outcome, ok, failed, tried))

    if args.junit:
        _write_junit(args.junit, reports)
    if args.json:
        print(json.dumps([{
            "name": r.case.name, "ok": r.ok, "expect": r.case.expect, "verdict": r.outcome.verdict.value,
            "mutants_tried": r.mutants_tried,
            "failed_mutants": [{"op": op, "verdict": mo.verdict.value, "tool_input": mo.call.tool_input} for op, mo in r.failed_mutants],
        } for r in reports], indent=2))
    else:
        for r in reports:
            mark = "PASS" if r.ok else "FAIL"
            extra = f"  (+{r.mutants_tried} mutants)" if r.mutants_tried else ""
            print(f"{mark}  {r.case.name}  expect={r.case.expect} got={r.outcome.verdict.value}{extra}")
            if not r.case.satisfied_by(r.outcome.verdict, r.outcome.reason) and r.case.reason_contains:
                print(f"      reason {r.outcome.reason[:120]!r} lacks {r.case.reason_contains!r}")
            for op, mo in r.failed_mutants[: args.show]:
                print(f"      {mo.verdict.value:>5} via {op:<22} {one_line(mo.call.summary(), 90, do_redact=False)}")
            if len(r.failed_mutants) > args.show:
                print(f"      ... {len(r.failed_mutants) - args.show} more")
        n_failed = sum(not r.ok for r in reports)
        print(f"\n{len(reports) - n_failed}/{len(reports)} cases passed")
    return EXIT_OK if all(r.ok for r in reports) else EXIT_FINDINGS


def _write_junit(path: Path, reports: list[CaseReport]) -> None:
    suite = ET.Element("testsuite", name="hook-gauntlet", tests=str(len(reports)),
                       failures=str(sum(not r.ok for r in reports)))
    for r in reports:
        tc = ET.SubElement(suite, "testcase", classname="hooks", name=r.case.name)
        if not r.ok:
            lines = [f"expect={r.case.expect} got={r.outcome.verdict.value}"]
            lines += [f"{op}: {mo.verdict.value}: {mo.call.summary()}" for op, mo in r.failed_mutants]
            ET.SubElement(tc, "failure", message=lines[0]).text = "\n".join(lines)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def cmd_replay(args: argparse.Namespace) -> int:
    hooks = _resolve_hooks(args)
    calls = _build_corpus(args)
    if args.save_corpus:
        with args.save_corpus.open("w", encoding="utf-8") as fh:
            for c in calls:
                fh.write(json.dumps({"tool_name": c.tool_name, "tool_input": c.tool_input, "cwd": c.cwd,
                                     "occurrences": c.occurrences}) + "\n")
        print(f"saved {len(calls)} calls to {args.save_corpus} (raw inputs, not redacted: review before committing)",
              file=sys.stderr)
    outcomes = _runner(args, hooks).evaluate_all(calls, _progress(not args.json))
    do_redact = not args.no_redact
    show = {Verdict(v.strip()) for v in args.show.split(",") if v.strip()}

    if args.json:
        print(json.dumps({
            "calls": len(outcomes),
            "occurrences": sum(o.call.occurrences for o in outcomes),
            "verdicts": {v.value: n for v, n in verdict_counts(outcomes).items()},
            "latency_ms": {k: round(v, 1) for k, v in latency_ms(outcomes).items()},
            "outcomes": [_outcome_json(o, do_redact=do_redact) for o in outcomes if o.verdict in show],
        }, indent=2))
    else:
        _print_replay(outcomes, hooks, show, args.top, do_redact)

    blocked = [o for o in outcomes if o.verdict.blocks]
    return EXIT_FINDINGS if args.fail_if_blocks and blocked else EXIT_OK


def _print_replay(outcomes: list[Outcome], hooks: list[Hook], show: set[Verdict], top: int, do_redact: bool) -> None:
    _print_hooks_header(hooks)
    total_occ = sum(o.call.occurrences for o in outcomes)
    sessions = {o.call.session_id for o in outcomes if o.call.session_id}
    print(f"\nreplayed {len(outcomes)} distinct calls ({total_occ} total"
          + (f", {len(sessions)} sessions" if sessions else "") + ")\n")

    by_tool: dict[str, Counter[Verdict]] = defaultdict(Counter)
    for o in outcomes:
        by_tool[o.call.tool_name][o.verdict] += 1
    cols = [Verdict.DENY, Verdict.ASK, Verdict.DEFER, Verdict.ALLOW, Verdict.NONE, Verdict.ERROR]
    rows = [["TOOL", "CALLS", *(v.value for v in cols)]]
    for tool, c in sorted(by_tool.items(), key=lambda kv: -sum(kv[1].values())):
        rows.append([tool, str(sum(c.values())), *(str(c[v]) if c[v] else "." for v in cols)])
    print(table(rows))

    lat = latency_ms(outcomes)
    if lat:
        print(f"\nhook latency per call: p50 {lat['p50']:.0f} ms, p95 {lat['p95']:.0f} ms, max {lat['max']:.0f} ms")

    hist = [o for o in outcomes if o.call.historical == "blocked"]
    if hist:
        still = sum(o.verdict.blocks for o in hist)
        print(f"historically blocked by a hook: {len(hist)} calls, {still} still blocked, {len(hist) - still} now pass")

    for verdict, title in ((Verdict.DENY, "DENIED: review each one, any benign call here is a false positive"),
                           (Verdict.ASK, "ASK: would interrupt you with a prompt"),
                           (Verdict.DEFER, "DEFER"),
                           (Verdict.ERROR, "ERRORS: hook crashed or timed out (fails open)")):
        if verdict not in show:
            continue
        hits = sorted((o for o in outcomes if o.verdict == verdict), key=lambda o: -o.call.occurrences)
        if not hits:
            continue
        print(f"\n{title} ({len(hits)})")
        for o in hits[:top]:
            occ = f"x{o.call.occurrences}" if o.call.occurrences > 1 else ""
            print(f"  {o.call.tool_name:<6} {occ:>4}  {one_line(o.call.summary(), 96, do_redact=do_redact)}")
            if o.reason:
                print(f"               -> {one_line(o.reason, 90, do_redact=do_redact)}")
        if len(hits) > top:
            print(f"  ... {len(hits) - top} more (--top N, or --json)")


def cmd_fuzz(args: argparse.Namespace) -> int:
    case_hooks: list[Hook] = []
    seeds: list[ToolCall] = [ToolCall("Bash", {"command": s}, cwd=str(args.project_dir.resolve()), source="--seed")
                             for s in args.seed]
    if args.cases:
        case_hooks, cases = load_cases(args.cases)
        seeds.extend(c.call for c in cases if c.expect in ("deny", "block", "ask", "defer"))
    if args.pack or not seeds:
        seeds.extend(pack_calls(args.pack or ["all"]))
    hooks = _resolve_hooks(args, case_hooks=case_hooks)
    runner = _runner(args, hooks)

    seed_outcomes = runner.evaluate_all(seeds)
    covered = [o for o in seed_outcomes if o.verdict.blocks]
    uncovered = [o for o in seed_outcomes if not o.verdict.blocks]

    bypasses: list[tuple[Outcome, str, Outcome]] = []
    tried = 0
    for so in covered:
        mutants = mutate(so.call, depth=args.depth)
        tried += len(mutants)
        for m, mo in zip(mutants, runner.evaluate_all([m.call for m in mutants])):
            if mo.verdict.passes:
                bypasses.append((so, m.op, mo))

    if args.json:
        print(json.dumps({
            "seeds": len(seeds), "covered": len(covered), "mutants": tried,
            "uncovered": [o.call.summary() for o in uncovered],
            "bypasses": [{"seed": s.call.summary(), "op": op, "tool_name": mo.call.tool_name,
                          "tool_input": mo.call.tool_input, "verdict": mo.verdict.value} for s, op, mo in bypasses],
        }, indent=2))
    else:
        _print_hooks_header(hooks)
        print(f"\nseeds blocked: {len(covered)}/{len(seeds)}   mutants tried: {tried}   bypasses: {len(bypasses)}")
        if uncovered:
            print(f"\nNOT BLOCKED AT ALL ({len(uncovered)}): the hook does not cover these")
            for o in uncovered:
                print(f"  {o.call.tool_name:<6} {one_line(o.call.summary(), 100, do_redact=False)}")
        if bypasses:
            by_seed: dict[str, list[tuple[str, Outcome]]] = defaultdict(list)
            for s, op, mo in bypasses:
                by_seed[s.call.summary()].append((op, mo))
            print(f"\nBYPASSES ({len(bypasses)}): blocked as written, allowed after a meaning-preserving rewrite")
            for seed, items in by_seed.items():
                print(f"  seed: {one_line(seed, 100, do_redact=False)}")
                for op, mo in items[: args.show]:
                    print(f"    {op:<26} {one_line(mo.call.summary(), 90, do_redact=False)}")
                if len(items) > args.show:
                    print(f"    ... {len(items) - args.show} more (--show N, or --json)")
            ops = Counter(op.split("+")[-1] for _, op, _ in bypasses)
            print("\nbypasses by operator: " + ", ".join(f"{op} {n}" for op, n in ops.most_common()))
        elif covered:
            print("\nno bypasses found at this depth (try --depth 2)")
    failed = bool(bypasses) or (args.strict and bool(uncovered))
    return EXIT_FINDINGS if failed else EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    calls = _build_corpus(args)
    with revision_workdir() as tmp:
        if args.against:
            new_hooks = _resolve_hooks(args)
            try:
                old_hooks = hooks_at_revision(new_hooks, args.against, args.project_dir.resolve(), Path(tmp))
            except RevisionError as exc:
                raise UsageError(str(exc)) from exc
        else:
            if not args.old_hook or not args.new_hook:
                raise UsageError("give --against REV, or both --old-hook and --new-hook")
            old_hooks = [Hook(command=c, matcher=args.matcher, source="--old-hook") for c in args.old_hook]
            new_hooks = [Hook(command=c, matcher=args.matcher, source="--new-hook") for c in args.new_hook]
        old = _runner(args, old_hooks).evaluate_all(calls, _progress(not args.json))
        new = _runner(args, new_hooks).evaluate_all(calls, _progress(not args.json))

    changes = [(a, b) for a, b in zip(old, new) if a.verdict != b.verdict]
    newly_blocked = [(a, b) for a, b in changes if a.verdict.passes and b.verdict.blocks]
    newly_allowed = [(a, b) for a, b in changes if a.verdict.blocks and b.verdict.passes]
    other = [(a, b) for a, b in changes
             if not (a.verdict.passes and b.verdict.blocks) and not (a.verdict.blocks and b.verdict.passes)]
    do_redact = not args.no_redact

    if args.json:
        def row(a: Outcome, b: Outcome) -> dict[str, Any]:
            return {"tool_name": a.call.tool_name, "tool_input": _scrub(a.call.tool_input, do_redact),
                    "occurrences": a.call.occurrences, "old": a.verdict.value, "new": b.verdict.value,
                    "new_reason": _scrub(b.reason, do_redact)}
        print(json.dumps({"calls": len(calls), "changed": len(changes),
                          "newly_blocked": [row(a, b) for a, b in newly_blocked],
                          "newly_allowed": [row(a, b) for a, b in newly_allowed],
                          "other": [row(a, b) for a, b in other]}, indent=2))
    else:
        old_label = f"@{args.against}" if args.against else "old"
        print(f"{len(calls)} calls, {len(changes)} decisions changed ({old_label} -> new)")
        for title, group in (("NEWLY BLOCKED (check for false positives)", newly_blocked),
                             ("NEWLY ALLOWED (check for lost protection)", newly_allowed),
                             ("OTHER CHANGES", other)):
            if not group:
                continue
            print(f"\n{title}: {len(group)}")
            for a, b in sorted(group, key=lambda ab: -ab[0].call.occurrences)[: args.top]:
                occ = f"x{a.call.occurrences}" if a.call.occurrences > 1 else ""
                print(f"  {a.verdict.value:>5} -> {b.verdict.value:<5} {a.call.tool_name:<6} {occ:>4}  "
                      f"{one_line(a.call.summary(), 80, do_redact=do_redact)}")
            if len(group) > args.top:
                print(f"  ... {len(group) - args.top} more")

    fail_on = {"any": changes, "newly-allowed": newly_allowed, "newly-blocked": newly_blocked, "none": []}[args.fail_on]
    return EXIT_FINDINGS if fail_on else EXIT_OK


# --------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gauntlet",
        description="Test Claude Code hooks against your real history, mutated attacks, and their own previous version.",
    )
    p.add_argument("--version", action="version", version=f"hook-gauntlet {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("hooks", help="list the command hooks Claude Code would load here")
    s.add_argument("--settings", action="append", default=[], type=Path, metavar="FILE")
    s.add_argument("--project-dir", type=Path, default=Path.cwd())
    s.add_argument("--no-user-settings", action="store_true")
    s.set_defaults(func=cmd_hooks)

    s = sub.add_parser("check", help="run one tool call through the hooks and show every decision")
    s.add_argument("tool", help="tool name, e.g. Bash, Write, Edit, Read, WebFetch")
    s.add_argument("value", nargs="?", help="command (Bash), file path (file tools) or url (WebFetch)")
    s.add_argument("--input", help="full tool_input as JSON instead of VALUE")
    s.add_argument("--json", action="store_true")
    _add_hook_args(s)
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("test", help="run a TOML file of expected decisions (CI-friendly)")
    s.add_argument("file", type=Path)
    s.add_argument("--depth", type=int, default=1, help="mutation depth for cases with mutate=true")
    s.add_argument("--show", type=int, default=5, help="failing mutants shown per case")
    s.add_argument("--junit", type=Path, default=None, help="also write a JUnit XML report")
    s.add_argument("--json", action="store_true")
    _add_hook_args(s)
    s.set_defaults(func=cmd_test)

    s = sub.add_parser("replay", help="replay your real tool-call history through the hooks (false positives, latency)")
    _add_corpus_args(s, default_history=True)
    s.add_argument("--show", default="deny,ask,defer,error", help="verdict groups to list")
    s.add_argument("--top", type=int, default=25)
    s.add_argument("--save-corpus", type=Path, default=None, help="write the corpus as JSONL for reuse in CI")
    s.add_argument("--fail-if-blocks", action="store_true", help="exit 1 if any call is denied/asked (benign corpus gate)")
    s.add_argument("--no-redact", action="store_true", help="show credential-like strings unmasked")
    s.add_argument("--json", action="store_true")
    _add_hook_args(s)
    s.set_defaults(func=cmd_replay)

    s = sub.add_parser("fuzz", help="mutate blocked calls into equivalent forms and report what slips through")
    s.add_argument("--seed", action="append", default=[], metavar="CMD", help="Bash command the hook must block")
    s.add_argument("--cases", type=Path, default=None, help="use deny/ask cases from a TOML file as seeds")
    s.add_argument("--pack", action="append", default=[], help=f"built-in seeds: {', '.join(sorted(PACKS))}, all")
    s.add_argument("--depth", type=int, default=1, help="compose up to N operators (default 1)")
    s.add_argument("--show", type=int, default=8, help="bypasses shown per seed")
    s.add_argument("--strict", action="store_true", help="also fail when a seed is not blocked at all")
    s.add_argument("--json", action="store_true")
    _add_hook_args(s)
    s.set_defaults(func=cmd_fuzz)

    s = sub.add_parser("diff", help="compare decisions of two hook versions over the same corpus")
    s.add_argument("--against", metavar="REV", help="old version = the hook files at this git revision")
    s.add_argument("--old-hook", action="append", default=[], metavar="CMD")
    s.add_argument("--new-hook", action="append", default=[], metavar="CMD")
    s.add_argument("--fail-on", choices=["any", "newly-allowed", "newly-blocked", "none"], default="any")
    s.add_argument("--top", type=int, default=25)
    s.add_argument("--no-redact", action="store_true")
    s.add_argument("--json", action="store_true")
    _add_corpus_args(s, default_history=False)
    _add_hook_args(s)
    s.set_defaults(func=cmd_diff)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "diff" and not (args.history or args.corpus or args.cases or args.pack):
        args.history = DEFAULT_ROOT
    try:
        rc: int = args.func(args)
        return rc
    except (UsageError, ConfigError, CaseError, KeyError) as exc:
        msg = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        print(f"gauntlet: error: {msg}", file=sys.stderr)
        return EXIT_USAGE
    except BrokenPipeError:
        return EXIT_OK
