# Changelog

## 0.1.0 (2026-11-16)

First release.

- `gauntlet replay`: replays your real Claude Code tool-call history (`~/.claude/projects/**/*.jsonl`) through your PreToolUse hooks. It lists every call they would deny, ask about or crash on, with occurrence counts, hook latency (p50/p95/max) and a comparison with what was blocked at the time. `--save-corpus` / `--corpus` turn history into a reusable CI fixture, and `--fail-if-blocks` gates on a benign corpus. Credential-like strings are masked in output by default.
- `gauntlet fuzz`: 26 bash operators and 5 path operators that rewrite a call without changing what it does (`r''m`, `bash -c`, `-rf` to `-r -f`, `$HOME`, `/./`, `git -C .`, ...), composed up to `--depth N`. It reports seeds your hook does not cover and every mutant that slips through. Built-in seed packs: destructive, git, secrets, network. GNU-only operators are platform-aware (`--coreutils auto|gnu|bsd`).
- `gauntlet diff`: shows the decisions that change between two hook versions over the same corpus. Use either `--old-hook/--new-hook` or `--against <git rev>`, which materializes the hook's directory at that revision. Changes are grouped as newly blocked, newly allowed and other.
- `gauntlet test`: TOML cases with `expect = deny|ask|defer|allow|none|pass|block`, optional `mutate = true` and `reason_contains`, and JUnit XML output.
- `gauntlet check` runs one call through every hook. `gauntlet hooks` lists the hooks Claude Code would load from user, project and local settings, with `matcher` and `if` rule semantics.
- Implements the documented hook protocol: exit 2, JSON `permissionDecision`, legacy `decision`, `continue:false`, `updatedInput`, `onFailure: block`, timeouts, and exec-form `args` with `${CLAUDE_PROJECT_DIR}`. When several hooks answer, the most restrictive decision wins.
- `--isolate-home` runs hooks with a throwaway `HOME`, so hooks that log under `~` do not write into yours.
- Stdlib only, Python 3.11+, `mypy --strict` clean.
