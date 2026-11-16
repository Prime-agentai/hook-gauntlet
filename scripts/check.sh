#!/usr/bin/env bash
# The whole offline gate: no network, no API key, no Claude Code needed.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"
PY="${PYTHON:-python3}"

echo "== compileall";  "$PY" -m compileall -q src tests examples scripts
if "$PY" -c "import mypy" 2>/dev/null; then
  echo "== mypy --strict"; "$PY" -m mypy --strict src/hook_gauntlet
else
  echo "== mypy not available, skipped"
fi
echo "== pytest"; "$PY" -m pytest -q
echo "== dogfood: example cases"; "$PY" -m hook_gauntlet test examples/cases.toml
echo "== dogfood: hardened guard survives fuzzing"
"$PY" -m hook_gauntlet fuzz --hook "$PY examples/hooks/hardened_guard.py" --pack all > /dev/null
echo "OK"
