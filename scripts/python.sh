#!/usr/bin/env bash
# Invoke the project interpreter from any working directory.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ -n "${KEETA_PYTHON:-}" ]]; then
  task_python="$KEETA_PYTHON"
elif [[ -x .venv/bin/python ]]; then
  task_python=.venv/bin/python
elif [[ -f .private/python_path ]]; then
  task_python="$(cat .private/python_path)"
else
  task_python=python3
fi
exec "$task_python" "$@"
