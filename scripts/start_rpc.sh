#!/usr/bin/env bash
set -euo pipefail
exec "$(dirname -- "$0")/python.sh" -m rpc "$@"
