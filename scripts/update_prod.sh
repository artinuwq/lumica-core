#!/usr/bin/env bash
# Thin wrapper: manual "prod update" entrypoint for operators on the box.
# All logic lives in lumica.update.UpdateManager (see src/lumica/update/) -
# this script never reimplements checkout/restart itself, so it can never
# drift from what /update in Telegram or POST /api/update do.
#
# Usage:
#   ./scripts/update_prod.sh status
#   ./scripts/update_prod.sh update [--force]
#   ./scripts/update_prod.sh restart

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN="python3"

cd "$ROOT_DIR"
export PYTHONPATH="${ROOT_DIR}/src:${ROOT_DIR}:${PYTHONPATH:-}"
exec "$PYTHON_BIN" -m lumica.update.cli "$@"
