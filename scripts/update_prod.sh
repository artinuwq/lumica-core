#!/usr/bin/env bash
# Thin wrapper: manual "prod update" entrypoint for operators on the box.
# All logic lives in lumica.update.UpdateManager (see src/lumica/update/) -
# this script never reimplements checkout/restart itself, so it can never
# drift from what /update in Telegram or POST /api/update do.
#
# Usage (normally via the `lumica` command installed by install.sh):
#   sudo lumica status
#   sudo lumica update [--force] [--no-restart]
#   sudo lumica rollback [--restore-db]
#   sudo lumica restart
#
# When started as root, re-executes itself as the user that owns the checkout,
# so git/pip never leave root-owned files behind in the install directory.

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -eq 0 ]]; then
    OWNER="$(stat -c '%U' "$ROOT_DIR")"
    if [[ "$OWNER" != "root" ]] && id -u "$OWNER" >/dev/null 2>&1; then
        OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
        exec runuser -u "$OWNER" -- env HOME="$OWNER_HOME" /bin/bash "${BASH_SOURCE[0]}" "$@"
    fi
fi

PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN="python3"

cd "$ROOT_DIR"
export PYTHONPATH="${ROOT_DIR}/src:${ROOT_DIR}:${PYTHONPATH:-}"
exec "$PYTHON_BIN" -m lumica.update.cli "$@"
