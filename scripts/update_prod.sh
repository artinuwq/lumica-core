#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage:
  update_prod.sh --service SERVICE --repo-dir PATH [options]

Required:
  --service NAME           systemd service name
  --repo-dir PATH          path to the production git checkout

Optional:
  --branch NAME            git branch to update from (default: main)
  --remote NAME            git remote to update from (default: origin)
  --python PATH            python binary for dependency install
  --skip-install           skip `pip install -r requirements.txt`
  --force-reset            reset branch to remote state after fetch
  --no-clean-check         allow local changes in the prod checkout
  --migration-cmd CMD      command to run after update, before start
  --start-timeout SEC      seconds to wait for service health (default: 30)
  -h, --help               show this help

Environment fallbacks:
  SERVICE_NAME, REPO_DIR, BRANCH, REMOTE, PYTHON_BIN,
  INSTALL_DEPS, FORCE_RESET, CHECK_CLEAN, MIGRATION_CMD, START_TIMEOUT

Examples:
  ./scripts/update_prod.sh --service lumica --repo-dir /opt/lumica-core
  ./scripts/update_prod.sh --service lumica --repo-dir /opt/lumica-core \
    --branch main --python /opt/lumica-core/.venv/bin/python
EOF
}

log() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fail() {
    log "ERROR: $*"
    exit 1
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "Required command is missing: $1"
    fi
}

SERVICE_NAME="${SERVICE_NAME:-}"
REPO_DIR="${REPO_DIR:-}"
BRANCH="${BRANCH:-main}"
REMOTE="${REMOTE:-origin}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_DEPS="${INSTALL_DEPS:-1}"
FORCE_RESET="${FORCE_RESET:-0}"
CHECK_CLEAN="${CHECK_CLEAN:-1}"
MIGRATION_CMD="${MIGRATION_CMD:-}"
START_TIMEOUT="${START_TIMEOUT:-30}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service)
            SERVICE_NAME="${2:-}"
            shift 2
            ;;
        --repo-dir)
            REPO_DIR="${2:-}"
            shift 2
            ;;
        --branch)
            BRANCH="${2:-}"
            shift 2
            ;;
        --remote)
            REMOTE="${2:-}"
            shift 2
            ;;
        --python)
            PYTHON_BIN="${2:-}"
            shift 2
            ;;
        --skip-install)
            INSTALL_DEPS="0"
            shift
            ;;
        --force-reset)
            FORCE_RESET="1"
            shift
            ;;
        --no-clean-check)
            CHECK_CLEAN="0"
            shift
            ;;
        --migration-cmd)
            MIGRATION_CMD="${2:-}"
            shift 2
            ;;
        --start-timeout)
            START_TIMEOUT="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "Unknown argument: $1"
            ;;
    esac
done

[[ -n "$SERVICE_NAME" ]] || fail "--service is required"
[[ -n "$REPO_DIR" ]] || fail "--repo-dir is required"
[[ -d "$REPO_DIR" ]] || fail "Repo directory does not exist: $REPO_DIR"
[[ "$START_TIMEOUT" =~ ^[0-9]+$ ]] || fail "--start-timeout must be a non-negative integer"

require_command git
require_command systemctl

if [[ "$INSTALL_DEPS" == "1" ]]; then
    require_command "$PYTHON_BIN"
fi

SERVICE_STOPPED="0"

restore_service_on_error() {
    local exit_code="$?"
    if [[ "$SERVICE_STOPPED" == "1" ]]; then
        log "Update failed. Attempting to start $SERVICE_NAME back up."
        systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}

trap restore_service_on_error ERR

cd "$REPO_DIR"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "Repo directory is not a git checkout: $REPO_DIR"

if [[ "$CHECK_CLEAN" == "1" ]] && [[ -n "$(git status --short)" ]]; then
    fail "Working tree is not clean. Commit or remove local changes, or rerun with --no-clean-check."
fi

log "Stopping service: $SERVICE_NAME"
systemctl stop "$SERVICE_NAME"
SERVICE_STOPPED="1"

log "Fetching updates from $REMOTE/$BRANCH"
git fetch --prune "$REMOTE"

current_branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$current_branch" != "$BRANCH" ]]; then
    log "Checking out branch: $BRANCH"
    if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
        git checkout "$BRANCH"
    else
        git checkout -b "$BRANCH" "${REMOTE}/${BRANCH}"
    fi
fi

if [[ "$FORCE_RESET" == "1" ]]; then
    log "Resetting branch to ${REMOTE}/${BRANCH}"
    git reset --hard "${REMOTE}/${BRANCH}"
else
    log "Pulling latest commits"
    git pull --ff-only "$REMOTE" "$BRANCH"
fi

if [[ "$INSTALL_DEPS" == "1" ]] && [[ -f requirements.txt ]]; then
    log "Installing Python dependencies"
    "$PYTHON_BIN" -m pip install -r requirements.txt
fi

if [[ -n "$MIGRATION_CMD" ]]; then
    log "Running migration command"
    eval "$MIGRATION_CMD"
fi

trap - ERR

log "Starting service: $SERVICE_NAME"
systemctl start "$SERVICE_NAME"
SERVICE_STOPPED="0"

log "Waiting for service health"
for ((second = 0; second < START_TIMEOUT; second += 1)); do
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Service is active"
        exit 0
    fi
    sleep 1
done

systemctl status "$SERVICE_NAME" --no-pager || true
fail "Service did not become active within ${START_TIMEOUT}s"
