#!/usr/bin/env bash
# Lumica Core uninstaller.
#
#   sudo ./uninstall.sh --install-dir /opt/lumica-core --service lumica
#
# Without --yes and without a TTY, this refuses to run (safe default).

set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/lumica-core}"
SERVICE_NAME="${SERVICE_NAME:-lumica}"
SERVICE_USER="${SERVICE_USER:-lumica}"
KEEP_DATA="0"
ASSUME_YES="0"

usage() {
    cat <<'EOF'
Usage: uninstall.sh [options]

  --install-dir PATH   target directory to remove (default: /opt/lumica-core)
  --service NAME         systemd service name (default: lumica)
  --service-user NAME     system user to remove (default: lumica)
  --keep-data              keep database/ and .env, remove everything else
  --yes, -y                 skip confirmation prompt
  -h, --help                 show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir) INSTALL_DIR="${2:?}"; shift 2 ;;
        --service) SERVICE_NAME="${2:?}"; shift 2 ;;
        --service-user) SERVICE_USER="${2:?}"; shift 2 ;;
        --keep-data) KEEP_DATA="1"; shift ;;
        --yes|-y) ASSUME_YES="1"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
fail() { log "ERROR: $*"; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "run this script as root (sudo)"

if [[ "$ASSUME_YES" != "1" ]]; then
    if [[ ! -t 0 ]]; then
        fail "refusing to uninstall without --yes (no TTY to confirm on)"
    fi
    read -r -p "This will remove ${SERVICE_NAME}.service and ${INSTALL_DIR}$( [[ "$KEEP_DATA" == "1" ]] && echo ' (keeping database/ and .env)' ). Continue? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || fail "aborted"
fi

stop_unit() {
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -f "/etc/sudoers.d/${SERVICE_NAME}-restart"
    systemctl daemon-reload 2>/dev/null || true
}

log "Stopping and removing systemd unit: ${SERVICE_NAME}.service"
stop_unit

if [[ -d "$INSTALL_DIR" ]]; then
    if [[ "$KEEP_DATA" == "1" ]]; then
        log "Removing code/venv, keeping database/ and .env"
        find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 \
            ! -name "database" ! -name ".env" -exec rm -rf {} +
    else
        log "Removing $INSTALL_DIR"
        rm -rf "$INSTALL_DIR"
    fi
else
    log "$INSTALL_DIR does not exist, nothing to remove there"
fi

if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "Removing system user: $SERVICE_USER"
    userdel "$SERVICE_USER" 2>/dev/null || true
fi

log "Done."
