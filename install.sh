#!/usr/bin/env bash
# Lumica Core installer.
#
#   curl -fsSL https://raw.githubusercontent.com/<owner>/lumica-core/main/install.sh \
#     | sudo bash -s -- --token 'xxx' --admin-id 123456789
#
# Idempotent: safe to re-run. Re-running with a new --token/--admin-id
# updates only those keys in .env and leaves the rest untouched.

set -Eeuo pipefail

REPO_URL="${REPO_URL:-https://github.com/artinuwq/lumica-core.git}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/lumica-core}"
SERVICE_NAME="${SERVICE_NAME:-lumica}"
SERVICE_USER="${SERVICE_USER:-lumica}"

TOKEN="${TELEGRAM_BOT_TOKEN:-}"
ADMIN_IDS=()
OWNER_IDS=()
WEBAPP_URL="${WEBAPP_URL:-}"
FLASK_HOST="${FLASK_HOST:-0.0.0.0}"
FLASK_PORT="${FLASK_PORT:-8000}"
NON_INTERACTIVE="0"

usage() {
    cat <<'EOF'
Usage: install.sh [options]

  --repo-url URL         git repo to install from (default: this repo)
  --branch NAME           git branch (default: main)
  --install-dir PATH      target directory (default: /opt/lumica-core)
  --service NAME           systemd service name (default: lumica)
  --service-user NAME      system user the service runs as (default: lumica; created if missing)
  --token TOKEN             Telegram bot token (TELEGRAM_BOT_TOKEN)
  --admin-id ID              admin Telegram ID; repeatable
  --owner-id ID               owner Telegram ID; repeatable
  --webapp-url URL           Telegram mini app URL (WEBAPP_URL)
  --host HOST                 web bind host (default: 0.0.0.0)
  --port PORT                  web bind port (default: 8000)
  --non-interactive             fail instead of prompting for missing values
  -h, --help                     show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-url) REPO_URL="${2:?}"; shift 2 ;;
        --branch) BRANCH="${2:?}"; shift 2 ;;
        --install-dir) INSTALL_DIR="${2:?}"; shift 2 ;;
        --service) SERVICE_NAME="${2:?}"; shift 2 ;;
        --service-user) SERVICE_USER="${2:?}"; shift 2 ;;
        --token) TOKEN="${2:?}"; shift 2 ;;
        --admin-id) ADMIN_IDS+=("${2:?}"); shift 2 ;;
        --owner-id) OWNER_IDS+=("${2:?}"); shift 2 ;;
        --webapp-url) WEBAPP_URL="${2:?}"; shift 2 ;;
        --host) FLASK_HOST="${2:?}"; shift 2 ;;
        --port) FLASK_PORT="${2:?}"; shift 2 ;;
        --non-interactive) NON_INTERACTIVE="1"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
fail() { log "ERROR: $*"; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "run this script as root (sudo)"
command -v git >/dev/null 2>&1 || fail "git is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

prompt() {
    local var_name="$1" question="$2" default_value="${3:-}"
    if [[ -n "${!var_name}" ]]; then
        return
    fi
    if [[ "$NON_INTERACTIVE" == "1" ]]; then
        fail "missing required value: $question (pass it as a flag or env var, or drop --non-interactive)"
    fi
    if [[ ! -t 0 ]] && [[ ! -e /dev/tty ]]; then
        fail "missing required value: $question (no TTY to prompt on; pass it as a flag)"
    fi
    local answer
    read -r -p "$question ${default_value:+[$default_value] }" answer < /dev/tty
    printf -v "$var_name" '%s' "${answer:-$default_value}"
}

prompt TOKEN "Telegram bot token (TELEGRAM_BOT_TOKEN):"
if [[ "${#ADMIN_IDS[@]}" -eq 0 ]]; then
    if [[ "$NON_INTERACTIVE" == "1" ]]; then
        log "WARNING: no --admin-id passed; chat-ops (/update, /restart, /config) will be locked to no one until configured"
    elif [[ -t 0 || -e /dev/tty ]]; then
        read -r -p "Admin Telegram ID (leave empty to configure later): " admin_reply < /dev/tty || true
        [[ -n "${admin_reply:-}" ]] && ADMIN_IDS+=("$admin_reply")
    fi
fi

join_csv() {
    local IFS=','
    echo "$*"
}

log "Installing to $INSTALL_DIR (branch: $BRANCH, service: $SERVICE_NAME)"

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "Creating system user: $SERVICE_USER"
    useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Existing checkout found, updating in place"
    git -C "$INSTALL_DIR" fetch --prune origin
    git -C "$INSTALL_DIR" checkout "$BRANCH"
    git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
else
    log "Cloning $REPO_URL"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi

log "Setting up virtualenv"
if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
    python3 -m venv "$INSTALL_DIR/.venv"
fi
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

ENV_FILE="$INSTALL_DIR/.env"
touch "$ENV_FILE"

set_env() {
    local key="$1" value="$2"
    [[ -z "$value" ]] && return 0
    if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s#^${key}=.*#${key}=${value}#" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

random_secret() { python3 -c 'import secrets; print(secrets.token_hex(32))'; }

set_env "TELEGRAM_BOT_TOKEN" "$TOKEN"
[[ "${#ADMIN_IDS[@]}" -gt 0 ]] && set_env "ADMIN_TELEGRAM_IDS" "$(join_csv "${ADMIN_IDS[@]}")"
[[ "${#OWNER_IDS[@]}" -gt 0 ]] && set_env "OWNER_TELEGRAM_IDS" "$(join_csv "${OWNER_IDS[@]}")"
set_env "WEBAPP_URL" "$WEBAPP_URL"
set_env "FLASK_HOST" "$FLASK_HOST"
set_env "FLASK_PORT" "$FLASK_PORT"
set_env "UPDATE_BRANCH" "$BRANCH"
set_env "UPDATE_SERVICE_NAME" "$SERVICE_NAME"

# Auto-generate secrets only if not already present (never overwrite on re-run).
grep -qE '^SESSION_PEPPER=' "$ENV_FILE" || echo "SESSION_PEPPER=$(random_secret)" >> "$ENV_FILE"
grep -qE '^CSRF_PEPPER=' "$ENV_FILE" || echo "CSRF_PEPPER=$(random_secret)" >> "$ENV_FILE"

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 600 "$ENV_FILE"

log "Writing systemd unit: ${SERVICE_NAME}.service"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=Lumica Core (web + bot + scheduler)
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/scripts/run_all.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

log "Granting ${SERVICE_USER} passwordless sudo to restart only this unit (needed for /restart and /update from chat)"
cat > "/etc/sudoers.d/${SERVICE_NAME}-restart" <<SUDOERS
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl restart ${SERVICE_NAME}.service, /usr/bin/systemctl status ${SERVICE_NAME}.service
SUDOERS
chmod 440 "/etc/sudoers.d/${SERVICE_NAME}-restart"
visudo -cf "/etc/sudoers.d/${SERVICE_NAME}-restart" || fail "generated sudoers rule failed validation"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

log "Done. Service status:"
systemctl --no-pager status "$SERVICE_NAME" || true
