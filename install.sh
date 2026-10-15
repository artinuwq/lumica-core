#!/usr/bin/env bash
# Установщик Lumica Core.
#
#   curl -fsSL https://raw.githubusercontent.com/artinuwq/lumica-core/main/install.sh | sudo bash
#
# Токен бота и admin ID будут запрошены интерактивно. Неинтерактивно:
#
#   curl -fsSL https://raw.githubusercontent.com/artinuwq/lumica-core/main/install.sh \
#     | sudo bash -s -- --token 'xxx' --admin-id 123456789 --non-interactive
#
# Идемпотентен: повторный запуск НЕ трогает .env, секреты и БД (меняются только
# ключи, явно переданные флагами), обновляет unit-файлы и запускает безопасное
# обновление кода (с откатом при неудаче). Если первая установка не удалась,
# всё созданное ею удаляется.

set -Eeuo pipefail

REPO_URL="${REPO_URL:-https://github.com/artinuwq/lumica-core.git}"
BRANCH="${BRANCH:-}"                      # пусто = main для новой установки, не менять для существующей
INSTALL_DIR="${INSTALL_DIR:-/opt/lumica-core}"
SERVICE_NAME="${SERVICE_NAME:-lumica}"
SERVICE_USER="${SERVICE_USER:-lumica}"
CLI_PATH="${CLI_PATH:-/usr/local/bin/lumica}"

TOKEN="${TELEGRAM_BOT_TOKEN:-}"
ADMIN_IDS=()
OWNER_IDS=()
WEBAPP_URL="${WEBAPP_URL:-}"
OPERATOR_GROUP_READY=""
FLASK_HOST="${FLASK_HOST:-}"              # пусто = не менять (по умолчанию 0.0.0.0 только при первой установке)
FLASK_PORT="${FLASK_PORT:-}"              # пусто = не менять (по умолчанию 8000 только при первой установке)
NON_INTERACTIVE="0"

# Состояние для отката неудачной первой установки.
FRESH_INSTALL=0
INSTALL_OK=0
CREATED_DIR=0
CREATED_USER=0
WROTE_UNITS=0
LOG_FILE=""

usage() {
    cat <<'USAGE'
Использование: install.sh [опции]

  --repo-url URL        git-репозиторий (по умолчанию: этот проект)
  --branch NAME         ветка (по умолчанию: main)
  --install-dir PATH    каталог установки (по умолчанию: /opt/lumica-core)
  --service NAME        имя systemd-сервиса (по умолчанию: lumica)
  --service-user NAME   системный пользователь сервиса (по умолчанию: lumica, создаётся при отсутствии)
  --token TOKEN         токен Telegram-бота (TELEGRAM_BOT_TOKEN)
  --admin-id ID         Telegram ID администратора; можно несколько раз
  --owner-id ID         Telegram ID владельца; можно несколько раз
  --webapp-url URL      URL Telegram Mini App (WEBAPP_URL)
  --host HOST           адрес веб-сервера (по умолчанию при первой установке: 0.0.0.0)
  --port PORT           порт веб-сервера (по умолчанию при первой установке: 8000)
  --non-interactive     не задавать вопросов, при нехватке данных завершиться с ошибкой
  -h, --help            эта справка

После установки: `sudo lumica status|update|rollback|restart`
USAGE
}

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { log "ВНИМАНИЕ: $*" >&2; }
fail() { log "ОШИБКА: $*" >&2; exit 1; }

have_tty() { ( : </dev/tty ) 2>/dev/null; }

# ---------------------------------------------------------------- cleanup

cleanup() {
    local code=$?
    [[ "$INSTALL_OK" == "1" || "$FRESH_INSTALL" != "1" || "$code" -eq 0 ]] && return 0
    # Ещё ничего не создано (например, не прошла валидация ввода) - откатывать нечего.
    [[ "$WROTE_UNITS" == "1" || "$CREATED_DIR" != "0" || "$CREATED_USER" == "1" ]] || return 0
    log "Установка не завершена - удаляю всё, что было создано этим запуском..."
    if [[ "$WROTE_UNITS" == "1" ]]; then
        systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service" \
              "/etc/systemd/system/${SERVICE_NAME}-update.service" \
              "/etc/sudoers.d/${SERVICE_NAME}-restart" "$CLI_PATH"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    if [[ -n "$INSTALL_DIR" && "$INSTALL_DIR" != "/" ]]; then
        if [[ "$CREATED_DIR" == "1" ]]; then
            rm -rf "$INSTALL_DIR"
        elif [[ "$CREATED_DIR" == "2" ]]; then
            find "$INSTALL_DIR" -mindepth 1 -delete 2>/dev/null || true   # каталог был пустым и мог быть точкой монтирования
        fi
    fi
    if [[ "$CREATED_USER" == "1" ]]; then
        userdel -r "$SERVICE_USER" >/dev/null 2>&1 || true
    fi
    log "Система возвращена в исходное состояние. Подробности: ${LOG_FILE:-нет лога}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
trap 'log "ОШИБКА: команда завершилась с кодом $? (строка $LINENO): $BASH_COMMAND" >&2' ERR

# ---------------------------------------------------------------- helpers

run_as() {  # run_as CMD... - выполнить от пользователя сервиса (stdin закрыт: нельзя "съесть" скрипт из pipe)
    runuser -u "$SERVICE_USER" -- env HOME="$SERVICE_HOME" "$@" </dev/null
}

install_file() {  # install_file DEST MODE  (содержимое из stdin; атомарная замена)
    local dest="$1" mode="$2" tmp
    tmp="$(mktemp "${dest}.XXXXXX")"
    cat > "$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$dest"
}

env_has() { grep -qE "^${1}=.+" "$ENV_FILE" 2>/dev/null; }
env_get() { grep -E "^${1}=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d "\"'" || true; }

env_set() {  # env_set KEY VALUE - заменить/добавить один ключ, остальные строки не трогать
    [[ "$(env_get "$1")" == "$2" ]] && return 0   # значение уже такое - файл не трогаем
    python3 - "$ENV_FILE" "$1" "$2" <<'PY'
import pathlib, sys
path, key, value = sys.argv[1:4]
p = pathlib.Path(path)
lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
new = f'{key}="{value}"' if " " in value else f"{key}={value}"
for i, line in enumerate(lines):
    s = line.strip()
    if s and not s.startswith("#") and s.split("=", 1)[0].strip() == key:
        lines[i] = new
        break
else:
    lines.append(new)
p.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
    ENV_CHANGED=1
}

env_default() { env_has "$1" || env_set "$1" "$2"; }   # только если ключа ещё нет
random_secret() { python3 -c 'import secrets; print(secrets.token_hex(32))'; }
join_csv() { local IFS=','; echo "$*"; }

ask() {  # ask VAR "вопрос" - спросить через /dev/tty, если значение не задано
    local var="$1" question="$2" answer
    [[ -n "${!var}" ]] && return 0
    [[ "$NON_INTERACTIVE" == "1" ]] && fail "не задано: ${question} (передайте флагом или уберите --non-interactive)"
    have_tty || fail "не задано: ${question} (нет терминала для вопроса, передайте флагом)"
    read -r -p "$question " answer < /dev/tty
    printf -v "$var" '%s' "$answer"
}

health_ok() {
    python3 - "$1" <<'PY'
import sys, urllib.request
try:
    sys.exit(0 if urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/health", timeout=3).status == 200 else 1)
except Exception:
    sys.exit(1)
PY
}

wait_for_service() {  # active 6 секунд подряд и отвечает /health, до ~60 с
    local port stable=0 i
    port="$(env_get FLASK_PORT)"; port="${port:-8000}"
    for ((i = 0; i < 60; i++)); do
        if systemctl is-active --quiet "$SERVICE_NAME"; then stable=$((stable + 1)); else stable=0; fi
        if (( stable >= 6 )) && health_ok "$port"; then return 0; fi
        sleep 1
    done
    return 1
}

# --------------------------------------------------------------- preflight

preflight() {
    [[ "${EUID}" -eq 0 ]] || fail "запустите от root: curl -fsSL <url>/install.sh | sudo bash"
    [[ "$INSTALL_DIR" == /* ]] || fail "--install-dir должен быть абсолютным путём"
    [[ -d /run/systemd/system ]] || fail "systemd не обнаружен: установщик настраивает автозапуск через systemd"

    local missing=() cmd
    for cmd in git python3 useradd userdel runuser visudo systemctl; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if ((${#missing[@]})); then
        fail "не хватает: ${missing[*]}. На Debian/Ubuntu: apt install -y git python3 python3-venv sudo"
    fi

    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
        || fail "нужен Python 3.10+, найден $(python3 -V 2>&1)"
    python3 -c 'import venv, ensurepip' 2>/dev/null \
        || fail "не хватает модуля venv. На Debian/Ubuntu: apt install -y python3-venv"

    if [[ -e "$INSTALL_DIR" && ! -d "$INSTALL_DIR/.git" ]] && [[ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]]; then
        fail "$INSTALL_DIR существует и не является установкой Lumica Core - ничего не трогаю. Выберите другой --install-dir"
    fi

    log "Проверяю доступ к $REPO_URL ..."
    GIT_TERMINAL_PROMPT=0 timeout 30 git ls-remote --exit-code --heads "$REPO_URL" "${BRANCH:-main}" >/dev/null 2>&1 \
        || fail "не удалось связаться с $REPO_URL или в нём нет ветки '${BRANCH:-main}' (нет интернета / DNS / GitHub недоступен?)"
}

# ------------------------------------------------------------- install parts

write_systemd_and_sudo() {
    local systemctl_bin
    systemctl_bin="$(command -v systemctl)"

    WROTE_UNITS=1
    install_file "/etc/systemd/system/${SERVICE_NAME}.service" 644 <<UNIT
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

    # Отдельный oneshot-юнит для /update из Telegram и API: он живёт вне cgroup
    # основного сервиса, поэтому перезапуск сервиса не убивает само обновление,
    # и оно может проверить результат и откатиться.
    install_file "/etc/systemd/system/${SERVICE_NAME}-update.service" 644 <<UNIT
[Unit]
Description=Lumica Core updater (oneshot)

[Service]
Type=oneshot
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/bin/bash ${INSTALL_DIR}/scripts/update_prod.sh update
TimeoutStartSec=900
UNIT

    local sudoers_tmp
    # Временный файл рядом с целевым (атомарный mv); имена с точкой sudo игнорирует.
    sudoers_tmp="$(mktemp "/etc/sudoers.d/.${SERVICE_NAME}-restart.XXXXXX")"
    cat > "$sudoers_tmp" <<SUDOERS
${SERVICE_USER} ALL=(root) NOPASSWD: ${systemctl_bin} restart ${SERVICE_NAME}.service, ${systemctl_bin} start ${SERVICE_NAME}.service, ${systemctl_bin} stop ${SERVICE_NAME}.service, ${systemctl_bin} status ${SERVICE_NAME}.service, ${systemctl_bin} start --no-block ${SERVICE_NAME}-update.service
SUDOERS
    chmod 440 "$sudoers_tmp"
    # Сначала проверяем, потом кладём на место: битый sudoers.d ломает sudo целиком.
    if ! visudo -cf "$sudoers_tmp" >/dev/null; then
        rm -f "$sudoers_tmp"
        fail "сгенерированное правило sudoers не прошло проверку visudo"
    fi
    mv -f "$sudoers_tmp" "/etc/sudoers.d/${SERVICE_NAME}-restart"

    install_file "$CLI_PATH" 755 <<CLI
#!/usr/bin/env bash
# Команда управления Lumica Core: sudo lumica {status|update|rollback|restart}
if [[ "\${EUID}" -ne 0 && "\$(id -un)" != "\$(stat -c %U '${INSTALL_DIR}')" ]]; then
    echo "Запустите через sudo: sudo lumica \$*" >&2
    exit 1
fi
exec /bin/bash '${INSTALL_DIR}/scripts/update_prod.sh' "\$@"
CLI

    systemctl daemon-reload
}

configure_env() {
    ENV_CHANGED=0
    if [[ ! -f "$ENV_FILE" ]]; then
        ( umask 077; : > "$ENV_FILE" )
    fi
    chown "$SERVICE_USER:$SERVICE_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    # Явно переданные флаги перезаписывают значение; значения по умолчанию
    # ставятся только если ключа ещё нет; существующие настройки не трогаются.
    [[ -n "$TOKEN" ]] && env_set TELEGRAM_BOT_TOKEN "$TOKEN"
    [[ "${#ADMIN_IDS[@]}" -gt 0 ]] && env_set ADMIN_TELEGRAM_IDS "$(join_csv "${ADMIN_IDS[@]}")"
    [[ "${#OWNER_IDS[@]}" -gt 0 ]] && env_set OWNER_TELEGRAM_IDS "$(join_csv "${OWNER_IDS[@]}")"
    [[ -n "$WEBAPP_URL" ]] && env_set WEBAPP_URL "$WEBAPP_URL"
    if [[ -n "$FLASK_HOST" ]]; then env_set FLASK_HOST "$FLASK_HOST"; else env_default FLASK_HOST 0.0.0.0; fi
    if [[ -n "$FLASK_PORT" ]]; then env_set FLASK_PORT "$FLASK_PORT"; else env_default FLASK_PORT 8000; fi
    if [[ -n "$BRANCH" ]]; then env_set UPDATE_BRANCH "$BRANCH"; else env_default UPDATE_BRANCH main; fi
    env_set UPDATE_SERVICE_NAME "$SERVICE_NAME"   # должно совпадать с именем unit, который мы только что записали

    # Секреты генерируются один раз и никогда не перезаписываются.
    env_has SESSION_PEPPER || env_set SESSION_PEPPER "$(random_secret)"
    env_has CSRF_PEPPER || env_set CSRF_PEPPER "$(random_secret)"
    env_has PANEL_SECRET_KEY || env_set PANEL_SECRET_KEY "$(random_secret)"
}

fresh_install() {
    FRESH_INSTALL=1
    log "Новая установка в $INSTALL_DIR (ветка: ${BRANCH:-main})"

    # Данные для .env нужны до любых изменений в системе.
    ask TOKEN "Токен Telegram-бота (TELEGRAM_BOT_TOKEN):"
    if [[ ! "$TOKEN" =~ ^[0-9]{5,}:[A-Za-z0-9_-]{20,}$ ]]; then
        fail "токен не похож на токен Telegram-бота (ожидается вид 123456789:AAE...)"
    fi
    if [[ "${#ADMIN_IDS[@]}" -eq 0 ]]; then
        if [[ "$NON_INTERACTIVE" != "1" ]] && have_tty; then
            local reply=""
            read -r -p "Telegram ID администратора (Enter - настроить позже): " reply < /dev/tty || true
            [[ -n "$reply" ]] && ADMIN_IDS+=("$reply")
        else
            warn "--admin-id не передан: команды /update, /restart, /config будут недоступны никому, пока ADMIN_TELEGRAM_IDS не задан в .env"
        fi
    fi
    if [[ "$NON_INTERACTIVE" != "1" ]] && have_tty; then
        local group_reply=""
        read -r -p "Операторская Telegram-группа уже создана как супергруппа-форум? [y/N]: " group_reply < /dev/tty || true
        case "${group_reply,,}" in
            y|yes|да) OPERATOR_GROUP_READY="yes" ;;
            n|no|нет|"") OPERATOR_GROUP_READY="no" ;;
            *) warn "Ответ не распознан; после установки проверьте настройку operator-группы вручную" ;;
        esac
    fi
    local id
    for id in ${ADMIN_IDS[@]+"${ADMIN_IDS[@]}"} ${OWNER_IDS[@]+"${OWNER_IDS[@]}"}; do
        [[ "$id" =~ ^[0-9]+$ ]] || fail "Telegram ID должен быть числом, получено: $id"
    done

    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        log "Создаю системного пользователя $SERVICE_USER"
        useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
        CREATED_USER=1
    fi
    SERVICE_HOME="$(getent passwd "$SERVICE_USER" | cut -d: -f6)"

    log "Скачиваю код"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    if [[ -d "$INSTALL_DIR" ]]; then CREATED_DIR=2; else CREATED_DIR=1; fi
    git clone --quiet --branch "${BRANCH:-main}" "$REPO_URL" "$INSTALL_DIR" >>"$LOG_FILE" 2>&1 \
        || fail "git clone не удался: $(tail -n 3 "$LOG_FILE")"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

    log "Создаю виртуальное окружение и ставлю зависимости (может занять пару минут)"
    run_as python3 -m venv "$INSTALL_DIR/.venv" >>"$LOG_FILE" 2>&1 \
        || fail "не удалось создать venv: $(tail -n 3 "$LOG_FILE")"
    run_as "$INSTALL_DIR/.venv/bin/python" -m pip install --disable-pip-version-check --no-input -q -r "$INSTALL_DIR/requirements.txt" >>"$LOG_FILE" 2>&1 \
        || fail "pip install не удался (нет доступа к PyPI?): $(tail -n 5 "$LOG_FILE")"

    ENV_FILE="$INSTALL_DIR/.env"
    log "Создаю конфигурацию (.env)"
    configure_env

    log "Настраиваю systemd, sudoers и команду 'lumica'"
    write_systemd_and_sudo

    # Установка файлов завершена; дальше - запуск. Если сервис не стартует
    # (например, неверный токен), установка остаётся для исправления конфигурации.
    INSTALL_OK=1
    systemctl enable "$SERVICE_NAME" >>"$LOG_FILE" 2>&1
    systemctl restart "$SERVICE_NAME"
    log "Запускаю сервис и проверяю, что он работает..."
    if wait_for_service; then
        log "Готово: сервис работает ($(run_as git -C "$INSTALL_DIR" describe --tags --always 2>/dev/null || echo '?'))"
    else
        journalctl -u "$SERVICE_NAME" -n 25 --no-pager 2>/dev/null || true
        fail "файлы установлены, но сервис не запустился (см. лог выше). Проверьте $ENV_FILE (токен?), затем: sudo systemctl restart $SERVICE_NAME"
    fi
}

existing_install() {
    log "Найдена существующая установка в $INSTALL_DIR: .env, секреты и БД не перезаписываются"
    id -u "$SERVICE_USER" >/dev/null 2>&1 \
        || fail "системный пользователь $SERVICE_USER не найден - укажите верный --service-user"
    SERVICE_HOME="$(getent passwd "$SERVICE_USER" | cut -d: -f6)"
    ENV_FILE="$INSTALL_DIR/.env"

    configure_env
    write_systemd_and_sudo
    systemctl enable "$SERVICE_NAME" >>"$LOG_FILE" 2>&1 || true

    log "Обновляю код безопасным механизмом (резервная копия БД, откат при ошибке)"
    local update_rc=0
    # От пользователя сервиса: root'у git не доверяет чужой каталог, а файлы должны остаться у lumica.
    run_as /bin/bash "$INSTALL_DIR/scripts/update_prod.sh" update || update_rc=$?
    if [[ "$update_rc" -ne 0 ]]; then
        fail "обновление не выполнено (см. сообщение выше); установленная версия сохранена. Повторить: sudo lumica update"
    fi

    if [[ "$ENV_CHANGED" == "1" ]] || ! systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Перезапускаю сервис (изменилась конфигурация или он был остановлен)"
        systemctl restart "$SERVICE_NAME"
    fi
    wait_for_service || { journalctl -u "$SERVICE_NAME" -n 25 --no-pager 2>/dev/null || true; fail "сервис не работает: journalctl -u $SERVICE_NAME -n 50"; }
    INSTALL_OK=1
    log "Готово: сервис работает"
}

main() {
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
            *) echo "Неизвестный аргумент: $1" >&2; usage >&2; exit 1 ;;
        esac
    done

    LOG_FILE="$(mktemp /tmp/lumica-install.XXXXXX.log)"
    chmod 600 "$LOG_FILE"
    preflight

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        existing_install
    else
        fresh_install
    fi

    cat <<DONE

Lumica Core установлен: $INSTALL_DIR
  Статус / обновление:  sudo lumica status | sudo lumica update
  Откат обновления:     sudo lumica rollback
  Логи:                 journalctl -u $SERVICE_NAME -f
  Конфигурация:         $INSTALL_DIR/.env (секреты не перезаписываются при повторной установке)
DONE
    if [[ "$OPERATOR_GROUP_READY" == "yes" ]]; then
        cat <<DONE
  Operator-группа:      добавьте бота администратором с правом управления темами,
                        затем отправьте /setup_group в этой супергруппе.
DONE
    elif [[ "$OPERATOR_GROUP_READY" == "no" ]]; then
        cat <<DONE
  Operator-группа:      создайте Telegram-супергруппу-форум, добавьте бота
                        администратором с правом управления темами и отправьте
                        /setup_group в группе. Bot API не может создать группу сам.
DONE
    fi
    rm -f "$LOG_FILE"
}

# Весь скрипт читается целиком до запуска main: при обрыве загрузки через
# `curl | bash` недокачанный скрипт не выполнится.
main "$@"
