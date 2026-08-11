# Lumica Project Structure (2026 Refactor)

## New layout

- `install.sh` / `uninstall.sh` - curl-installer and uninstaller (bash, no app dependency)
- `scripts/` - single runtime entrypoints (canonical)
  - `scripts/run_web.py`
  - `scripts/run_bot.py`
  - `scripts/run_all.py`
  - `scripts/update_prod.sh` - thin CLI wrapper, delegates to `lumica.update.cli`
- `src/lumica/` - logical application package
  - `api/` - API app boundary (includes `routes/update.py`: status/apply/restart)
  - `runtime/` - runtime launch modules used by scripts
  - `bot/` - telegram bot implementation (includes `chatops.py`: /status /update /restart /config)
  - `domain/` - data models
  - `services/` - business services (includes `roles.py`: shared telegram-id -> role resolution)
  - `integrations/` - external systems (3x-ui, Telegram storage)
  - `jobs/` - background jobs
  - `infra/` - DB/bootstrap/env
  - `update/` - self-update engine (single source of truth, see below)
- `frontend/`
  - `index.html`
  - `assets/css/app.css`
  - `assets/js/app.js`
- `tests/` - smoke tests

## Run commands

- Web: `python scripts/run_web.py`
- Bot: `python scripts/run_bot.py`
- Full stack (web + scheduler + bot): `python scripts/run_all.py`
- Manual update ops: `./scripts/update_prod.sh {status|update|restart}`

## Install / update / uninstall system

Five layers, all funneling through one engine (`lumica.update.UpdateManager`)
so chat, HTTP API and manual CLI can never give different results:

1. **`install.sh`** (bash) - `curl -fsSL <raw-url>/install.sh | sudo bash -s -- --token 'xxx' --admin-id 123`.
   Clones/updates the repo into `/opt/lumica-core` (configurable), sets up a
   venv, generates `.env` (auto-generating `SESSION_PEPPER`/`CSRF_PEPPER` if
   absent), creates a dedicated `lumica` system user, writes the
   `lumica.service` systemd unit, and grants that user a scoped passwordless
   sudo rule limited to `systemctl restart lumica.service` (needed so
   `/restart` and `/update` work without running the whole app as root).
   Idempotent - safe to re-run with new flags.
2. **`uninstall.sh`** (bash) - stops/removes the unit and sudoers rule,
   removes `INSTALL_DIR` (or keeps `database/` + `.env` with `--keep-data`),
   removes the system user. Refuses to run without `--yes` when there's no
   TTY (safe default).
3. **`src/lumica/update/`** (Python, the only place update logic lives):
   - `provider.py` - git subprocess wrapper (current_sha/remote_sha/is_dirty/checkout_remote)
   - `installer.py` - `pip install -r requirements.txt` after checkout, no-op
     if the file is missing, optional `UPDATE_MIGRATION_CMD` hook
   - `rollback.py` - writes the previous SHA to `database/.update_previous_sha`
     before every hard reset (manual rollback only, not a schema migration)
   - `manifest.py` - `UpdateStatus` / `UpdateResult` dataclasses
   - `manager.py` - `UpdateManager.check()` / `.apply(force=False)` / `.restart_service()`
   - `env_config.py` - the `/config` registry (`ConfigSpec`) + `.env` reader/writer
   - `cli.py` - `python -m lumica.update.cli {status|update|restart}`
4. **HTTP API** (`src/lumica/api/routes/update.py`) - `GET /api/update/status`,
   `POST /api/update`, `POST /api/restart`, admin-gated via the existing
   session auth, purely calling `UpdateManager`.
5. **Chat-ops** (`src/lumica/bot/chatops.py`) - Telegram commands `/ping`,
   `/status`, `/update`, `/restart` (asks for inline Да/Нет confirmation
   first), `/config [get|set|clear] KEY [VALUE]`. Admin check goes through
   `lumica.services.roles.is_authorized`, shared with the HTTP API. Unlike a
   typical dev-mode default, **chat-ops denies everyone if no
   `ADMIN_TELEGRAM_IDS`/`OWNER_TELEGRAM_IDS`/`ROLE_BINDINGS` is configured** -
   this bot can trigger `/update` and `/restart`, so an empty roster must not
   silently mean "everyone is admin".

Invariant: none of layers 2/4/5 duplicate update logic - they all call
`UpdateManager`, so behaviour is guaranteed identical everywhere.

## Migration note

Primary code now lives under `src/lumica/*`.
Legacy root wrappers were removed; code is split by layers under `src/lumica/*` and started via `scripts/*`.
