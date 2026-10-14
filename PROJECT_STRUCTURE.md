# Lumica Project Structure (2026 Refactor)

## New layout

- `install.sh` / `uninstall.sh` - curl-installer and uninstaller (bash, no app dependency)
- `scripts/` - single runtime entrypoints (canonical)
  - `scripts/run_web.py`
  - `scripts/run_bot.py`
  - `scripts/run_all.py`
  - `scripts/update_prod.sh` - thin CLI wrapper (re-execs as the checkout owner when run as root), delegates to `lumica.update.cli`
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
- Manual update ops: `sudo lumica {status|update|rollback|restart}` (= `scripts/update_prod.sh`)

## Install / update / uninstall system

Layers, all funneling through one engine (`lumica.update.UpdateManager`)
so chat, HTTP API and manual CLI can never give different results.

**Install (one command):**
`curl -fsSL https://raw.githubusercontent.com/artinuwq/lumica-core/main/install.sh | sudo bash`
(asks for the bot token / admin ID; non-interactive: `| sudo bash -s -- --token ... --admin-id ... --non-interactive`).

**Update an installed system:** `sudo lumica update` (also `status`, `rollback`,
`restart`), `/update` + `/status` in Telegram, `POST /api/update`.

1. **`install.sh`** (bash) - preflight (root, systemd, git, python>=3.10+venv,
   GitHub reachable) -> clone into `/opt/lumica-core` -> venv + deps as the
   unprivileged `lumica` user -> `.env` -> units -> start and verify (`/health`).
   - Config is written once: `.env` is never overwritten on re-run. Only keys
     passed explicitly as flags change; defaults (`FLASK_HOST/PORT`,
     `UPDATE_BRANCH`) and generated secrets (`SESSION_PEPPER`, `CSRF_PEPPER`)
     are set only when the key is missing.
   - Re-run on an existing install = refresh unit/sudoers/`lumica` command + run
     the safe update below. It never `git reset`s on its own.
   - If a *first* install fails (clone, pip, validation) everything it created
     is removed (dir, user, units, sudoers, command). If only the final start
     fails (e.g. wrong token) the install is kept so `.env` can be fixed.
   - Writes `lumica.service`, `lumica-update.service` (oneshot, see below), a
     validated sudoers rule limited to `systemctl restart|start|stop|status
     lumica.service` and `start --no-block lumica-update.service`, and
     `/usr/local/bin/lumica`.
2. **`uninstall.sh`** (bash) - removes units, sudoers rule, `lumica` command,
   `INSTALL_DIR` (or keeps `database/` + `.env` with `--keep-data`) and the user.
3. **`src/lumica/update/`** (Python, the only place update logic lives):
   - `provider.py` - git subprocess wrapper; network failures raise `NetworkError`
   - `backup.py` - sqlite online backups of `database/*.db` into
     `database/backups/` (last 5 kept) before every update; restore helpers
   - `installer.py` - `pip install -r requirements.txt` (only when it changed),
     compile check of the new sources, optional `UPDATE_MIGRATION_CMD` hook
   - `service.py` - systemctl wrapper + `wait_healthy` (unit `active` for 8 s in
     a row **and** `GET /health` ok; `UPDATE_HEALTH_URL` overrides, `off` disables)
   - `rollback.py` - previous SHA, last operation result, force marker
     (all in `database/`)
   - `manifest.py` - `UpdateStatus` / `UpdateResult`
   - `manager.py` - `check()` / `apply()` / `apply_background()` / `rollback()` / `restart_service()`
   - `env_config.py` - the `/config` registry + `.env` reader/writer
   - `cli.py` - `python -m lumica.update.cli {status|update|rollback|restart}`
4. **HTTP API** (`src/lumica/api/routes/update.py`) - `GET /api/update/status`,
   `POST /api/update` (starts the update in the background, HTTP 202),
   `POST /api/restart`; admin-gated, only calls `UpdateManager`.
5. **Chat-ops** (`src/lumica/bot/chatops.py`) - `/ping`, `/status` (versions +
   last update result), `/update`, `/restart` (inline confirmation),
   `/config [get|set|clear] KEY [VALUE]`. Deny-by-default if no admin roster is
   configured.

### Update flow (`UpdateManager.apply`)

lock -> fetch & compare versions (`git describe`/short SHA + date) -> refuse on
local changes to tracked files (unless `--force`, which stashes them) ->
**DB backup** -> `git reset --hard origin/<branch>` -> `pip install` only if
`requirements.txt` changed -> compile check -> restart -> verify the service
really runs. Any failure after the checkout restores the previous commit (and
its dependencies); if the new version already migrated the DB (alembic revision
differs from the backup) the DB is restored from the backup as well, then the
old version is started and verified. `.env`, `database/` and the venv are
never touched by the code switch (all git-ignored).

Why a separate `lumica-update.service`: `/update` from Telegram or the API runs
*inside* the service that has to be restarted. The update therefore runs as its
own oneshot unit (own cgroup), so the restart cannot kill it and it can verify
and roll back. Installs created by an older `install.sh` have no such unit; the
engine falls back to the in-process update until `install.sh` is re-run.

Delivery source: git branch (`UPDATE_BRANCH`, default `main`). The repo has no
tags/GitHub Releases yet; once tags exist, `git describe` shows them as the
version automatically.

Manual recovery: `sudo lumica rollback` (previous version; add `--restore-db`
to also restore the latest `database/backups/*`), state of the last operation:
`sudo lumica status`.

Invariant: none of the other layers duplicate update logic - they all call
`UpdateManager`, so behaviour is identical everywhere.

## Migration note

Primary code now lives under `src/lumica/*`.
Legacy root wrappers were removed; code is split by layers under `src/lumica/*` and started via `scripts/*`.
