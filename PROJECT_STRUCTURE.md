# Lumica Project Structure (2026 Refactor)

## New layout

- `scripts/` - single runtime entrypoints (canonical)
  - `scripts/run_web.py`
  - `scripts/run_bot.py`
  - `scripts/run_all.py`
  - `scripts/update_prod.sh`
- `src/lumica/` - logical application package
  - `api/` - API app boundary
  - `runtime/` - runtime launch modules used by scripts
  - `bot/` - telegram bot implementation
  - `domain/` - data models
  - `services/` - business services
  - `integrations/` - external systems (3x-ui, Telegram storage)
  - `jobs/` - background jobs
  - `infra/` - DB/bootstrap/env
- `frontend/`
  - `index.html`
  - `assets/css/app.css`
  - `assets/js/app.js`
- `tests/` - smoke tests

## Run commands

- Web: `python scripts/run_web.py`
- Bot: `python scripts/run_bot.py`
- Full stack (web + scheduler + bot): `python scripts/run_all.py`
- Prod update (Linux/systemd): `./scripts/update_prod.sh --service <name> --repo-dir <path>`

## Production update

The `scripts/update_prod.sh` helper is intended for a Linux server with
`systemd` and a git checkout of the project. It runs the production update
sequence in this order:

1. Stop the service.
2. Fetch and pull the selected branch.
3. Optionally install `requirements.txt`.
4. Optionally run an extra migration command.
5. Start the service and wait until it becomes active.

## Migration note

Primary code now lives under `src/lumica/*`.
Legacy root wrappers were removed; code is split by layers under `src/lumica/*` and started via `scripts/*`.
