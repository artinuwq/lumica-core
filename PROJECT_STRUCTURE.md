# Lumica Project Structure (2026 Refactor)

## New layout

- `scripts/` - single runtime entrypoints (canonical)
  - `scripts/run_web.py`
  - `scripts/run_bot.py`
  - `scripts/run_all.py`
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

## Migration note

Primary code now lives under `src/lumica/*`.
Legacy root wrappers were removed; code is split by layers under `src/lumica/*` and started via `scripts/*`.
