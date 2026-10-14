"""python -m lumica.update.cli {status|update|rollback|restart}

Manual-ops entrypoint. Kept thin on purpose: all logic lives in
UpdateManager, this just prints its progress/result. scripts/update_prod.sh
(and the `lumica` command installed by install.sh) exec into this so the bash
layer never reimplements update logic.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

from .env_config import load_env_file
from .manager import UpdateManager
from .rollback import pop_force_marker


def _log(message: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {message}", flush=True)


def main(argv: list[str] | None = None) -> int:
    # Plain env loader on purpose: importing lumica.infra would open the DB.
    load_env_file(UpdateManager.resolve_repo_dir() / ".env")

    parser = argparse.ArgumentParser(prog="lumica")
    parser.add_argument("action", choices=["status", "update", "rollback", "restart"])
    parser.add_argument("--force", action="store_true", help="update even if already up to date / discard local changes into git stash")
    parser.add_argument("--no-restart", action="store_true", help="update: do not restart the service (dev machines)")
    parser.add_argument("--restore-db", action="store_true", help="rollback: also restore the latest pre-update DB backup")
    parser.add_argument("--branch")
    parser.add_argument("--service")
    args = parser.parse_args(argv)

    manager = UpdateManager(branch=args.branch, service_name=args.service, log=_log)
    try:
        return _run(manager, args)
    except Exception as exc:  # noqa: BLE001 - operators need a reason, not a traceback
        print(f"Непредвиденная ошибка: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _run(manager: UpdateManager, args: argparse.Namespace) -> int:
    if args.action == "status":
        status = manager.check()
        print(status.message)
        last = manager.last_result()
        if last:
            outcome = "успех" if last.get("success") else "ошибка"
            print(f"Последняя операция ({last.get('kind')}, {last.get('finished_at')}): {outcome} - {last.get('message')}")
        return 0 if status.local_sha else 1

    if args.action == "update":
        force = args.force or pop_force_marker(manager.state_dir)
        result = manager.apply(force=force, restart=not args.no_restart)
        print(result.message)
        return 0 if result.success else 1

    if args.action == "rollback":
        result = manager.rollback(restore_db=args.restore_db)
        print(result.message)
        return 0 if result.success else 1

    ok, message = manager.restart_service()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
