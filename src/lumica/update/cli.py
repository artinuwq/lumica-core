"""python -m lumica.update.cli {status|update|restart}

Manual-ops entrypoint. Kept thin on purpose: all logic lives in
UpdateManager, this just prints its result. scripts/update_prod.sh execs
into this so the bash layer never reimplements update logic (see
PROJECT_STRUCTURE.md / update engine invariants).
"""

from __future__ import annotations

import argparse
import sys

from lumica.infra import ENV_FILE, load_dotenv

from .manager import UpdateManager


def main(argv: list[str] | None = None) -> int:
    load_dotenv(ENV_FILE)

    parser = argparse.ArgumentParser(prog="lumica-update")
    parser.add_argument("action", choices=["status", "update", "restart"])
    parser.add_argument("--force", action="store_true", help="re-run installer/restart even if already up to date")
    parser.add_argument("--branch")
    parser.add_argument("--service")
    args = parser.parse_args(argv)

    manager = UpdateManager(branch=args.branch, service_name=args.service)

    if args.action == "status":
        status = manager.check()
        print(status.message)
        return 0 if status.local_sha else 1

    if args.action == "update":
        result = manager.apply(force=args.force)
        print(result.message)
        return 0 if result.success else 1

    result_ok, message = manager.restart_service()
    print(message)
    return 0 if result_ok else 1


if __name__ == "__main__":
    sys.exit(main())
