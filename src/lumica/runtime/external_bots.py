from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.util
import inspect
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from lumica.infra import ENV_FILE, load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BOTS_ROOT = PROJECT_ROOT / "external_bots"
SCRIPT_ENTRYPOINT = PROJECT_ROOT / "scripts" / "run_external_bots.py"
BASE_DELAY = 1.0
MAX_DELAY = 60.0
RESERVED_BOTS = {"__pycache__", "bot_template"}
LOG = logging.getLogger("external-bot-loader")


@dataclass(frozen=True)
class BotSpec:
    name: str
    directory: Path
    main_file: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Autoload external bots from external_bots/*.")
    parser.add_argument("--root", default=str(DEFAULT_BOTS_ROOT), help="Directory that contains bot folders.")
    parser.add_argument(
        "--bot",
        dest="bots",
        action="append",
        default=[],
        help="Bot folder name to run. Repeat the flag to select multiple bots.",
    )
    parser.add_argument("--sandbox", action="store_true", help="Run every bot in a subprocess.")
    parser.add_argument("--once", action="store_true", help="Run each bot once and exit.")
    parser.add_argument(
        "--log-level",
        default=os.getenv("BOT_LOADER_LOG_LEVEL", "INFO"),
        help="Logging level. Defaults to BOT_LOADER_LOG_LEVEL or INFO.",
    )
    return parser.parse_args()


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def discover_bots(root: Path, selected: set[str]) -> list[BotSpec]:
    if not root.exists():
        raise SystemExit(f"Bot root does not exist: {root}")
    if not root.is_dir():
        raise SystemExit(f"Bot root is not a directory: {root}")

    bots: list[BotSpec] = []
    found: set[str] = set()
    for path in sorted(root.iterdir()):
        if not path.is_dir():
            continue
        if path.name in RESERVED_BOTS and path.name not in selected:
            # Keep the scaffold available for copying, not autostarting.
            continue
        if selected and path.name not in selected:
            continue
        main_file = path / "main.py"
        if not main_file.is_file():
            LOG.debug("Skipping %s: missing main.py", path)
            continue
        bots.append(BotSpec(name=path.name, directory=path, main_file=main_file))
        found.add(path.name)

    missing = sorted(selected - found)
    if missing:
        raise SystemExit(f"Requested bots not found: {', '.join(missing)}")
    return bots


@contextlib.contextmanager
def temporary_sys_path(path: Path):
    raw = str(path)
    if raw in sys.path:
        yield
        return
    sys.path.insert(0, raw)
    try:
        yield
    finally:
        with contextlib.suppress(ValueError):
            sys.path.remove(raw)


def load_module(bot: BotSpec) -> ModuleType:
    module_name = f"external_bot_{bot.name}_{time.time_ns()}"
    spec = importlib.util.spec_from_file_location(module_name, bot.main_file)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not create import spec for {bot.main_file}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)
    return module


async def invoke_noargs(target) -> object:
    if inspect.iscoroutinefunction(target) or inspect.iscoroutinefunction(getattr(target, "__call__", None)):
        result = target()
    else:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, target)
    if inspect.isawaitable(result):
        return await result
    return result


async def run_bot_object(bot_entry) -> object:
    instance = bot_entry
    if inspect.isclass(bot_entry) or callable(bot_entry):
        instance = await invoke_noargs(bot_entry)

    runner = getattr(instance, "run", None)
    if callable(runner):
        return await invoke_noargs(runner)
    if callable(instance):
        return await invoke_noargs(instance)
    raise TypeError("Bot entry must be callable or expose a callable run() method.")


async def run_imported_bot(bot: BotSpec) -> None:
    with temporary_sys_path(bot.directory):
        module = load_module(bot)
        start = getattr(module, "start", None)
        if callable(start):
            LOG.info("Starting %s via start()", bot.name)
            await invoke_noargs(start)
            return

        if hasattr(module, "Bot"):
            LOG.info("Starting %s via Bot", bot.name)
            await run_bot_object(getattr(module, "Bot"))
            return

        run = getattr(module, "run", None)
        if callable(run):
            LOG.info("Starting %s via run()", bot.name)
            await invoke_noargs(run)
            return

    raise AttributeError(f"{bot.main_file} must define start(), Bot or run().")


async def run_sandboxed_bot(bot: BotSpec, root: Path, log_level: str) -> None:
    entrypoint = SCRIPT_ENTRYPOINT if SCRIPT_ENTRYPOINT.is_file() else Path(__file__).resolve()
    command = [
        sys.executable,
        str(entrypoint),
        "--root",
        str(root),
        "--bot",
        bot.name,
        "--once",
        "--log-level",
        log_level,
    ]
    LOG.info("Starting %s in sandbox mode", bot.name)
    process = await asyncio.create_subprocess_exec(*command, cwd=str(PROJECT_ROOT))
    return_code = await process.wait()
    if return_code != 0:
        raise RuntimeError(f"Sandboxed bot {bot.name} exited with code {return_code}")


async def supervise_bot(bot: BotSpec, root: Path, sandbox: bool, once: bool, log_level: str) -> None:
    delay = BASE_DELAY
    while True:
        started_at = time.monotonic()
        try:
            if sandbox:
                await run_sandboxed_bot(bot, root, log_level)
            else:
                await run_imported_bot(bot)
        except asyncio.CancelledError:
            raise
        except Exception:
            LOG.exception("Bot %s crashed", bot.name)
            if once:
                raise
            LOG.info("Restarting %s in %.1fs", bot.name, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, MAX_DELAY)
            continue

        runtime = time.monotonic() - started_at
        if once:
            LOG.info("Bot %s finished after %.1fs", bot.name, runtime)
            return

        LOG.warning("Bot %s stopped after %.1fs; restarting in %.1fs", bot.name, runtime, BASE_DELAY)
        delay = BASE_DELAY
        await asyncio.sleep(delay)


async def main_async(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    selected = set(args.bots)
    bots = discover_bots(root, selected)
    if not bots:
        LOG.warning("No bots found in %s", root)
        return 0

    tasks = [
        asyncio.create_task(
            supervise_bot(bot, root=root, sandbox=args.sandbox, once=args.once, log_level=args.log_level),
            name=f"bot:{bot.name}",
        )
        for bot in bots
    ]
    await asyncio.gather(*tasks)
    return 0


def main() -> int:
    load_dotenv(ENV_FILE)
    args = parse_args()
    configure_logging(args.log_level)
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        LOG.info("Shutdown requested")
        return 130
    except SystemExit:
        raise
    except Exception:
        LOG.exception("Loader stopped unexpectedly")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
