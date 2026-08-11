"""Post-checkout steps: install dependencies, run an optional migration hook.

No-op (with a clear message) if requirements.txt is missing, so this stays
safe to call even for stacks that later drop it.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def resolve_python_bin(repo_dir: Path) -> str:
    venv_python = repo_dir / ".venv" / "bin" / "python"
    if venv_python.is_file():
        return str(venv_python)
    return os.getenv("UPDATE_PYTHON_BIN", sys.executable)


def install(repo_dir: Path) -> tuple[bool, str]:
    requirements = repo_dir / "requirements.txt"
    if not requirements.is_file():
        return True, "requirements.txt не найден, установка зависимостей пропущена"

    python_bin = resolve_python_bin(repo_dir)
    try:
        result = subprocess.run(
            [python_bin, "-m", "pip", "install", "-r", str(requirements)],
            capture_output=True,
            text=True,
            cwd=str(repo_dir),
            timeout=600,
        )
    except FileNotFoundError:
        return False, f"python-интерпретатор не найден: {python_bin}"
    except subprocess.TimeoutExpired:
        return False, "установка зависимостей превысила таймаут"

    if result.returncode != 0:
        return False, f"pip install завершился с ошибкой: {result.stderr.strip()[-1500:]}"

    migration_cmd = os.getenv("UPDATE_MIGRATION_CMD", "").strip()
    if migration_cmd:
        try:
            mig = subprocess.run(
                migration_cmd,
                shell=True,
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            return False, "команда миграции превысила таймаут"
        if mig.returncode != 0:
            return False, f"команда миграции завершилась с ошибкой: {mig.stderr.strip()[-1500:]}"
        return True, "зависимости и миграция применены"

    return True, "зависимости установлены"


__all__ = ["install", "resolve_python_bin"]
