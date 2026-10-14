"""Post-checkout steps: install dependencies, optional migration hook, source sanity check.

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
            [python_bin, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "-r", str(requirements)],
            capture_output=True,
            text=True,
            cwd=str(repo_dir),
            timeout=600,
        )
    except FileNotFoundError:
        return False, f"python-интерпретатор не найден: {python_bin}"
    except subprocess.TimeoutExpired:
        return False, "установка зависимостей превысила таймаут (нет интернета/PyPI?)"

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


def verify_sources(repo_dir: Path) -> tuple[bool, str]:
    """Cheap pre-restart check: the new code must at least compile."""
    python_bin = resolve_python_bin(repo_dir)
    targets = [str(p) for p in (repo_dir / "src", repo_dir / "scripts") if p.is_dir()]
    if not targets:
        return True, "нечего проверять"
    try:
        result = subprocess.run(
            [python_bin, "-m", "compileall", "-q", *targets],
            capture_output=True,
            text=True,
            cwd=str(repo_dir),
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, f"не удалось проверить исходники: {exc}"
    if result.returncode != 0:
        return False, f"в новой версии синтаксическая ошибка: {(result.stdout + result.stderr).strip()[-800:]}"
    return True, "исходники проверены"


__all__ = ["install", "verify_sources", "resolve_python_bin"]
