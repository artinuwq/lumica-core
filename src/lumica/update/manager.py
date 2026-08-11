from __future__ import annotations

import os
import subprocess
from pathlib import Path

from lumica.infra.db import DATABASE_DIR
from lumica.infra.settings import ROOT

from . import provider
from .installer import install as install_deps
from .manifest import UpdateResult, UpdateStatus
from .rollback import load_previous_sha, save_previous_sha


class UpdateManager:
    """Single point of entry for git-based self-update.

    HTTP API routes and the Telegram chat-ops bot both call this class -
    neither reimplements checkout/restart logic itself (see PROJECT_STRUCTURE.md).
    """

    def __init__(
        self,
        repo_dir: Path | None = None,
        remote: str | None = None,
        branch: str | None = None,
        service_name: str | None = None,
    ):
        self.repo_dir = repo_dir or self.resolve_repo_dir()
        self.remote = remote or os.getenv("UPDATE_REMOTE", "origin")
        self.branch = branch or os.getenv("UPDATE_BRANCH", "main")
        self.service_name = service_name or os.getenv("UPDATE_SERVICE_NAME", "lumica")

    @staticmethod
    def resolve_repo_dir() -> Path:
        """Handle the ambiguous-layout case where the deploy root isn't
        itself the git checkout (e.g. project nested one level in)."""
        candidates = [ROOT, ROOT.parent]
        for candidate in candidates:
            if (candidate / ".git").is_dir():
                return candidate
        return ROOT

    def check(self) -> UpdateStatus:
        try:
            local_sha = provider.current_sha(self.repo_dir)
            branch = provider.current_branch(self.repo_dir)
            remote_sha = provider.remote_sha(self.repo_dir, self.remote, self.branch)
            dirty = provider.is_dirty(self.repo_dir)
        except provider.GitError as exc:
            return UpdateStatus(self.branch, "", "", False, False, f"ошибка git: {exc}")

        up_to_date = local_sha == remote_sha
        if up_to_date:
            message = f"Актуальная версия: {branch}@{local_sha[:8]}"
        else:
            message = f"Доступно обновление на {branch}: {local_sha[:8]} -> {remote_sha[:8]}"
        if dirty:
            message += " (внимание: есть незакоммиченные локальные изменения)"

        return UpdateStatus(branch, local_sha, remote_sha, up_to_date, dirty, message)

    def apply(self, force: bool = False) -> UpdateResult:
        status = self.check()
        if not status.local_sha:
            return UpdateResult(False, status.message)

        if status.up_to_date and not force:
            return UpdateResult(
                success=True,
                message="Уже установлена последняя версия, обновление не требуется",
                previous_sha=status.local_sha,
                current_sha=status.local_sha,
                restarted=False,
            )

        previous_sha = status.local_sha
        save_previous_sha(DATABASE_DIR, previous_sha)

        try:
            provider.checkout_remote(self.repo_dir, self.remote, self.branch)
        except provider.GitError as exc:
            return UpdateResult(False, f"обновление не удалось на этапе checkout: {exc}", previous_sha, None, False)

        current_sha = provider.current_sha(self.repo_dir)
        install_ok, install_message = install_deps(self.repo_dir)
        if not install_ok:
            return UpdateResult(
                success=False,
                message=f"код обновлён ({previous_sha[:8]} -> {current_sha[:8]}), но {install_message}",
                previous_sha=previous_sha,
                current_sha=current_sha,
                restarted=False,
            )

        restarted, restart_message = self.restart_service()
        message = (
            f"Обновлено {previous_sha[:8]} -> {current_sha[:8]}. {install_message}. {restart_message}"
        )
        return UpdateResult(True, message, previous_sha, current_sha, restarted)

    def restart_service(self) -> tuple[bool, str]:
        override = os.getenv("UPDATE_RESTART_CMD", "").strip()
        if override:
            cmd = override.split()
        elif getattr(os, "geteuid", lambda: 1)() == 0:
            cmd = ["systemctl", "restart", self.service_name]
        else:
            # install.sh grants a scoped, passwordless sudo rule for exactly
            # this command to the service's own system user.
            cmd = ["sudo", "-n", "systemctl", "restart", self.service_name]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except FileNotFoundError:
            return False, "systemctl недоступен на этом хосте"
        except subprocess.TimeoutExpired:
            return False, "перезапуск сервиса превысил таймаут"

        if result.returncode != 0:
            stderr = result.stderr.strip()[-500:]
            return False, f"перезапуск не выполнен: {stderr or 'нет прав (см. UPDATE_RESTART_CMD / sudoers)'}"
        return True, "сервис перезапущен"

    def previous_sha(self) -> str | None:
        return load_previous_sha(DATABASE_DIR)


__all__ = ["UpdateManager"]
