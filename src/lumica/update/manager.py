from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable

from . import backup, provider
from .installer import install as install_deps
from .installer import verify_sources
from .manifest import UpdateResult, UpdateStatus
from .rollback import (
    load_last_result,
    load_previous_sha,
    save_last_result,
    save_previous_sha,
    set_force_marker,
)
from .service import ServiceController, default_health_url

# Same value as lumica.infra.settings.ROOT, computed locally so the update
# engine (and its CLI) stays importable without touching the DB layer.
ROOT = Path(__file__).resolve().parents[3]


class UpdateManager:
    """Single point of entry for git-based self-update.

    HTTP API routes, the Telegram chat-ops bot and the CLI all call this
    class - none of them reimplements checkout/restart logic.

    Update flow (apply): lock -> fetch/compare -> DB backup -> checkout ->
    deps (only if requirements.txt changed) -> compile check -> restart ->
    verify the service is really up. Any failure after the checkout restores
    the previous commit (and the DB if a migration already ran).
    """

    def __init__(
        self,
        repo_dir: Path | None = None,
        remote: str | None = None,
        branch: str | None = None,
        service_name: str | None = None,
        service: ServiceController | None = None,
        log: Callable[[str], None] | None = None,
    ):
        self.repo_dir = repo_dir or self.resolve_repo_dir()
        self.state_dir = self.repo_dir / "database"
        self.remote = remote or os.getenv("UPDATE_REMOTE", "origin")
        self.branch = branch or os.getenv("UPDATE_BRANCH", "main")
        self.service_name = service_name or os.getenv("UPDATE_SERVICE_NAME", "lumica")
        self.service = service or ServiceController(self.service_name)
        self._log = log or (lambda message: None)

    @staticmethod
    def resolve_repo_dir() -> Path:
        """Handle the ambiguous-layout case where the deploy root isn't
        itself the git checkout (e.g. project nested one level in)."""
        for candidate in (ROOT, ROOT.parent):
            if (candidate / ".git").is_dir():
                return candidate
        return ROOT

    # ------------------------------------------------------------------ status

    def check(self) -> UpdateStatus:
        try:
            local_sha = provider.current_sha(self.repo_dir)
            branch = provider.current_branch(self.repo_dir)
            remote_sha = provider.remote_sha(self.repo_dir, self.remote, self.branch)
            dirty = provider.is_dirty(self.repo_dir)
        except provider.NetworkError as exc:
            return UpdateStatus(self.branch, "", "", False, False, f"ошибка сети: {exc}", network_error=True)
        except provider.GitError as exc:
            return UpdateStatus(self.branch, "", "", False, False, f"ошибка git: {exc}")

        local_version = provider.describe(self.repo_dir, local_sha)
        remote_version = provider.describe(self.repo_dir, remote_sha)
        up_to_date = local_sha == remote_sha
        remote_subject = "" if up_to_date else provider.subject(self.repo_dir, remote_sha)
        if up_to_date:
            message = f"Актуальная версия: {local_version} [{branch}]"
        else:
            note = remote_subject
            message = f"Доступно обновление [{branch}]: {local_version} -> {remote_version}"
            if note:
                message += f" - {note}"
        if dirty:
            message += " (внимание: есть локальные изменения отслеживаемых файлов)"

        return UpdateStatus(
            branch, local_sha, remote_sha, up_to_date, dirty, message,
            local_version=local_version, remote_version=remote_version,
            remote_subject=remote_subject,
        )

    def last_result(self) -> dict | None:
        return load_last_result(self.state_dir)

    def previous_sha(self) -> str | None:
        return load_previous_sha(self.state_dir)

    # ------------------------------------------------------------------ update

    @contextmanager
    def _lock(self):
        try:
            import fcntl  # POSIX only; on other platforms updates are not serialized
        except ImportError:
            yield True
            return
        self.state_dir.mkdir(parents=True, exist_ok=True)
        handle = open(self.state_dir / ".update.lock", "w")
        try:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                yield False
                return
            yield True
        finally:
            handle.close()

    def apply(self, force: bool = False, restart: bool = True) -> UpdateResult:
        with self._lock() as acquired:
            if not acquired:
                return UpdateResult(False, "Другое обновление уже выполняется, повторите позже")
            result = self._apply_locked(force, restart)
        if not result.noop:  # "already up to date" must not hide the outcome of a real update
            save_last_result(self.state_dir, {"kind": "update", **result.to_dict()})
        return result

    def apply_background(self, force: bool = False) -> UpdateResult:
        """For callers living *inside* the service (HTTP API, chat-ops): the
        restart would kill them mid-update, so hand the job to the separate
        `<service>-update.service` oneshot unit (own cgroup, survives the
        restart). Installs made by an older install.sh have no such unit;
        for them fall back to the in-process update."""
        if not self.service.unit_exists(self.service.update_unit):
            return self.apply(force=force)
        if force:
            set_force_marker(self.state_dir)
        started, error = self.service.start_unit_detached(self.service.update_unit)
        if not started:
            return UpdateResult(False, f"не удалось запустить фоновое обновление: {error}")
        return UpdateResult(
            True,
            f"Обновление запущено в фоне. Итог: /status или `journalctl -u {self.service.update_unit}`",
            started=True,
        )

    def _apply_locked(self, force: bool, restart: bool) -> UpdateResult:
        say = self._log
        say("Проверяю версии...")
        status = self.check()
        if not status.local_sha:
            return UpdateResult(False, status.message)

        if status.up_to_date and not force:
            return UpdateResult(
                success=True,
                message=f"Уже установлена последняя версия: {status.local_version}. Обновление не требуется",
                previous_sha=status.local_sha,
                current_sha=status.local_sha,
                noop=True,
            )

        previous, target = status.local_sha, status.remote_sha
        say(f"Текущая версия: {status.local_version}")
        say(f"Новая версия:   {status.remote_version}")

        if status.dirty:
            if not force:
                return UpdateResult(
                    False,
                    "В каталоге приложения есть локальные изменения отслеживаемых файлов. "
                    "Обновление отменено, чтобы их не потерять. Сохраните их или запустите с --force "
                    "(изменения уйдут в git stash).",
                    previous_sha=previous,
                )
            try:
                provider.stash_local_changes(self.repo_dir, f"lumica-update {datetime.now():%Y%m%d-%H%M%S}")
                say("Локальные изменения убраны в git stash")
            except provider.GitError as exc:
                return UpdateResult(False, f"не удалось сохранить локальные изменения: {exc}", previous_sha=previous)

        say("Делаю резервную копию БД...")
        try:
            backup_dir = backup.create_backup(self.state_dir, previous)
        except (sqlite3.Error, OSError) as exc:
            return UpdateResult(False, f"не удалось сделать резервную копию БД, обновление отменено: {exc}", previous_sha=previous)
        if backup_dir:
            say(f"Резервная копия: {backup_dir}")

        save_previous_sha(self.state_dir, previous)

        say("Загружаю новую версию...")
        try:
            provider.checkout_remote(self.repo_dir, self.remote, self.branch)
        except provider.GitError as exc:
            self._restore_code(previous)
            return UpdateResult(False, f"не удалось получить новую версию: {exc}. Прежняя версия сохранена.", previous, None)

        deps_changed = force or provider.paths_changed(self.repo_dir, previous, target, "requirements.txt")
        restart_attempted = False
        try:
            if deps_changed:
                say("Устанавливаю зависимости...")
                ok, detail = install_deps(self.repo_dir)
                if not ok:
                    return self._abort(previous, deps_changed, backup_dir, detail, restarted=False)
            else:
                detail = "зависимости не менялись"

            ok, check_detail = verify_sources(self.repo_dir)
            if not ok:
                return self._abort(previous, deps_changed, backup_dir, check_detail, restarted=False)

            if not restart:
                return UpdateResult(True, f"Обновлено {status.local_version} -> {status.remote_version}. {detail}. Перезапуск пропущен (--no-restart)", previous, target, False)

            say("Перезапускаю сервис...")
            restart_attempted = True
            restarted, restart_message = self.service.restart()
            if not restarted:
                return self._abort(previous, deps_changed, backup_dir, restart_message, restarted=False)

            say("Проверяю, что сервис действительно запустился...")
            healthy, health_message = self.service.wait_healthy(default_health_url())
            if not healthy:
                return self._abort(previous, deps_changed, backup_dir, f"новая версия не запустилась: {health_message}", restarted=True)
        except Exception as exc:  # noqa: BLE001 - whatever happens, never leave half-applied code behind
            return self._abort(previous, deps_changed, backup_dir, f"непредвиденная ошибка: {exc}", restarted=restart_attempted)

        return UpdateResult(
            True,
            f"Обновлено {status.local_version} -> {status.remote_version}. {detail}. Сервис перезапущен и работает.",
            previous, target, True,
        )

    # ---------------------------------------------------------------- rollback

    def _restore_code(self, sha: str) -> None:
        try:
            provider.reset_hard(self.repo_dir, sha)
        except provider.GitError:
            pass

    def _abort(self, previous: str, deps_changed: bool, backup_dir: Path | None, reason: str, restarted: bool) -> UpdateResult:
        """Return to the previous commit and make sure the old version runs."""
        self._log(f"Ошибка: {reason}. Откатываюсь на предыдущую версию...")
        notes: list[str] = []

        if restarted:
            self.service.stop()  # stop a crash-looping unit before touching code/DB
        self._restore_code(previous)

        if deps_changed:
            ok, detail = install_deps(self.repo_dir)
            if not ok:
                notes.append(f"зависимости старой версии не восстановлены ({detail})")

        if backup_dir and restarted and backup.schema_changed_since(self.state_dir, backup_dir):
            try:
                backup.restore_backup(self.state_dir, backup_dir)
                notes.append("БД восстановлена из резервной копии (новая версия успела изменить схему)")
            except OSError as exc:
                notes.append(f"БД не удалось восстановить из {backup_dir}: {exc}")

        running_old = False
        if restarted:
            ok, detail = self.service.start()
            if ok:
                running_old, detail = self.service.wait_healthy(default_health_url())
            if not running_old:
                notes.append(f"старая версия не поднялась: {detail}")
        else:
            running_old = True  # the old process was never stopped

        status_line = "Сервис работает на прежней версии." if running_old else "ВНИМАНИЕ: сервис не работает, проверьте `journalctl -u lumica -n 100`."
        message = f"Обновление не удалось: {reason}. Выполнен откат на {previous[:8]}. {status_line}"
        if notes:
            message += " " + "; ".join(notes) + "."
        return UpdateResult(False, message, previous, previous, restarted, rolled_back=True)

    def rollback(self, restore_db: bool = False) -> UpdateResult:
        """Manual return to the version that was installed before the last update."""
        with self._lock() as acquired:
            if not acquired:
                return UpdateResult(False, "Другое обновление уже выполняется, повторите позже")
            result = self._rollback_locked(restore_db)
        save_last_result(self.state_dir, {"kind": "rollback", **result.to_dict()})
        return result

    def _rollback_locked(self, restore_db: bool) -> UpdateResult:
        previous = self.previous_sha()
        if not previous:
            return UpdateResult(False, "Нет сохранённой предыдущей версии для отката")
        try:
            current = provider.current_sha(self.repo_dir)
            if current == previous:
                return UpdateResult(False, "Уже установлена предыдущая версия")
            deps_changed = provider.paths_changed(self.repo_dir, current, previous, "requirements.txt")
            if provider.is_dirty(self.repo_dir):
                return UpdateResult(False, "Есть локальные изменения отслеживаемых файлов, откат отменён")
            backup_dir = backup.latest_backup(self.state_dir) if restore_db else None
            if restore_db and not backup_dir:
                return UpdateResult(False, "Резервных копий БД нет, откат с --restore-db невозможен")
            save_previous_sha(self.state_dir, current)  # so that a second rollback returns forward
            self._log("Останавливаю сервис...")
            self.service.stop()
            provider.reset_hard(self.repo_dir, previous)
        except provider.GitError as exc:
            return UpdateResult(False, f"откат не удался: {exc}")

        notes = []
        if deps_changed:
            ok, detail = install_deps(self.repo_dir)
            if not ok:
                notes.append(f"зависимости не обновлены: {detail}")
        if backup_dir:
            backup.restore_backup(self.state_dir, backup_dir)
            notes.append(f"БД восстановлена из {backup_dir}")

        ok, detail = self.service.start()
        healthy = False
        if ok:
            healthy, detail = self.service.wait_healthy(default_health_url())
        message = f"Откат на {provider.describe(self.repo_dir, previous)}: " + ("сервис работает" if healthy else f"сервис не поднялся ({detail})")
        if notes:
            message += ". " + "; ".join(notes)
        return UpdateResult(healthy, message, current, previous, True, rolled_back=True)

    # ----------------------------------------------------------------- restart

    def restart_service(self) -> tuple[bool, str]:
        return self.service.restart()


__all__ = ["UpdateManager"]
