"""systemd control + post-restart verification."""

from __future__ import annotations

import os
import subprocess
import time
import urllib.error
import urllib.request



class ServiceController:
    """Restart/stop/start the main unit and check that it is *really* up.

    Non-root callers go through `sudo -n systemctl ...`; install.sh grants the
    service user a scoped rule for exactly these verbs on this unit.
    """

    def __init__(self, name: str):
        self.name = name if name.endswith(".service") else f"{name}.service"
        # install.sh creates `<service>-update.service`, a oneshot unit that runs
        # the update outside the main unit's cgroup (so a restart can't kill it).
        self.update_unit = f"{self.name[: -len('.service')]}-update.service"

    def _systemctl(self, *args: str, timeout: int = 90) -> tuple[bool, str]:
        override = os.getenv("UPDATE_RESTART_CMD", "").strip()
        if override and args and args[0] == "restart":
            cmd = override.split()
        elif getattr(os, "geteuid", lambda: 1)() == 0:
            cmd = ["systemctl", *args]
        else:
            cmd = ["sudo", "-n", "systemctl", *args]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return False, f"команда недоступна на этом хосте: {cmd[0]}"
        except OSError as exc:  # e.g. PermissionError when sudo/systemctl can't be executed
            return False, f"не удалось выполнить {cmd[0]}: {exc}"
        except subprocess.TimeoutExpired:
            return False, f"systemctl {args[0]}: превышено время ожидания"
        if result.returncode != 0:
            stderr = (result.stderr.strip() or result.stdout.strip())[-500:]
            return False, stderr or "нет прав (см. UPDATE_RESTART_CMD / sudoers)"
        return True, ""

    def restart(self) -> tuple[bool, str]:
        ok, err = self._systemctl("restart", self.name)
        return (True, "сервис перезапущен") if ok else (False, f"перезапуск не выполнен: {err}")

    def stop(self) -> tuple[bool, str]:
        ok, err = self._systemctl("stop", self.name)
        return (True, "сервис остановлен") if ok else (False, f"остановка не выполнена: {err}")

    def start(self) -> tuple[bool, str]:
        ok, err = self._systemctl("start", self.name)
        return (True, "сервис запущен") if ok else (False, f"запуск не выполнен: {err}")

    def is_active(self) -> bool:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", self.name], capture_output=True, text=True, timeout=15
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.stdout.strip() == "active"

    def unit_exists(self, unit: str) -> bool:
        try:
            result = subprocess.run(["systemctl", "cat", unit], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0

    def start_unit_detached(self, unit: str) -> tuple[bool, str]:
        ok, err = self._systemctl("start", "--no-block", unit)
        return (True, "запущено") if ok else (False, err)

    def wait_healthy(self, health_url: str | None, timeout: int = 60, stable_for: int = 8) -> tuple[bool, str]:
        """The unit must be `active` for `stable_for` seconds in a row (catches
        crash loops, where `restart` itself returns 0) and, if a health URL is
        configured, answer HTTP 200 before `timeout` expires."""
        deadline = time.monotonic() + timeout
        active_since: float | None = None
        health_ok = health_url is None
        last_problem = "сервис не стал active"

        while time.monotonic() < deadline:
            if self.is_active():
                active_since = active_since or time.monotonic()
            else:
                active_since = None
                last_problem = "сервис не active (упал или перезапускается)"

            if not health_ok and health_url:
                try:
                    with urllib.request.urlopen(health_url, timeout=3) as response:
                        health_ok = response.status == 200
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    last_problem = f"health-check {health_url} не отвечает: {exc}"

            if active_since and health_ok and time.monotonic() - active_since >= stable_for:
                return True, "сервис работает"
            time.sleep(1)

        return False, last_problem


def default_health_url() -> str | None:
    """http://127.0.0.1:<FLASK_PORT>/health, UPDATE_HEALTH_URL overrides, 'off' disables."""
    override = os.getenv("UPDATE_HEALTH_URL", "").strip()
    if override.lower() in {"off", "none", "0", "false"}:
        return None
    if override:
        return override
    return f"http://127.0.0.1:{os.getenv('FLASK_PORT', '8000').strip() or '8000'}/health"


__all__ = ["ServiceController", "default_health_url"]
