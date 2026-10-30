"""Background scheduler loop.

Каждая задача выполняется отдельно: ошибка одной не останавливает остальные, но всегда
попадает в лог (с трассировкой). Чтобы постоянная поломка не засоряла журнал, повтор
одной и той же ошибки подробно пишется раз в REPEAT_LOG_SECONDS, а возвращение к норме
отмечается отдельной строкой."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Callable

from lumica.infra.bootstrap import _bootstrap_multi_panel_state
from lumica.infra.bootstrap import bootstrap_runtime
from lumica.infra.db import SessionLocal
from lumica.jobs.expire_subscriptions import run_expire_subscriptions
from lumica.jobs.panel_monitor import run_panel_monitoring
from lumica.jobs.subscription_reminders import run_subscription_reminders
from lumica.jobs.payment_due_reminders import run_payment_due_reminders
from lumica.services.panels import PanelRegistry, sync_all_panels, sync_group_members_from_inbounds

logger = logging.getLogger("lumica.scheduler")

REPEAT_LOG_SECONDS = 600


@dataclass
class ScheduledJob:
    name: str
    interval: float
    func: Callable[[], object]
    next_run: float = 0.0
    consecutive_failures: int = 0
    last_ok: float | None = None
    last_error: str | None = None
    last_error_logged: float = 0.0


def _record_failure(job: ScheduledJob, now: float) -> None:
    job.consecutive_failures += 1
    job.last_error = "ошибка"  # короткая метка; подробности - в логе
    first = job.consecutive_failures == 1
    if first or now - job.last_error_logged >= REPEAT_LOG_SECONDS:
        job.last_error_logged = now
        logger.exception(
            "Фоновая задача «%s» завершилась ошибкой (подряд ошибок: %d)", job.name, job.consecutive_failures
        )
    else:
        logger.debug("Фоновая задача «%s» снова упала (подряд: %d)", job.name, job.consecutive_failures)


def run_job(job: ScheduledJob, now: float) -> bool:
    """Выполняет одну задачу, не пропуская ошибки наружу. Возвращает True при успехе."""
    try:
        job.func()
    except Exception:  # noqa: BLE001 - планировщик не должен падать из-за одной задачи
        _record_failure(job, now)
        return False
    if job.consecutive_failures:
        logger.warning(
            "Фоновая задача «%s» снова работает (до этого ошибок подряд: %d)", job.name, job.consecutive_failures
        )
    job.consecutive_failures = 0
    job.last_error = None
    job.last_ok = now
    return True


def run_due_jobs(jobs: list[ScheduledJob], now: float) -> None:
    for job in jobs:
        if now >= job.next_run:
            run_job(job, now)
            job.next_run = now + job.interval


def job_status(jobs: list[ScheduledJob]) -> list[dict]:
    """Состояние задач для будущего экрана «Проверка готовности»."""
    return [
        {
            "name": job.name,
            "interval": job.interval,
            "last_ok": job.last_ok,
            "failing": job.consecutive_failures > 0,
            "consecutive_failures": job.consecutive_failures,
        }
        for job in jobs
    ]


def _sync_panels(registry: PanelRegistry) -> None:
    with SessionLocal() as db:
        _bootstrap_multi_panel_state(db)
        result = sync_all_panels(db, registry)
        if result.get("ok"):
            sync_group_members_from_inbounds(db)
        db.commit()


def build_jobs(registry: PanelRegistry) -> list[ScheduledJob]:
    sync_interval = max(30, int(os.getenv("PANEL_SYNC_INTERVAL_SEC", "300")))
    expire_interval = max(60, int(os.getenv("EXPIRE_SUBSCRIPTIONS_INTERVAL_SEC", "3600")))
    reminders_interval = max(300, int(os.getenv("REMINDERS_INTERVAL_SEC", "600")))
    return [
        ScheduledJob("синхронизация панелей", sync_interval, lambda: _sync_panels(registry)),
        ScheduledJob("истечение подписок", expire_interval, run_expire_subscriptions),
        ScheduledJob("напоминания об окончании", reminders_interval, run_subscription_reminders),
        ScheduledJob("напоминания об оплате", 30, run_payment_due_reminders),
        ScheduledJob("мониторинг серверов", 60, lambda: run_panel_monitoring(registry)),
    ]


def run_scheduler_forever() -> None:
    enabled = os.getenv("ENABLE_BACKGROUND_JOBS", "true").strip().lower() in {"1", "true", "yes", "on"}
    if not enabled:
        return

    jobs = build_jobs(PanelRegistry())
    bootstrap_runtime(with_multi_panel_state=True)
    logger.info("Планировщик запущен: %s", ", ".join(f"{job.name} / {job.interval:g} с" for job in jobs))

    while True:
        run_due_jobs(jobs, time.time())
        time.sleep(3)


__all__ = ["run_scheduler_forever", "run_due_jobs", "run_job", "build_jobs", "job_status", "ScheduledJob"]
