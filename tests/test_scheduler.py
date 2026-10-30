import logging

from lumica.jobs import scheduler
from lumica.jobs.scheduler import ScheduledJob, job_status, run_due_jobs, run_job


def _failing(counter=None):
    def job():
        if counter is not None:
            counter["n"] += 1
        raise RuntimeError("boom")
    return job


def test_failing_job_is_logged_with_traceback_not_swallowed(caplog):
    job = ScheduledJob("напоминания", 10, _failing())
    with caplog.at_level(logging.ERROR, logger="lumica.scheduler"):
        assert run_job(job, now=100.0) is False
    record = caplog.records[0]
    assert "напоминания" in record.getMessage() and "подряд ошибок: 1" in record.getMessage()
    assert record.exc_info and "boom" in str(record.exc_info[1])  # трассировка сохранена


def test_one_failing_job_does_not_stop_the_others(caplog):
    ran = []
    jobs = [
        ScheduledJob("падает", 10, _failing()),
        ScheduledJob("работает", 10, lambda: ran.append("ok")),
    ]
    with caplog.at_level(logging.ERROR, logger="lumica.scheduler"):
        run_due_jobs(jobs, now=100.0)
    assert ran == ["ok"] and len(caplog.records) == 1
    assert [j.next_run for j in jobs] == [110.0, 110.0]      # расписание двигается и после ошибки


def test_repeated_failures_are_throttled_but_recovery_is_reported(caplog):
    job = ScheduledJob("мониторинг", 60, _failing())
    with caplog.at_level(logging.DEBUG, logger="lumica.scheduler"):
        run_job(job, now=0.0)                    # подробно
        run_job(job, now=60.0)                   # не спамим
        run_job(job, now=120.0)                  # не спамим
        run_job(job, now=scheduler.REPEAT_LOG_SECONDS + 1)  # прошло время - снова подробно
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 2 and "подряд ошибок: 4" in errors[1].getMessage()
    job.func = lambda: None
    with caplog.at_level(logging.WARNING, logger="lumica.scheduler"):
        assert run_job(job, now=1000.0) is True
    assert "снова работает" in caplog.records[-1].getMessage() and "4" in caplog.records[-1].getMessage()
    assert job.consecutive_failures == 0 and job.last_ok == 1000.0


def test_jobs_run_only_when_due_and_status_is_reported():
    counter = {"n": 0}
    good = ScheduledJob("a", 30, lambda: counter.__setitem__("n", counter["n"] + 1))
    bad = ScheduledJob("b", 30, _failing())
    run_due_jobs([good, bad], now=0.0)
    run_due_jobs([good, bad], now=10.0)   # ещё рано
    assert counter["n"] == 1
    run_due_jobs([good, bad], now=31.0)
    assert counter["n"] == 2
    status = {item["name"]: item for item in job_status([good, bad])}
    assert status["a"]["failing"] is False and status["a"]["last_ok"] == 31.0
    assert status["b"]["failing"] is True and status["b"]["consecutive_failures"] == 2


def test_default_job_table_covers_all_five_background_tasks(monkeypatch):
    monkeypatch.setenv("REMINDERS_INTERVAL_SEC", "600")
    jobs = scheduler.build_jobs(object())
    assert [j.name for j in jobs] == [
        "синхронизация панелей", "истечение подписок", "напоминания об окончании",
        "напоминания об оплате", "мониторинг серверов",
    ]
    assert all(callable(j.func) and j.interval > 0 for j in jobs)
