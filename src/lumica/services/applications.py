"""Заявки (applications): единственное место с бизнес-логикой их жизненного
цикла - API-роуты (api/routes/applications.py) не дублируют переходы
статусов, только вызывают эти функции (тот же паттерн, что и UpdateManager)."""

from __future__ import annotations

from datetime import datetime, timezone

from lumica.domain.models import Application, User

VALID_TRANSITIONS: dict[str, set[str]] = {
    "new": {"reviewing", "need_more_info", "approved", "rejected", "cancelled"},
    "reviewing": {"approved", "need_more_info", "rejected", "cancelled"},
    "need_more_info": {"reviewing", "cancelled"},
    "approved": set(),
    "rejected": set(),
    "cancelled": set(),
}


class ApplicationError(ValueError):
    pass


def create_application(
    db,
    *,
    user_id: int,
    full_name: str,
    tariff_id: int | None = None,
    needs_proxy: bool = False,
    extra_info: str | None = None,
) -> Application:
    full_name = (full_name or "").strip()
    if not full_name:
        raise ApplicationError("full_name обязателен")

    application = Application(
        user_id=user_id,
        full_name=full_name,
        tariff_id=tariff_id,
        needs_proxy=1 if needs_proxy else 0,
        extra_info=(extra_info or "").strip() or None,
        status="new",
    )
    db.add(application)
    db.flush()
    return application


def _transition(application: Application, new_status: str, *, staff_user_id: int | None, note: str | None) -> None:
    allowed = VALID_TRANSITIONS.get(application.status, set())
    if new_status not in allowed:
        raise ApplicationError(f"нельзя перевести заявку из {application.status} в {new_status}")
    application.status = new_status
    application.reviewed_by = staff_user_id
    application.reviewed_at = datetime.now(timezone.utc)
    if note is not None:
        application.review_note = note


def start_review(db, application: Application, *, staff_user_id: int) -> None:
    _transition(application, "reviewing", staff_user_id=staff_user_id, note=None)


def request_more_info(db, application: Application, *, staff_user_id: int, note: str | None) -> None:
    if not (note or "").strip():
        raise ApplicationError("нужно указать, что требуется уточнить")
    _transition(application, "need_more_info", staff_user_id=staff_user_id, note=note.strip())


def approve(db, application: Application, *, staff_user_id: int) -> User:
    """Одобряет заявку. Пользователь (клиент) уже существует - создаётся
    автоматически при первом входе через Telegram (/api/tg/auth) - поэтому
    approve() ничего не создаёт, а лишь помечает заявку и возвращает клиента
    для дальнейших шагов (например, выставление счёта на оплату тарифа)."""
    if application.status not in ("new", "reviewing"):
        raise ApplicationError(f"нельзя одобрить заявку в статусе {application.status}")
    _transition(application, "approved", staff_user_id=staff_user_id, note=None)

    user = db.query(User).filter(User.id == application.user_id).first()
    if not user:
        raise ApplicationError("привязанный пользователь не найден")
    return user


def reject(db, application: Application, *, staff_user_id: int, note: str | None = None) -> None:
    if application.status not in ("new", "reviewing", "need_more_info"):
        raise ApplicationError(f"нельзя отклонить заявку в статусе {application.status}")
    _transition(application, "rejected", staff_user_id=staff_user_id, note=note)


def cancel(db, application: Application) -> None:
    if application.status in ("approved", "rejected", "cancelled"):
        raise ApplicationError(f"нельзя отменить заявку в статусе {application.status}")
    application.status = "cancelled"


__all__ = [
    "ApplicationError",
    "VALID_TRANSITIONS",
    "create_application",
    "start_review",
    "request_more_info",
    "approve",
    "reject",
    "cancel",
]
