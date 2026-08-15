"""Поиск/связывание/ручное создание пользователей.

Позволяет админу создать пользователя ДО того, как он впервые зайдёт в бот
(по username или телефону), и связывает эту запись с Telegram-аккаунтом при
первом реальном обращении - без создания дубликата."""

from __future__ import annotations

from sqlalchemy import func

from lumica.domain.models import User


class UserProvisioningError(ValueError):
    pass


def find_by_telegram_id(db, telegram_id: str) -> User | None:
    return db.query(User).filter(User.telegram_id == telegram_id).first()


def find_preprovisioned_by_username(db, username: str) -> User | None:
    """Ищет заранее созданного администратором пользователя (ещё без
    telegram_id) по username, без учёта регистра. Точное сравнение через
    lower(), а не ILIKE - имена пользователей Telegram могут содержать "_",
    который в LIKE является спецсимволом."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return None
    return (
        db.query(User)
        .filter(User.telegram_id.is_(None))
        .filter(User.username.isnot(None))
        .filter(func.lower(User.username) == username.lower())
        .first()
    )


def link_telegram_identity(db, user: User, *, telegram_id: str, username: str | None, name: str | None) -> User:
    user.telegram_id = telegram_id
    if username:
        user.username = username
    if name and not user.name:
        user.name = name
    return user


def create_preprovisioned_user(
    db,
    *,
    username: str | None = None,
    phone: str | None = None,
    name: str | None = None,
    role: str = "user",
) -> User:
    """Создаёт пользователя вручную (админ), до его первого захода в бот.
    Нужен хотя бы один из username/phone, чтобы потом было по чему
    связать запись с реальным Telegram-аккаунтом."""
    username = (username or "").strip().lstrip("@") or None
    phone = (phone or "").strip() or None
    if not username and not phone:
        raise UserProvisioningError("нужно указать хотя бы username или телефон")

    if username:
        existing = db.query(User).filter(func.lower(User.username) == username.lower()).first()
        if existing:
            raise UserProvisioningError(f"пользователь с username @{username} уже существует")
    if phone:
        existing = db.query(User).filter(User.phone == phone).first()
        if existing:
            raise UserProvisioningError(f"пользователь с телефоном {phone} уже существует")

    user = User(
        username=username,
        phone=phone,
        name=(name or "").strip() or None,
        role=role,
        status="unverified",
    )
    db.add(user)
    db.flush()
    return user


__all__ = [
    "UserProvisioningError",
    "find_by_telegram_id",
    "find_preprovisioned_by_username",
    "link_telegram_identity",
    "create_preprovisioned_user",
]
