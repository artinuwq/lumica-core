"""Полное удаление клиента из базы и ручная смена его идентификации.

Удаление стирает строку пользователя и всё, что на неё ссылается (подписки,
платежи, VPN-аккаунты в нашей БД и т. д.). Клиенты на самих панелях 3x-ui не
затрагиваются. Если клиент был администратором семьи, группа не
расформировывается: администратором становится следующий участник (добавленный
после удалённого, иначе первый из оставшихся); если участников не осталось,
группа удаляется.
"""

from __future__ import annotations

import re

from sqlalchemy import delete, select, update

from lumica.domain.models import Base, Group, User
from lumica.services import groups as group_service

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{5,32}$")


class IdentityError(ValueError):
    """Некорректные данные идентификации (текст показывается администратору)."""


def normalize_identity(body: dict) -> dict:
    """Проверяет присланные поля и возвращает только изменяемые: name, username, telegram_id."""
    values: dict = {}
    if "name" in body:
        values["name"] = str(body.get("name") or "").strip()[:120] or None
    if "username" in body:
        raw = str(body.get("username") or "").strip().lstrip("@")
        if raw and not USERNAME_RE.match(raw):
            raise IdentityError("Username: 5-32 символа, латиница, цифры и «_»")
        values["username"] = raw or None
    if "telegram_id" in body:
        raw = str(body.get("telegram_id") or "").strip()
        if raw and not raw.isdigit():
            raise IdentityError("Telegram ID должен состоять только из цифр")
        values["telegram_id"] = raw or None
    return values


def _purge(db, table, condition, _depth: int = 0) -> None:
    """Удаляет строки table по условию вместе с зависимыми: обнуляет необязательные
    внешние ключи и рекурсивно удаляет строки с обязательными."""
    pk_columns = list(table.primary_key.columns)
    if _depth > 8 or len(pk_columns) != 1:
        db.execute(delete(table).where(condition))
        return
    pk = pk_columns[0]
    ids = [row[0] for row in db.execute(select(pk).where(condition))]
    if not ids:
        return
    for child in Base.metadata.tables.values():
        for fk in child.foreign_keys:
            if fk.column is not pk:
                continue
            column = fk.parent
            if child is table and column.nullable:
                continue
            if column.nullable:
                db.execute(update(child).where(column.in_(ids)).values({column.name: None}))
            else:
                _purge(db, child, column.in_(ids), _depth + 1)
    db.execute(delete(table).where(pk.in_(ids)))


def delete_user(db, user: User) -> dict:
    """Удаляет пользователя. Возвращает сводку: назначенные админы групп и удалённые группы."""
    summary: dict = {"promoted": [], "deleted_groups": []}
    for group in db.query(Group).filter(Group.admin_user_id == user.id).all():
        members = (
            db.query(User)
            .filter(User.group_id == group.id, User.id != user.id)
            .order_by(User.id.asc())
            .all()
        )
        successor = next((member for member in members if member.id > user.id), None) or (members[0] if members else None)
        if successor is not None:
            group_service.set_admin(db, group, successor.id)
            summary["promoted"].append({"group_id": group.id, "user_id": successor.id})
        else:
            summary["deleted_groups"].append(group.id)
            group_id = group.id
            db.expunge(group)
            _purge(db, Group.__table__, Group.__table__.c.id == group_id)
    db.flush()
    user_id = user.id
    db.expunge(user)
    _purge(db, User.__table__, User.__table__.c.id == user_id)
    return summary


__all__ = ["IdentityError", "normalize_identity", "delete_user"]
