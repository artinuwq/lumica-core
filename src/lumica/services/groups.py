"""Группы (ТЗ п.15-17, переименовано из «семей» для более широкого будущего
применения). Все мутации - создание, переименование, удаление, управление
составом - доступны только системному админу (роль admin/super_admin), не
самим участникам: состав формируется вручную, без self-service приглашений.
Единственное место с этой логикой - api/routes/groups.py её не дублирует."""

from __future__ import annotations

from lumica.domain.models import Group, User


class GroupError(ValueError):
    pass


def _get_user(db, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise GroupError("пользователь не найден")
    return user


def create_group(db, *, name: str | None = None, admin_user_id: int | None = None) -> Group:
    group = Group(name=(name or "").strip() or None)
    db.add(group)
    db.flush()
    if admin_user_id is not None:
        set_admin(db, group, admin_user_id)
    return group


def rename_group(db, group: Group, *, name: str | None) -> None:
    group.name = (name or "").strip() or None


def delete_group(db, group: Group) -> None:
    db.query(User).filter(User.group_id == group.id).update({User.group_id: None})
    db.delete(group)


def add_member(db, group: Group, user_id: int) -> User:
    user = _get_user(db, user_id)
    if user.group_id is not None and user.group_id != group.id:
        raise GroupError("пользователь уже состоит в другой группе")
    user.group_id = group.id
    return user


def remove_member(db, group: Group, user_id: int) -> None:
    user = _get_user(db, user_id)
    if user.group_id != group.id:
        raise GroupError("пользователь не состоит в этой группе")
    if group.admin_user_id == user_id:
        raise GroupError("нельзя удалить администратора группы - сначала назначьте нового или удалите группу")
    user.group_id = None


def set_admin(db, group: Group, user_id: int) -> User:
    """Назначает пользователя администратором группы (добавляет в группу,
    если ещё не состоит)."""
    user = _get_user(db, user_id)
    if user.group_id is not None and user.group_id != group.id:
        raise GroupError("пользователь уже состоит в другой группе")
    user.group_id = group.id
    group.admin_user_id = user_id
    return user


def is_group_admin(user: User, group: Group) -> bool:
    return group.admin_user_id is not None and group.admin_user_id == user.id


__all__ = [
    "GroupError",
    "create_group",
    "rename_group",
    "delete_group",
    "add_member",
    "remove_member",
    "set_admin",
    "is_group_admin",
]
