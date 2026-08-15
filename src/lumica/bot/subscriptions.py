"""`/subscription` - показывает подписку пользователя. Если он администратор
группы - дополнительно показывает подписку каждого участника группы,
КАЖДУЮ ОТДЕЛЬНЫМ СООБЩЕНИЕМ (как и попросили), а не одним общим текстом."""

from __future__ import annotations

from aiogram import Router, types
from aiogram.filters import Command

from lumica.domain.models import Group, Subscription, User
from lumica.infra.db import SessionLocal
from lumica.services import groups as group_service

router = Router(name="subscriptions")

_STATUS_LABELS = {
    "active": "🟢 Активна",
    "expiring": "🟡 Скоро закончится",
    "expired": "🔴 Закончилась",
    "draft": "⚪ Черновик (не оплачена)",
    "lifetime": "🟢 Бессрочная",
    "cancelled": "⚪ Отменена",
}


def _format_subscription(sub: Subscription, *, owner_name: str | None = None) -> str:
    status_label = _STATUS_LABELS.get((sub.status or "").lower(), sub.status or "неизвестно")
    lines = []
    if owner_name:
        lines.append(f"👤 {owner_name}")
    lines.append(f"Подписка №{sub.id}")
    lines.append(status_label)
    if sub.access_until:
        lines.append(f"До {sub.access_until.strftime('%d.%m.%Y')}")
    return "\n".join(lines)


@router.message(Command("subscription"))
async def cmd_subscription(message: types.Message) -> None:
    if not message.from_user:
        return
    telegram_id = str(message.from_user.id)

    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == telegram_id).first()
        if not user:
            await message.answer("Вы ещё не зарегистрированы. Отправьте /start, чтобы оставить заявку.")
            return

        own_subs = (
            db.query(Subscription)
            .filter(Subscription.user_id == user.id)
            .order_by(Subscription.created_at.desc())
            .all()
        )

        if not own_subs:
            await message.answer("У вас пока нет подписки. Оставьте заявку через /start или обратитесь в поддержку.")
        else:
            for sub in own_subs:
                await message.answer(_format_subscription(sub))

        group = db.query(Group).filter(Group.id == user.group_id).first() if user.group_id else None
        if not group or not group_service.is_group_admin(user, group):
            return

        members = db.query(User).filter(User.group_id == group.id, User.id != user.id).all()
        if not members:
            return

        await message.answer(f"👥 Группа «{group.name or group.id}» - подписки участников:")
        for member in members:
            member_subs = (
                db.query(Subscription)
                .filter(Subscription.user_id == member.id)
                .order_by(Subscription.created_at.desc())
                .all()
            )
            member_name = member.name or member.username or f"id{member.telegram_id}"
            if not member_subs:
                await message.answer(f"👤 {member_name}\nПодписки нет")
                continue
            for sub in member_subs:
                await message.answer(_format_subscription(sub, owner_name=member_name))


__all__ = ["router"]
