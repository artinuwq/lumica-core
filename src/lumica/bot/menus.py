"""Главное меню бота (клиент / администратор) и просмотр подписок."""

from __future__ import annotations

import html
import os
from decimal import Decimal, InvalidOperation
from urllib.parse import quote

from aiogram import Router, types
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

from lumica.domain.models import Group, Subscription, SubscriptionVpnAccount, User, VpnAccount
from lumica.infra.db import SessionLocal
from lumica.services import groups as group_service
from lumica.services.roles import is_authorized, load_role_bindings, role_allows

router = Router(name="menus")

DEFAULT_WEBAPP_URL = "https://lumica.duckdns.org/"
USER_GREETING = (
    "Здравствуйте! Здесь вы можете посмотреть подписки, статус инфраструктуры и связаться с поддержкой."
)
ADMIN_GREETING = "Добро пожаловать в Lumica"


def webapp_url() -> str:
    """URL mini app. WEBAPP_URL из .env имеет приоритет (кроме заглушки example.com)."""
    value = os.getenv("WEBAPP_URL", "").strip()
    if not value or "example.com" in value:
        return DEFAULT_WEBAPP_URL
    return value


def support_url() -> str:
    return os.getenv("SUPPORT_URL", "https://t.me/NovenWrk")


def user_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="Подписка", callback_data="menu:subscription"),
            InlineKeyboardButton(text="Оплатить", callback_data="menu:pay"),
        ],
        [
            InlineKeyboardButton(text="Рабочий аккаунт", url=support_url()),
            InlineKeyboardButton(text="Статус серверов", callback_data="menu:status"),
        ],
        [InlineKeyboardButton(text="Настройки", callback_data="menu:settings")],
    ])


def admin_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Открыть mini app", web_app=WebAppInfo(url=webapp_url()))],
        [InlineKeyboardButton(text="Подписка", callback_data="menu:subscription")],
        [InlineKeyboardButton(text="Настройки", callback_data="menu:settings")],
    ])


def menu_button() -> InlineKeyboardMarkup:
    """Одна кнопка «Меню» - возвращает в стандартное меню, как при приветствии."""
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="Меню", callback_data="menu:main")]])


def is_admin_telegram_user(user: User | None, telegram_id: int) -> bool:
    if user is not None and role_allows(user.role, "admin"):
        return True
    return is_authorized(telegram_id, "admin", load_role_bindings())


async def answer_main_menu(message: types.Message, *, is_admin: bool) -> None:
    if is_admin:
        await message.answer(ADMIN_GREETING, reply_markup=admin_menu())
    else:
        await message.answer(USER_GREETING, reply_markup=user_menu())


# --------------------------------------------------------------- подписки

def _fmt_price(value) -> str:
    if value is None or value == "":
        return "—"
    try:
        text = f"{Decimal(str(value)):f}"
    except InvalidOperation:
        return str(value)
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text} ₽"


def _fmt_until(subscription: Subscription) -> str:
    if (subscription.status or "").strip().lower() == "lifetime":
        return "Бессрочно"
    return subscription.access_until.strftime("%d.%m.%Y") if subscription.access_until else "не указана"


def _build_subscription_url(explicit, sub_id) -> str | None:
    value = str(explicit or "").strip()
    if value.lower().startswith(("http://", "https://")):
        return value
    sid = str(sub_id or "").strip()
    if not sid:
        return None
    sid_quoted = quote(sid)
    subscription_base = os.getenv("PANEL_SUBSCRIPTION_BASE_URL", "").strip().rstrip("/")
    public_base = os.getenv("PANEL_PUBLIC_BASE_URL", "").strip().rstrip("/")
    template = os.getenv("PANEL_SUBSCRIPTION_URL_TEMPLATE", "").strip()
    if template:
        for base in (subscription_base, public_base, ""):
            try:
                candidate = template.format(sub_id=sid, base_url=base).strip()
            except (KeyError, IndexError, ValueError):
                break
            if candidate.lower().startswith(("http://", "https://")):
                return candidate
    for base in (subscription_base, public_base):
        if base:
            return f"{base}/sub/{sid_quoted}"
    return None


def subscription_urls(db, subscription: Subscription) -> list[str]:
    """Ссылки подписки (по одной на клиента панели; одинаковые склеиваются)."""
    accounts = (
        db.query(VpnAccount)
        .join(SubscriptionVpnAccount, SubscriptionVpnAccount.vpn_account_id == VpnAccount.id)
        .filter(SubscriptionVpnAccount.subscription_id == subscription.id)
        .order_by(VpnAccount.id.asc())
        .all()
    )
    if not accounts:
        accounts = (
            db.query(VpnAccount)
            .filter(VpnAccount.user_id == subscription.user_id, VpnAccount.status == "active")
            .order_by(VpnAccount.id.asc())
            .all()
        )
    urls: list[str] = []
    for account in accounts:
        meta = account.meta_json if isinstance(account.meta_json, dict) else {}
        url = _build_subscription_url(meta.get("sub_url"), meta.get("sub_id"))
        if url and url not in urls:
            urls.append(url)
    return urls


def format_subscription_message(
    subscription: Subscription,
    urls: list[str],
    *,
    hide_billing: bool = False,
    owner_name: str | None = None,
) -> str:
    """HTML-текст подписки: срок оплаты, цена и ссылки цитатой."""
    lines: list[str] = []
    if owner_name:
        lines.append(f"👤 {html.escape(owner_name)}")
    if hide_billing:
        lines.append("Дату оплаты и стоимость семейной подписки видит только администратор группы.")
    else:
        lines.append(f"Дата оплаты до: {_fmt_until(subscription)}")
        lines.append(f"Цена: {_fmt_price(subscription.price_amount)}")
    lines.append("")
    if owner_name:
        header = "Подписки:" if len(urls) > 1 else "Подписка:"
    else:
        header = "Ваши личные подписки:" if len(urls) > 1 else "Ваша личная подписка:"
    if urls:
        lines.append(header)
        lines.append("<blockquote>" + "\n".join(f"<code>{html.escape(url)}</code>" for url in urls) + "</blockquote>")
    else:
        lines.append("Ссылка на подписку пока не выдана. Напишите в рабочий аккаунт.")
    return "\n".join(lines)


def _display_name(user: User) -> str:
    return user.name or (f"@{user.username}" if user.username else f"id{user.telegram_id}")


def collect_subscription_messages(db, user: User | None) -> list[str]:
    if user is None:
        return ["Вы ещё не зарегистрированы. Отправьте /start, чтобы оставить заявку."]
    group = db.query(Group).filter(Group.id == user.group_id).first() if user.group_id else None
    is_group_admin = bool(group and group_service.is_group_admin(user, group))
    hide_billing = bool(group and not is_group_admin)

    def _subs(user_id: int) -> list[Subscription]:
        return (
            db.query(Subscription)
            .filter(Subscription.user_id == user_id, Subscription.status != "draft")
            .order_by(Subscription.id.asc())
            .all()
        )

    messages: list[str] = []
    own = _subs(user.id)
    if not own:
        messages.append("Подписок пока нет.")
    for item in own:
        messages.append(format_subscription_message(item, subscription_urls(db, item), hide_billing=hide_billing))

    if is_group_admin:
        members = db.query(User).filter(User.group_id == group.id, User.id != user.id).order_by(User.id.asc()).all()
        for member in members:
            member_subs = _subs(member.id)
            name = _display_name(member)
            if not member_subs:
                messages.append(f"👤 {html.escape(name)}\nПодписки нет.")
                continue
            for item in member_subs:
                messages.append(format_subscription_message(item, subscription_urls(db, item), owner_name=name))
    return messages


async def send_subscription_info(message: types.Message, tg_user: types.User) -> None:
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(tg_user.id)).first()
        texts = collect_subscription_messages(db, user)
    for text in texts:
        await message.answer(text, parse_mode="HTML")


# ------------------------------------------------------------------ колбэки

@router.callback_query(lambda query: query.data == "menu:main")
async def menu_main(query: CallbackQuery) -> None:
    await query.answer()
    if not query.from_user or not query.message:
        return
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        is_admin = is_admin_telegram_user(user, query.from_user.id)
    await answer_main_menu(query.message, is_admin=is_admin)


@router.callback_query(lambda query: query.data == "menu:subscription")
async def subscription_menu(query: CallbackQuery) -> None:
    await query.answer()
    if query.from_user and query.message:
        await send_subscription_info(query.message, query.from_user)


@router.callback_query(lambda query: query.data == "menu:status")
async def status_menu(query: CallbackQuery) -> None:
    await query.answer("Статус серверов доступен в Mini App.", show_alert=True)


@router.callback_query(lambda query: query.data == "menu:settings")
async def settings_menu(query: CallbackQuery) -> None:
    await query.answer("Настройки скоро появятся.", show_alert=True)


__all__ = [
    "router",
    "user_menu",
    "admin_menu",
    "menu_button",
    "answer_main_menu",
    "send_subscription_info",
    "format_subscription_message",
    "collect_subscription_messages",
    "is_admin_telegram_user",
    "webapp_url",
]
