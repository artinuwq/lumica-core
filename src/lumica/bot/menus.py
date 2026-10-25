"""Главное меню бота (клиент / администратор) и просмотр подписок."""

from __future__ import annotations

import asyncio
import html
import os
from decimal import Decimal, InvalidOperation

from aiogram import Router, types
from aiogram.exceptions import TelegramAPIError
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

from lumica.domain.models import AppSetting, Group, Panel, Subscription, SubscriptionVpnAccount, User, VpnAccount
from lumica.infra.db import SessionLocal
from lumica.services import groups as group_service
from lumica.services import subscription_links as subscription_links_module
from lumica.services.panel_labels import server_code
from lumica.services.roles import is_authorized, load_role_bindings, role_allows

router = Router(name="menus")

DEFAULT_WEBAPP_URL = "https://lumica.duckdns.org/"
USER_GREETING = (
    "Здравствуйте! Добро пожаловать в инфраструктуру Lumica. Здесь вы можете посмотреть подписки, "
    "статус инфраструктуры и связаться с поддержкой."
)
HELP_TEXT = "Здесь будет справка."
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
            InlineKeyboardButton(text="📋 Подписка", callback_data="menu:subscription"),
            InlineKeyboardButton(text="💳 Оплатить", callback_data="menu:pay"),
        ],
        [
            InlineKeyboardButton(text="🖥 Статус серверов", callback_data="menu:status"),
            InlineKeyboardButton(text="🌐 Центр Lumica", callback_data="menu:help"),
        ],
        [InlineKeyboardButton(text="⚙️ Настройки", callback_data="menu:settings")],
    ])


def admin_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Открыть mini app", web_app=WebAppInfo(url=webapp_url()))],
        [InlineKeyboardButton(text="Подписка", callback_data="menu:subscription")],
        [InlineKeyboardButton(text="Настройки", callback_data="menu:settings")],
    ])


NO_DETAILS_TEXT = "Реквизиты для вас пока не настроены. Напишите в рабочий аккаунт"


def no_details_keyboard() -> InlineKeyboardMarkup:
    """[Меню] [Аккаунт] - под сообщением, что реквизиты ещё не настроены."""
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="Меню", callback_data="menu:main"),
        InlineKeyboardButton(text="Аккаунт", url=support_url()),
    ]])


def page_back_keyboard(label: str) -> InlineKeyboardMarkup:
    """Кнопка внизу «страницы» (статус серверов, справка): возвращает в меню, меняя это же сообщение."""
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=label, callback_data="menu:back")]])


def menu_button() -> InlineKeyboardMarkup:
    """Одна кнопка «Меню» - возвращает в стандартное меню, как при приветствии."""
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="Меню", callback_data="menu:main")]])


def is_admin_telegram_user(user: User | None, telegram_id: int) -> bool:
    if user is not None and role_allows(user.role, "admin"):
        return True
    return is_authorized(telegram_id, "admin", load_role_bindings())


# ---------------------------------------------------------- состояние серверов

PANEL_MONITOR_STATE_KEY = "telegram.panel_monitor_state"
EXCELLENT_CPU_BELOW = 50.0
EXCELLENT_RAM_BELOW = 80.0


def server_condition(health: str | None, cpu: float | None, ram: float | None) -> tuple[str, str]:
    """(эмодзи, слово): недоступен / отличное / среднее / доступен (нет данных о нагрузке).

    «Отличное» - CPU ниже 50% и RAM ниже 80%; если хотя бы одно условие не
    выполнено - «среднее»."""
    if str(health or "").lower() == "red":
        return "🔴", "недоступен"
    if cpu is None or ram is None:
        return "🟢", "доступен"
    if cpu < EXCELLENT_CPU_BELOW and ram < EXCELLENT_RAM_BELOW:
        return "🟢", "отличное"
    return "🟡", "среднее"


def servers_status_text(db) -> str:
    """Блок «Состояние серверов» для клиентов: все активные серверы сразу."""
    row = db.query(AppSetting).filter(AppSetting.key == PANEL_MONITOR_STATE_KEY).first()
    state = row.value_json if row and isinstance(row.value_json, dict) else {}
    lines: list[str] = []
    for panel in db.query(Panel).filter(Panel.is_active == 1).order_by(Panel.name.asc()).all():
        entry = state.get(panel.id) if isinstance(state.get(panel.id), dict) else {}
        health = panel.health_status or entry.get("health_status")
        emoji, word = server_condition(health, entry.get("cpu"), entry.get("mem"))
        lines.append(f"{emoji} {html.escape(panel.name)} - {word}")
    if not lines:
        return ""
    return "🌍 Состояние серверов\n" + "\n".join(lines)


def main_menu_content(is_admin: bool) -> tuple[str, InlineKeyboardMarkup]:
    return (ADMIN_GREETING, admin_menu()) if is_admin else (USER_GREETING, user_menu())


async def answer_main_menu(message: types.Message, *, is_admin: bool) -> None:
    text, markup = main_menu_content(is_admin)
    await message.answer(text, reply_markup=markup)


async def _show_page(query: CallbackQuery, text: str, markup: InlineKeyboardMarkup) -> None:
    """Меняет текущее сообщение на «страницу»; если изменить нельзя - отправляет новое."""
    if not query.message:
        return
    try:
        await query.message.edit_text(text, reply_markup=markup, parse_mode="HTML")
    except TelegramAPIError:
        await query.message.answer(text, reply_markup=markup, parse_mode="HTML")


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


def user_accounts(db, user_id: int) -> list[VpnAccount]:
    return (
        db.query(VpnAccount)
        .filter(VpnAccount.user_id == user_id, VpnAccount.status == "active")
        .order_by(VpnAccount.id.asc())
        .all()
    )


def subscription_links(db, subscription: Subscription) -> list[tuple[str | None, str]]:
    """Ссылки подписки как (подпись сервера, ссылка): по одной на клиента панели.
    Логика выбора ссылки та же, что в mini app: см. services/subscription_links.py."""
    accounts = (
        db.query(VpnAccount)
        .join(SubscriptionVpnAccount, SubscriptionVpnAccount.vpn_account_id == VpnAccount.id)
        .filter(SubscriptionVpnAccount.subscription_id == subscription.id)
        .order_by(VpnAccount.id.asc())
        .all()
    )
    return account_links(db, accounts or user_accounts(db, subscription.user_id))


def account_links(db, accounts: list[VpnAccount]) -> list[tuple[str | None, str]]:
    """Ссылки по подключениям клиента. Нужны и тогда, когда у клиента ещё нет записи подписки
    (подключения привязали, а срок и цену не назначали): ссылки всё равно выдаём."""
    links: list[tuple[str | None, str]] = []
    seen: set[str] = set()
    for account in accounts:
        meta = account.meta_json if isinstance(account.meta_json, dict) else {}
        panel = db.query(Panel).filter(Panel.id == meta.get("panel_id")).first() if meta.get("panel_id") else None
        extra_roots = [root] if panel and (root := subscription_links_module.panel_root(panel.base_url)) else []
        candidates = subscription_links_module.build_subscription_urls(
            meta.get("sub_id"), meta.get("sub_url"), extra_roots=extra_roots
        )
        url = subscription_links_module.pick_subscription_url(candidates)
        if url and url not in seen:
            seen.add(url)
            links.append((server_code(panel), url))
    return links


def format_subscription_message(
    subscription: Subscription,
    links: list,
    *,
    hide_billing: bool = False,
    owner_name: str | None = None,
    billing_note: str | None = None,
) -> str:
    """HTML-текст подписки.

    Своя подписка: срок оплаты и цена, затем для каждого сервера подпись
    «Сервер "De":» и ссылка цитатой. Подписка участника группы (её видит
    администратор): имя участника и ссылки, без срока и цены."""
    lines: list[str] = []
    if owner_name:
        lines += ["Подписка участника группы", f"👤 {html.escape(owner_name)}"]
    else:
        lines.append("Ваша подписка")
        lines.append("")
        if billing_note:  # записи подписки нет: вместо срока и цены - пояснение
            lines.append(billing_note)
        elif hide_billing:
            lines.append("Дату оплаты и стоимость семейной подписки видит только администратор группы.")
        else:
            lines.append(f"Дата оплаты до: {_fmt_until(subscription)}")
            lines.append(f"Цена: {_fmt_price(subscription.price_amount)}")
    entries = [(None, item) if isinstance(item, str) else item for item in links]
    notes = str(getattr(subscription, "notes", None) or "").strip()
    if not entries and not notes:
        lines += ["", "Ссылка на подписку пока не выдана. Напишите в рабочий аккаунт."]
        return "\n".join(lines)
    for label, url in entries:
        title = f'Сервер "{html.escape(label, quote=False)}":' if label else "Ссылка:"
        lines += ["", title, f"<blockquote><code>{html.escape(url)}</code></blockquote>"]
    if notes:  # отдельные прокси-ссылки - в самом низу, цитатой
        lines += ["", "Прокси-ссылки:", f"<blockquote>{html.escape(notes[:2500])}</blockquote>"]
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
        links = account_links(db, user_accounts(db, user.id))
        if links:
            if group and not is_group_admin:
                admin = db.query(User).filter(User.id == group.admin_user_id).first() if group.admin_user_id else None
                note = (
                    f"Оплату вносит администратор группы «{html.escape(_display_name(admin))}»."
                    if admin else "Оплату вносит администратор группы."
                )
            else:
                note = "Срок оплаты и цена пока не назначены."
            messages.append(format_subscription_message(None, links, billing_note=note))
        else:
            messages.append("Подписок пока нет.")
    for item in own:
        messages.append(format_subscription_message(item, subscription_links(db, item), hide_billing=hide_billing))

    if is_group_admin:
        members = db.query(User).filter(User.group_id == group.id, User.id != user.id).order_by(User.id.asc()).all()
        for member in members:
            member_subs = _subs(member.id)
            name = _display_name(member)
            if not member_subs:
                member_links = account_links(db, user_accounts(db, member.id))
                if member_links:  # у участника своей записи подписки нет, но ссылки выданы
                    messages.append(format_subscription_message(None, member_links, owner_name=name))
                else:
                    messages.append(f"👤 {html.escape(name)}\nПодписки нет.")
                continue
            for item in member_subs:
                messages.append(format_subscription_message(item, subscription_links(db, item), owner_name=name))
    return messages


def _load_subscription_texts(telegram_id: int) -> list[str]:
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(telegram_id)).first()
        return collect_subscription_messages(db, user)


async def send_subscription_info(message: types.Message, tg_user: types.User) -> None:
    # Проверка ссылок ходит в сеть - выполняем в потоке, чтобы не блокировать бота.
    texts = await asyncio.to_thread(_load_subscription_texts, tg_user.id)
    for text in texts:
        await message.answer(text, parse_mode="HTML")


# ------------------------------------------------------------------ колбэки

@router.message(Command("menu"))
async def cmd_menu(message: types.Message) -> None:
    """/menu - показать главное меню ещё раз."""
    if not message.from_user:
        return
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(message.from_user.id)).first()
        is_admin = is_admin_telegram_user(user, message.from_user.id)
    if user is None and not is_admin:
        await message.answer("Вы ещё не зарегистрированы. Отправьте /start, чтобы оставить заявку.")
        return
    await answer_main_menu(message, is_admin=is_admin)


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
    """Страница «Статус серверов»: сообщение меняется на статус, внизу кнопка [Меню]."""
    await query.answer()
    with SessionLocal() as db:
        text = servers_status_text(db)
    await _show_page(query, text or "Данные о серверах пока недоступны.", page_back_keyboard("Меню"))


@router.callback_query(lambda query: query.data == "menu:help")
async def help_menu(query: CallbackQuery) -> None:
    """«Центр Lumica»: справка появится позже, пока заглушка с кнопкой [Назад]."""
    await query.answer()
    await _show_page(query, HELP_TEXT, page_back_keyboard("Назад"))


@router.callback_query(lambda query: query.data == "menu:back")
async def back_to_menu(query: CallbackQuery) -> None:
    """Возврат на главное меню в этом же сообщении."""
    await query.answer()
    if not query.from_user:
        return
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        is_admin = is_admin_telegram_user(user, query.from_user.id)
    text, markup = main_menu_content(is_admin)
    await _show_page(query, text, markup)


__all__ = [
    "router",
    "user_menu",
    "admin_menu",
    "menu_button",
    "page_back_keyboard",
    "main_menu_content",
    "no_details_keyboard",
    "NO_DETAILS_TEXT",
    "answer_main_menu",
    "send_subscription_info",
    "format_subscription_message",
    "server_code",
    "subscription_links",
    "collect_subscription_messages",
    "is_admin_telegram_user",
    "servers_status_text",
    "server_condition",
    "webapp_url",
]
