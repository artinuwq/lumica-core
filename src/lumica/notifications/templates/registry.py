"""
Notification templates. Plain Python data for MVP (spec §11: "в будущем
администратор должен иметь возможность изменять тексты без изменения
бизнес-логики" — that future feature only needs a new implementation of
`TemplateRegistry`, e.g. `DbTemplateRegistry`, that also returns
`NotificationTemplate` instances. Nothing else in the system depends on
templates being hardcoded here.)

Variables used across templates: {name} {date} {days_left} {amount}
{server} {group_name}. A given template only needs to use the subset it
cares about — the renderer degrades missing variables gracefully instead of
raising.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from lumica.notifications.domain.enums import NotificationType


@dataclass(frozen=True)
class Button:
    text: str
    # Symbolic route, resolved to an actual bot deep-link / Mini App URL by
    # integrations/telegram/deep_link.py. Keeps templates channel-agnostic.
    target: str


@dataclass(frozen=True)
class NotificationTemplate:
    type: NotificationType
    title: str
    body: str
    buttons: tuple[Button, ...] = field(default_factory=tuple)


class TemplateRegistry(Protocol):
    def get(self, type_: NotificationType) -> NotificationTemplate: ...


_TEMPLATES: dict[NotificationType, NotificationTemplate] = {}


def _register(tpl: NotificationTemplate) -> None:
    _TEMPLATES[tpl.type] = tpl


# --- APPLICATION ---

_register(
    NotificationTemplate(
        type=NotificationType.APPLICATION_CREATED,
        title="Новая заявка",
        body="Поступила новая заявка от {name}.",
        buttons=(Button("Открыть заявку", "application:open:{application_id}"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.APPLICATION_APPROVED,
        title="Заявка одобрена",
        body="Ваша заявка была одобрена. Добро пожаловать в Lumica!",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.APPLICATION_REJECTED,
        title="Заявка отклонена",
        body="К сожалению, ваша заявка была отклонена.",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.APPLICATION_NEED_INFORMATION,
        title="Нужны дополнительные данные",
        body="Для рассмотрения вашей заявки нам нужно уточнить: {requested_info}",
        buttons=(Button("Ответить", "application:open:{application_id}"),),
    )
)

# --- PAYMENT ---

_register(
    NotificationTemplate(
        type=NotificationType.PAYMENT_INSTRUCTIONS,
        title="Оплата подписки",
        body="Сумма к оплате: {amount}. Следуйте инструкции для оплаты.",
        buttons=(Button("Оплатить", "payment:instructions:{subscription_id}"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.PAYMENT_REPORTED,
        title="Платёж на проверке",
        body="Ваш платёж на сумму {amount} принят и ожидает подтверждения.",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.PAYMENT_CONFIRMED,
        title="Платёж подтверждён",
        body="Платёж на сумму {amount} подтверждён. Подписка активна до {date}.",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.PAYMENT_REJECTED,
        title="Платёж отклонён",
        body="Ваш платёж на сумму {amount} был отклонён. Причина: {reason}",
        buttons=(Button("Проверить", "payment:open:{payment_id}"),),
    )
)

# --- SUBSCRIPTION ---

_register(
    NotificationTemplate(
        type=NotificationType.SUBSCRIPTION_EXPIRING,
        title="Подписка скоро закончится",
        body="Подписка {group_name}Lumica заканчивается {date} ({days_left} дн.).",
        buttons=(Button("Продлить подписку", "subscription:renew:{subscription_id}"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.SUBSCRIPTION_EXPIRED,
        title="Подписка закончилась",
        body="Подписка {group_name}Lumica закончилась {date}. VPN отключён.",
        buttons=(Button("Продлить подписку", "subscription:renew:{subscription_id}"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.SUBSCRIPTION_RENEWED,
        title="Подписка продлена",
        body="Подписка {group_name}Lumica продлена до {date}.",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.SUBSCRIPTION_CANCELLED,
        title="Подписка отменена",
        body="Подписка {group_name}Lumica отменена.",
    )
)

# --- VPN ---

_register(
    NotificationTemplate(
        type=NotificationType.VPN_CREATED,
        title="VPN создан",
        body="Ваше VPN-подключение готово к использованию.",
        buttons=(Button("Открыть клиента", "vpn:open:{vpn_account_id}"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.VPN_DISABLED,
        title="VPN отключён",
        body="Ваш VPN был отключён.",
        buttons=(Button("Подробнее", "vpn:open:{vpn_account_id}"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.VPN_UNAVAILABLE,
        title="VPN временно недоступен",
        body="Ваше VPN-подключение временно недоступно. Мы уже разбираемся.",
        buttons=(Button("Открыть клиента", "vpn:open:{vpn_account_id}"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.VPN_RECOVERED,
        title="VPN восстановлен",
        body="Подключение восстановлено.",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.VPN_BLACKLISTED,
        title="VPN заблокирован",
        body="Ваш VPN-аккаунт был заблокирован. Обратитесь в поддержку.",
        buttons=(Button("Поддержка", "support:new"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.VPN_SERVER_CHANGED,
        title="Сервер изменён",
        body="Для вашего подключения изменился сервер: {server}.",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.VPN_MEMBER_ISSUE_DIGEST,
        title="Проблема у участника группы",
        body="У участника {name} возникла проблема с VPN-подключением.",
    )
)

# --- SERVER (admin) ---

_register(
    NotificationTemplate(
        type=NotificationType.SERVER_UNAVAILABLE,
        title="Сервер недоступен",
        body="Сервер {server} не отвечает.",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.SERVER_RECOVERED,
        title="Сервер восстановлен",
        body="Сервер {server} снова в строю.",
    )
)

# --- SUPPORT ---

_register(
    NotificationTemplate(
        type=NotificationType.SUPPORT_TICKET_CREATED,
        title="Тикет создан",
        body="Ваше обращение принято в обработку.",
        buttons=(Button("Открыть тикет", "support:open:{ticket_id}"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.SUPPORT_TICKET_UPDATED,
        title="Обновление по тикету",
        body="По вашему обращению есть новый ответ.",
        buttons=(Button("Открыть тикет", "support:open:{ticket_id}"),),
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.SUPPORT_TICKET_CLOSED,
        title="Тикет закрыт",
        body="Ваше обращение закрыто.",
    )
)

# --- SYSTEM (admin) ---

_register(
    NotificationTemplate(
        type=NotificationType.SYSTEM_ERROR,
        title="Системная ошибка",
        body="Компонент {name}: {amount}",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.BACKGROUND_JOB_FAILED,
        title="Фоновая задача упала",
        body="Задача {name} завершилась с ошибкой.",
    )
)
_register(
    NotificationTemplate(
        type=NotificationType.NOTIFICATION_DELIVERY_FAILED,
        title="Не удалось доставить уведомление",
        body="Уведомление получателю {name} не было доставлено после всех попыток.",
    )
)


class StaticTemplateRegistry:
    """Default in-process registry. Satisfies the `TemplateRegistry` Protocol."""

    def get(self, type_: NotificationType) -> NotificationTemplate:
        try:
            return _TEMPLATES[type_]
        except KeyError as exc:
            raise LookupError(f"No template registered for {type_!r}") from exc
