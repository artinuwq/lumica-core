"""Рассылки от имени бота: Markdown -> Telegram HTML, отправка с причинами ошибок, текст лога."""

from __future__ import annotations

import html
import os
import re
import time
from dataclasses import dataclass, field

import requests

# Тип рассылки -> (эмодзи, подпись). Подпись показывается получателям первой строкой.
BROADCAST_TYPES: dict[str, tuple[str, str]] = {
    "ad": ("📢", "Реклама"),
    "news": ("📰", "Новости"),
    "important": ("⚠️", "Важное"),
    "maintenance": ("🛠", "Технические работы"),
}
MAX_TEXT_LENGTH = 3500
MAX_RECIPIENTS = 2000
SEND_INTERVAL_SECONDS = 0.04  # ~25 сообщений в секунду, лимит Telegram - 30
LOG_LIMIT = 3900

_FENCE = re.compile(r"```(?:[A-Za-z0-9_+-]*\n)?(.*?)```", re.S)
_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_LINK = re.compile(r"\[([^\]\n]+)\]\(((?:https?|tg)://[^\s)]+)\)")
_BOLD = re.compile(r"(\*\*|__)(?=\S)(.+?)(?<=\S)\1", re.S)
_ITALIC_STAR = re.compile(r"(?<![*\w])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![*\w])")
_ITALIC_UNDER = re.compile(r"(?<![_\w])_(?=\S)([^_\n]+?)(?<=\S)_(?![_\w])")
_STRIKE = re.compile(r"~~(?=\S)(.+?)(?<=\S)~~", re.S)
_SPOILER = re.compile(r"\|\|(?=\S)(.+?)(?<=\S)\|\|", re.S)
_PLACEHOLDER = re.compile(r"\x00(\d+)\x00")
_TAG = re.compile(r"<(/?)(b|i|s|code|pre|a|blockquote|tg-spoiler)(?:\s[^>]*)?>")


def _esc(value: str) -> str:
    return html.escape(value, quote=False)


def _inline(text: str) -> str:
    text = _esc(text)
    text = _LINK.sub(lambda m: f'<a href="{m.group(2).replace(chr(34), "&quot;")}">{m.group(1)}</a>', text)
    text = _BOLD.sub(lambda m: f"<b>{m.group(2)}</b>", text)
    text = _STRIKE.sub(lambda m: f"<s>{m.group(1)}</s>", text)
    text = _SPOILER.sub(lambda m: f"<tg-spoiler>{m.group(1)}</tg-spoiler>", text)
    text = _ITALIC_STAR.sub(lambda m: f"<i>{m.group(1)}</i>", text)
    text = _ITALIC_UNDER.sub(lambda m: f"<i>{m.group(1)}</i>", text)
    return text


def _balanced(markup: str) -> bool:
    stack: list[str] = []
    for match in _TAG.finditer(markup):
        closing, name = match.group(1), match.group(2)
        if not closing:
            stack.append(name)
        elif not stack or stack.pop() != name:
            return False
    return not stack


def markdown_to_telegram_html(text: str) -> str:
    """Обычный Markdown (**жирный**, *курсив*, `код`, ```блок```, [текст](ссылка), > цитата,
    ~~зачёркнутый~~, ||спойлер||, # заголовок, - список) -> HTML, который понимает Telegram.
    Всё остальное экранируется. Если разметка получилась некорректной (пересекающиеся
    теги), возвращается обычный экранированный текст."""
    source = (text or "").replace("\r\n", "\n").replace("\x00", "")
    stash: list[str] = []

    def keep(markup: str) -> str:
        stash.append(markup)
        return f"\x00{len(stash) - 1}\x00"

    work = _FENCE.sub(lambda m: keep(f"<pre>{_esc(m.group(1).strip(chr(10)))}</pre>"), source)
    work = _INLINE_CODE.sub(lambda m: keep(f"<code>{_esc(m.group(1))}</code>"), work)

    out: list[str] = []
    quote: list[str] = []

    def flush_quote() -> None:
        if quote:
            out.append(keep("<blockquote>" + _inline("\n".join(quote)) + "</blockquote>"))
            quote.clear()

    for line in work.split("\n"):
        quoted = re.match(r"^>\s?(.*)$", line)
        if quoted:
            quote.append(quoted.group(1))
            continue
        flush_quote()
        heading = re.match(r"^#{1,6}\s+(.*)$", line)
        bullet = re.match(r"^\s*[-*+]\s+(.*)$", line)
        if heading:
            out.append(f"<b>{_inline(heading.group(1))}</b>")
        elif bullet:
            out.append("• " + _inline(bullet.group(1)))
        else:
            out.append(_inline(line))
    flush_quote()

    result = "\n".join(out)
    while _PLACEHOLDER.search(result):
        result = _PLACEHOLDER.sub(lambda m: stash[int(m.group(1))], result)
    return result if _balanced(result) else _esc(source)


def build_message(type_key: str, text: str) -> tuple[str, str]:
    """(HTML-вариант, простой текст) с подписью типа первой строкой."""
    emoji, label = BROADCAST_TYPES[type_key]
    return (
        f"{emoji} <b>{label}</b>\n\n{markdown_to_telegram_html(text)}",
        f"{emoji} {label}\n\n{text}",
    )


def reason_from_error(description: str) -> str:
    lowered = (description or "").lower()
    if "blocked by the user" in lowered:
        return "заблокировал бота"
    if "user is deactivated" in lowered:
        return "аккаунт удалён"
    if "chat not found" in lowered or "can't initiate conversation" in lowered:
        return "не запускал бота (чат не найден)"
    if "too many requests" in lowered:
        return "лимит Telegram, повторите позже"
    return description or "неизвестная ошибка"


def _send_message(token: str, chat_id: str, text: str, parse_mode: str | None) -> tuple[bool, str, float]:
    """(успех, описание ошибки, пауза при лимите)."""
    payload = {"chat_id": chat_id, "text": text}
    if parse_mode:
        payload["parse_mode"] = parse_mode
    try:
        response = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=10)
    except requests.RequestException as exc:
        return False, f"ошибка сети: {exc.__class__.__name__}", 0.0
    try:
        data = response.json()
    except ValueError:
        data = {}
    data = data if isinstance(data, dict) else {}
    if response.status_code < 400 and data.get("ok"):
        return True, "", 0.0
    retry_after = 0.0
    if isinstance(data.get("parameters"), dict):
        retry_after = float(data["parameters"].get("retry_after") or 0)
    return False, str(data.get("description") or response.status_code), retry_after


@dataclass
class BroadcastResult:
    sent: list = field(default_factory=list)
    failed: list = field(default_factory=list)  # (user, причина)


def send_broadcast(users, type_key: str, text: str, *, sleep=time.sleep) -> BroadcastResult:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    html_text, plain_text = build_message(type_key, text)
    result = BroadcastResult()
    for user in users:
        chat_id = str(getattr(user, "telegram_id", "") or "").strip()
        if not chat_id.isdigit():
            result.failed.append((user, "нет Telegram ID"))
            continue
        if not token:
            result.failed.append((user, "токен бота не настроен"))
            continue
        ok, error, retry_after = _send_message(token, chat_id, html_text, "HTML")
        if not ok and "can't parse entities" in error.lower():
            ok, error, retry_after = _send_message(token, chat_id, plain_text, None)  # без разметки
        if not ok and retry_after:
            sleep(min(retry_after, 30))
            ok, error, retry_after = _send_message(token, chat_id, html_text, "HTML")
        if ok:
            result.sent.append(user)
        else:
            result.failed.append((user, reason_from_error(error)))
        sleep(SEND_INTERVAL_SECONDS)
    return result


def _person(user) -> str:
    name = html.escape(str(getattr(user, "name", None) or f"#{user.id}"), quote=False)
    username = getattr(user, "username", None)
    return f"{name} (@{html.escape(str(username), quote=False)})" if username else name


def format_log(actor, type_key: str, text: str, selected: list, failed: list) -> str:
    """HTML для темы операторской группы: кто, тип, сообщение цитатой и два сворачиваемых списка."""
    emoji, label = BROADCAST_TYPES[type_key]
    actor_line = _person(actor) if actor is not None else "—"
    quoted = html.escape(text.strip(), quote=False)
    if len(quoted) > 1200:
        quoted = quoted[:1200] + "…"
    delivered = len(selected) - len(failed)

    def block(title: str, lines: list[str], budget: int) -> str:
        if not lines:
            return ""
        shown: list[str] = []
        used = 0
        for line in lines:
            if used + len(line) + 1 > budget:
                break
            shown.append(line)
            used += len(line) + 1
        if len(shown) < len(lines):
            shown.append(f"… и ещё {len(lines) - len(shown)}")
        return f"\n\n<b>{title} ({len(lines)}):</b>\n<blockquote expandable>" + "\n".join(shown) + "</blockquote>"

    head = (
        f"📣 <b>Рассылка</b>\n"
        f"<b>Кто:</b> {actor_line}\n"
        f"<b>Тип:</b> {emoji} {label}\n"
        f"<b>Сообщение:</b>\n<blockquote>{quoted}</blockquote>\n"
        f"<b>Доставлено:</b> {delivered} из {len(selected)}"
    )
    selected_lines = [f"{i}. {_person(u)}" for i, u in enumerate(selected, 1)]
    failed_lines = [f"{i}. {_person(u)} - {html.escape(reason, quote=False)}" for i, (u, reason) in enumerate(failed, 1)]
    room = max(LOG_LIMIT - len(head), 400)
    failed_part = block("Не доставлено", failed_lines, room // 2)
    selected_part = block("Выбрано для рассылки", selected_lines, max(room - len(failed_part), 200))
    return head + selected_part + failed_part


__all__ = [
    "BROADCAST_TYPES", "MAX_TEXT_LENGTH", "MAX_RECIPIENTS", "markdown_to_telegram_html", "build_message",
    "reason_from_error", "send_broadcast", "format_log", "BroadcastResult",
]
