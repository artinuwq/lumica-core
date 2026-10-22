from types import SimpleNamespace

import pytest

from lumica.services import broadcasts
from lumica.services.broadcasts import markdown_to_telegram_html as md


def test_markdown_basics_become_telegram_html():
    assert md("**жирный** и *курсив* и _тоже_ и ~~нет~~") == "<b>жирный</b> и <i>курсив</i> и <i>тоже</i> и <s>нет</s>"
    assert md("`a<b>` и ```\nprint(1)\n```") == "<code>a&lt;b&gt;</code> и <pre>print(1)</pre>"
    assert md("[сайт](https://x.io/a?b=1&c=2)") == '<a href="https://x.io/a?b=1&amp;c=2">сайт</a>'
    assert md("||секрет||") == "<tg-spoiler>секрет</tg-spoiler>"
    assert md("# Заголовок\n- пункт") == "<b>Заголовок</b>\n• пункт"


def test_quotes_are_grouped_and_html_is_escaped():
    assert md("> раз\n> **два**\nобычный") == "<blockquote>раз\n<b>два</b></blockquote>\nобычный"
    assert md("1 < 2 & 3 > 2") == "1 &lt; 2 &amp; 3 &gt; 2"
    assert md("<script>x</script>") == "&lt;script&gt;x&lt;/script&gt;"
    assert md("snake_case_name и 2*3*4") == "snake_case_name и 2*3*4"  # внутри слов разметки нет


def test_unbalanced_markup_falls_back_to_plain_escaped_text():
    broken = "**a *b** c*"
    assert md(broken) == "**a *b** c*"
    assert md("[x](javascript:alert(1))") == "[x](javascript:alert(1))"  # опасные ссылки не превращаются в теги


def test_message_has_type_header():
    html_text, plain = broadcasts.build_message("ad", "Скидка **20%**")
    assert html_text == "📢 <b>Реклама</b>\n\nСкидка <b>20%</b>"
    assert plain == "📢 Реклама\n\nСкидка **20%**"


class _Post:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, url, json=None, timeout=None):
        self.calls.append(json)
        status, body = self.replies.pop(0)
        return SimpleNamespace(status_code=status, json=lambda: body)


def _user(i, tg="1", name=None, username=None):
    return SimpleNamespace(id=i, telegram_id=tg, name=name or f"U{i}", username=username)


def test_send_collects_sent_and_failed_with_reasons(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    post = _Post([
        (200, {"ok": True}),
        (403, {"ok": False, "description": "Forbidden: bot was blocked by the user"}),
        (400, {"ok": False, "description": "Bad Request: chat not found"}),
    ])
    monkeypatch.setattr(broadcasts.requests, "post", post)
    users = [_user(1, "11"), _user(2, "22"), _user(3, "33"), _user(4, None), _user(5, "abc")]
    result = broadcasts.send_broadcast(users, "news", "Привет", sleep=lambda s: None)
    assert [u.id for u in result.sent] == [1]
    assert [(u.id, r) for u, r in result.failed] == [
        (2, "заблокировал бота"), (3, "не запускал бота (чат не найден)"),
        (4, "нет Telegram ID"), (5, "нет Telegram ID"),
    ]
    assert post.calls[0]["parse_mode"] == "HTML" and post.calls[0]["chat_id"] == "11"


def test_send_retries_plain_when_telegram_cannot_parse_and_waits_on_rate_limit(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    post = _Post([
        (400, {"ok": False, "description": "Bad Request: can't parse entities: x"}),
        (200, {"ok": True}),
        (429, {"ok": False, "description": "Too Many Requests", "parameters": {"retry_after": 2}}),
        (200, {"ok": True}),
    ])
    monkeypatch.setattr(broadcasts.requests, "post", post)
    pauses = []
    result = broadcasts.send_broadcast([_user(1, "1"), _user(2, "2")], "ad", "**x**", sleep=pauses.append)
    assert len(result.sent) == 2 and not result.failed
    assert "parse_mode" not in post.calls[1]  # вторая попытка без разметки
    assert 2.0 in pauses  # дождались retry_after


def test_log_has_author_type_quote_and_two_collapsible_lists():
    actor = _user(9, name="Admin", username="boss")
    selected = [_user(1, name="Anna", username="anna"), _user(2, name="Bob")]
    failed = [(selected[1], "заблокировал бота")]
    log = broadcasts.format_log(actor, "ad", "Текст <b>", selected, failed)
    assert "<b>Кто:</b> Admin (@boss)" in log
    assert "<b>Тип:</b> 📢 Реклама" in log
    assert "<blockquote>Текст &lt;b&gt;</blockquote>" in log
    assert "<b>Доставлено:</b> 1 из 2" in log
    assert "<b>Выбрано для рассылки (2):</b>\n<blockquote expandable>1. Anna (@anna)\n2. Bob</blockquote>" in log
    assert "<b>Не доставлено (1):</b>\n<blockquote expandable>1. Bob - заблокировал бота</blockquote>" in log


def test_log_stays_within_telegram_limit_for_big_lists():
    selected = [_user(i, name=f"Very Long Client Name {i}", username=f"user_{i}") for i in range(600)]
    failed = [(u, "заблокировал бота") for u in selected[:300]]
    log = broadcasts.format_log(_user(1), "news", "x" * 5000, selected, failed)
    assert len(log) <= 4096
    assert "и ещё" in log
