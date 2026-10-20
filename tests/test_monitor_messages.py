from types import SimpleNamespace

import requests

from lumica.jobs import panel_monitor


def _fake_post(monkeypatch, replies):
    """replies: список ответов по порядку; каждый - (status, json) или исключение."""
    calls = []

    def post(url, json=None, timeout=None):
        calls.append((url.rsplit("/", 1)[1], json))
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        status, body = reply
        return SimpleNamespace(status_code=status, json=lambda: body, reason="x")

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setattr(panel_monitor.requests, "post", post)
    return calls


def test_editable_message_is_updated_in_place(monkeypatch):
    calls = _fake_post(monkeypatch, [(200, {"ok": True})])
    assert panel_monitor._topic_message("-100", 5, "txt", message_id=11) == 11
    assert [name for name, _ in calls] == ["editMessageText"]


def test_message_that_cannot_be_edited_is_deleted_and_reposted(monkeypatch):
    calls = _fake_post(monkeypatch, [
        (400, {"ok": False, "description": "Bad Request: message can't be edited"}),
        (200, {"ok": True, "result": True}),
        (200, {"ok": True, "result": {"message_id": 99}}),
    ])
    assert panel_monitor._topic_message("-100", 5, "txt", message_id=11) == 99
    assert [name for name, _ in calls] == ["editMessageText", "deleteMessage", "sendMessage"]
    assert calls[1][1] == {"chat_id": "-100", "message_id": 11}
    assert calls[2][1]["message_thread_id"] == 5


def test_already_deleted_message_is_just_reposted(monkeypatch):
    calls = _fake_post(monkeypatch, [
        (400, {"ok": False, "description": "Bad Request: message to edit not found"}),
        (200, {"ok": True, "result": {"message_id": 7}}),
    ])
    assert panel_monitor._topic_message("-100", 5, "txt", message_id=11) == 7
    assert [name for name, _ in calls] == ["editMessageText", "sendMessage"]


def test_unchanged_text_and_network_errors_keep_the_old_message(monkeypatch):
    calls = _fake_post(monkeypatch, [
        (400, {"ok": False, "description": "Bad Request: message is not modified"}),
        requests.ConnectionError("down"),
        (502, {}),
    ])
    for _ in range(3):
        assert panel_monitor._topic_message("-100", 5, "txt", message_id=11) == 11
    assert [name for name, _ in calls] == ["editMessageText"] * 3  # ничего не удалено и не продублировано


def test_first_message_is_simply_sent(monkeypatch):
    calls = _fake_post(monkeypatch, [(200, {"ok": True, "result": {"message_id": 5}})])
    assert panel_monitor._topic_message("-100", 5, "txt") == 5
    assert [name for name, _ in calls] == ["sendMessage"]
