"""Refresh one Telegram monitoring message per panel and emit health transitions."""

from __future__ import annotations

import os
from datetime import datetime
from zoneinfo import ZoneInfo

import requests

from lumica.domain.models import AppSetting, Panel
from lumica.infra.db import SessionLocal
from lumica.services.panels import PanelRegistry

WORKSPACE_KEY = "telegram.operator_workspace"
STATE_KEY = "telegram.panel_monitor_state"
MOSCOW = ZoneInfo("Europe/Moscow")


def _find_value(payload, names: set[str]):
    pending = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = str(key).replace("_", "").lower()
                if normalized in names and not isinstance(item, (dict, list)):
                    return item
                pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)
    return None


def _format_number(value, suffix: str = "") -> str:
    if value is None:
        return "недоступно"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return f"{value}{suffix}"
    rendered = str(int(number)) if number.is_integer() else f"{number:.1f}"
    return f"{rendered}{suffix}"


def _resource_percent(resource: dict | None) -> float | None:
    if not isinstance(resource, dict):
        return None
    try:
        total = float(resource.get("total"))
        current = float(resource.get("current"))
    except (TypeError, ValueError):
        return None
    return min(max(current / total * 100, 0), 100) if total > 0 else None


def _gigabytes(value) -> str:
    try:
        return f"{float(value) / (1024 ** 3):.1f} GB"
    except (TypeError, ValueError):
        return "недоступно"


def _megabits_per_second(value) -> str:
    try:
        return f"{float(value) * 8 / 1_000_000:.1f} Мбит/с"
    except (TypeError, ValueError):
        return "недоступно"


def _uptime_text(value) -> str:
    try:
        total_seconds = max(int(value), 0)
    except (TypeError, ValueError):
        return "недоступно"
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    return f"{days} д {hours:02} ч {minutes:02} мин" if days else f"{hours} ч {minutes:02} мин"


def _to_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _observatory_unhealthy(payload) -> bool | None:
    observations = []
    pending = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if isinstance(value.get("alive"), bool):
                observations.append(not value["alive"])
            status = str(value.get("status") or value.get("health") or "").strip().lower()
            if status in {"down", "failed", "unhealthy", "error"}:
                observations.append(True)
            elif status in {"up", "healthy", "available", "ok"}:
                observations.append(False)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return any(observations) if observations else None


def _format_snapshot(panel: Panel, snapshot: dict, updated_at: datetime) -> str:
    status = snapshot.get("status")
    status = status if isinstance(status, dict) else {}
    memory = status.get("mem") if isinstance(status.get("mem"), dict) else {}
    swap = status.get("swap") if isinstance(status.get("swap"), dict) else {}
    disk = status.get("disk") if isinstance(status.get("disk"), dict) else {}
    net_io = status.get("netIO") if isinstance(status.get("netIO"), dict) else {}
    cpu = status.get("cpu")
    memory_percent = _resource_percent(memory)
    swap_percent = _resource_percent(swap)
    disk_percent = _resource_percent(disk)
    disk_used = _gigabytes(disk.get("current"))
    disk_total = _gigabytes(disk.get("total"))
    disk_free = _gigabytes(max(float(disk["total"]) - float(disk["current"]), 0)) if disk_percent is not None else "недоступно"
    uptime = _uptime_text(status.get("uptime"))
    xray_version = snapshot.get("xray_version")
    xray = status.get("xray") if isinstance(status.get("xray"), dict) else {}
    xray_state = str(xray.get("state") or "недоступно")
    xray_version = xray_version or xray.get("version")
    online = snapshot.get("online_clients")
    if isinstance(online, list):
        online_count = len(online)
    else:
        online_count = None
    tcp_count = status.get("tcpCount")
    udp_count = status.get("udpCount")
    try:
        connection_count = int(tcp_count or 0) + int(udp_count or 0)
    except (TypeError, ValueError):
        connection_count = None
    panel_version = snapshot.get("panel_version") or status.get("panelVersion")
    net_up = _megabits_per_second(net_io.get("up"))
    net_down = _megabits_per_second(net_io.get("down"))
    is_online = str(panel.health_status or "unknown").lower() == "green"
    updated = updated_at.astimezone(MOSCOW).strftime("%H:%M:%S")
    return (
        f"Сервер {panel.name}\n\n"
        f"{'Online' if is_online else 'Offline' if panel.health_status == 'red' else 'Статус неизвестен'}\n\n"
        f"CPU {_format_number(cpu, '%')} · Диск {_format_number(disk_percent, '%')} ({disk_used}/{disk_total})\n"
        f"RAM {_format_number(memory_percent, '%')} · SWAP {_format_number(swap_percent, '%')}\n"
        f"Свободно на диске: {disk_free}\n"
        f"Подключения: {_format_number(connection_count)} · Пользователи online: {_format_number(online_count)}\n"
        f"Xray: {xray_state} {_format_number(xray_version)} · Панель: {_format_number(panel_version)}\n"
        f"Uptime: {uptime}\n"
        f"Сеть: ↑ {net_up} · ↓ {net_down}\n\n"
        f"Обновлено: {updated}"
    )


def _telegram_request(method: str, payload: dict) -> tuple[dict | None, str, bool]:
    """Вызов Bot API: (ответ при успехе, текст ошибки, временная ли ошибка).

    Временные ошибки (нет сети, 5xx, 429) отличаем от окончательных (400/403:
    «message can't be edited» и т. п.), чтобы не удалять сообщения из-за сбоя сети."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        return None, "TELEGRAM_BOT_TOKEN is not set", True
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/{method}",
            json=payload,
            timeout=10,
        )
    except requests.RequestException as exc:
        return None, str(exc), True
    try:
        data = response.json()
    except ValueError:
        data = {}
    data = data if isinstance(data, dict) else {}
    if response.status_code < 400 and data.get("ok"):
        return data, "", False
    description = str(data.get("description") or getattr(response, "reason", "") or response.status_code)
    return None, description, response.status_code >= 500 or response.status_code == 429


def _telegram_call(method: str, payload: dict) -> dict | None:
    result, _error, _transient = _telegram_request(method, payload)
    return result


def _topic_message(chat_id: str, thread_id: int, text: str, *, message_id: int | None = None) -> int | None:
    """Обновляет сообщение мониторинга. Если Telegram больше не даёт его изменить
    (слишком старое и т. п.), старое сообщение удаляется, а вместо него
    публикуется новое - чтобы в теме не копились устаревшие снимки."""
    if message_id:
        updated, error, transient = _telegram_request("editMessageText", {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
        })
        if updated:
            return message_id
        lowered = error.lower()
        if "message is not modified" in lowered or transient:
            return message_id  # текст тот же или сбой сети: старое сообщение остаётся, повторим в следующий цикл
        if "message to edit not found" not in lowered:  # если его уже нет - удалять нечего
            _telegram_request("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
    sent = _telegram_call("sendMessage", {
        "chat_id": chat_id,
        "message_thread_id": thread_id,
        "text": text,
    })
    result = sent.get("result") if sent else None
    return result.get("message_id") if isinstance(result, dict) else None


def run_panel_monitoring(registry: PanelRegistry | None = None, now: datetime | None = None) -> int:
    registry = registry or PanelRegistry()
    now = now or datetime.now(MOSCOW)
    refreshed = 0
    with SessionLocal() as db:
        workspace_row = db.query(AppSetting).filter(AppSetting.key == WORKSPACE_KEY).first()
        workspace = workspace_row.value_json if workspace_row and isinstance(workspace_row.value_json, dict) else {}
        chat_id = workspace.get("chat_id")
        topics = workspace.get("topics") if isinstance(workspace.get("topics"), dict) else {}
        monitoring_thread = topics.get("📊 Мониторинг")
        event_thread = topics.get("🔴 События серверов")
        if not chat_id or not monitoring_thread:
            return 0

        state_row = db.query(AppSetting).filter(AppSetting.key == STATE_KEY).first()
        stored_state = state_row.value_json if state_row and isinstance(state_row.value_json, dict) else {}
        state = dict(stored_state)
        panels = db.query(Panel).order_by(Panel.name.asc()).all()
        for panel in panels:
            old = state.get(panel.id) if isinstance(state.get(panel.id), dict) else {}
            previous_health = old.get("health_status", "unknown")
            snapshot = {}
            try:
                auth = registry.get_auth_payload(db, panel)
                provider = registry.get_provider(panel.provider)
                provider.health_check(panel, auth)
                panel.health_status = "green"
                panel.last_ok_at = now
                panel.error_message = None
                getter = getattr(provider, "monitoring_snapshot", None)
                if callable(getter):
                    snapshot = getter(panel, auth)
            except Exception as exc:
                registry.invalidate_panel(panel.id)
                panel.health_status = "red"
                panel.error_message = str(exc)[:500]
                snapshot = {}

            content = _format_snapshot(panel, snapshot, now)
            message_id = _topic_message(
                str(chat_id),
                int(monitoring_thread),
                content,
                message_id=old.get("message_id"),
            )
            current_health = str(panel.health_status or "unknown").lower()
            if event_thread and current_health != previous_health:
                if current_health == "red":
                    event_text = f"🔴 Сервер недоступен: {panel.name}\nВремя: {now.astimezone(MOSCOW):%d.%m.%Y %H:%M:%S} MSK"
                elif current_health == "green" and previous_health == "red":
                    event_text = f"🟢 Сервер восстановился: {panel.name}\nВремя: {now.astimezone(MOSCOW):%d.%m.%Y %H:%M:%S} MSK"
                else:
                    event_text = None
                if event_text:
                    _telegram_call("sendMessage", {
                        "chat_id": str(chat_id),
                        "message_thread_id": int(event_thread),
                        "text": event_text,
                    })
            alerts = dict(old.get("alerts", {})) if isinstance(old.get("alerts"), dict) else {}
            status = snapshot.get("status") if isinstance(snapshot.get("status"), dict) else {}
            xray = status.get("xray") if isinstance(status.get("xray"), dict) else {}
            xray_state = str(xray.get("state") or "").strip().lower()
            disk_percent = _resource_percent(status.get("disk"))
            memory_percent = _resource_percent(status.get("mem"))
            alert_states = []
            if xray_state:
                alert_states.append((
                    "xray_down",
                    xray_state != "running",
                    f"🔴 Xray недоступен на {panel.name}: {xray_state}",
                    f"🟢 Xray восстановился на {panel.name}",
                ))
            if disk_percent is not None:
                alert_states.append((
                    "disk_critical",
                    disk_percent >= 90,
                    f"🔴 Диск {panel.name} заполнен на {disk_percent:.1f}%",
                    f"🟢 Критический уровень заполнения диска снят: {panel.name} ({disk_percent:.1f}%)",
                ))
            if memory_percent is not None:
                free_memory = 100 - memory_percent
                alert_states.append((
                    "ram_critical",
                    free_memory < 5,
                    f"🔴 Критически мало свободной RAM на {panel.name}: {free_memory:.1f}%",
                    f"🟢 Свободная RAM восстановилась на {panel.name}: {free_memory:.1f}%",
                ))
            proxy_unhealthy = _observatory_unhealthy(snapshot.get("xray_observatory"))
            if proxy_unhealthy is not None:
                alert_states.append((
                    "proxy_unavailable",
                    proxy_unhealthy,
                    f"🔴 Проверка прокси не проходит на {panel.name}",
                    f"🟢 Проверка прокси восстановилась на {panel.name}",
                ))
            for key, is_critical, alert_text, recovery_text in alert_states:
                previous = alerts.get(key)
                if event_thread and is_critical and previous is not True:
                    _telegram_call("sendMessage", {
                        "chat_id": str(chat_id),
                        "message_thread_id": int(event_thread),
                        "text": f"{alert_text}\nВремя: {now.astimezone(MOSCOW):%d.%m.%Y %H:%M:%S} MSK",
                    })
                elif event_thread and not is_critical and previous is True:
                    _telegram_call("sendMessage", {
                        "chat_id": str(chat_id),
                        "message_thread_id": int(event_thread),
                        "text": f"{recovery_text}\nВремя: {now.astimezone(MOSCOW):%d.%m.%Y %H:%M:%S} MSK",
                    })
                alerts[key] = is_critical

            update_status = snapshot.get("update_status")
            update_status = update_status if isinstance(update_status, dict) else {}
            update_state = str(update_status.get("state") or "").strip().lower()
            update_run_id = str(update_status.get("runId") or "")
            previous_update = old.get("update") if isinstance(old.get("update"), dict) else {}
            if event_thread and update_state == "failed" and update_run_id != previous_update.get("run_id"):
                _telegram_call("sendMessage", {
                    "chat_id": str(chat_id),
                    "message_thread_id": int(event_thread),
                    "text": (
                        f"🔴 Обновление панели завершилось ошибкой: {panel.name}\n"
                        f"Код: {update_status.get('exitCode', '—')}\n"
                        f"Время: {now.astimezone(MOSCOW):%d.%m.%Y %H:%M:%S} MSK"
                    ),
                })
            elif (
                event_thread
                and update_state == "success"
                and previous_update.get("state") == "failed"
                and update_run_id != previous_update.get("run_id")
            ):
                _telegram_call("sendMessage", {
                    "chat_id": str(chat_id),
                    "message_thread_id": int(event_thread),
                    "text": (
                        f"🟢 Обновление панели успешно завершено: {panel.name}\n"
                        f"Время: {now.astimezone(MOSCOW):%d.%m.%Y %H:%M:%S} MSK"
                    ),
                })
            state[panel.id] = {
                "message_id": message_id or old.get("message_id"),
                "health_status": current_health,
                "updated_at": now.isoformat(),
                "text": content,
                "alerts": alerts,
                "update": {"run_id": update_run_id, "state": update_state},
                # Для бота («Состояние серверов»): нагрузка из последнего снимка.
                "cpu": _to_float(status.get("cpu")),
                "mem": memory_percent,
            }
            refreshed += 1

        if state_row:
            state_row.value_json = dict(state)
        else:
            db.add(AppSetting(key=STATE_KEY, value_json=state, description="Состояние сообщений мониторинга"))
        db.commit()
    return refreshed


__all__ = ["run_panel_monitoring"]