import io
import os
import time

import requests

from .settings_manager import (
    CLOUD_TELEGRAM_SEND_RETRIES_KEY,
    CLOUD_TELEGRAM_SEND_RETRY_DELAY_SEC_KEY,
    CLOUD_TELEGRAM_SEND_TIMEOUT_SEC_KEY,
    CLOUD_UPLOAD_CHUNK_SIZE_MB_KEY,
    get_runtime_setting_values,
    to_int,
)


class TelegramStorageError(RuntimeError):
    pass


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw is not None else int(default)
    except (TypeError, ValueError):
        value = int(default)
    if min_value is not None:
        value = max(min_value, value)
    if max_value is not None:
        value = min(max_value, value)
    return value


def _cloud_runtime_settings() -> dict[str, object]:
    return get_runtime_setting_values(
        [
            CLOUD_UPLOAD_CHUNK_SIZE_MB_KEY,
            CLOUD_TELEGRAM_SEND_TIMEOUT_SEC_KEY,
            CLOUD_TELEGRAM_SEND_RETRIES_KEY,
            CLOUD_TELEGRAM_SEND_RETRY_DELAY_SEC_KEY,
        ]
    )


def cloud_chunk_size_bytes(settings: dict[str, object] | None = None) -> int:
    runtime = settings or _cloud_runtime_settings()
    raw = runtime.get(CLOUD_UPLOAD_CHUNK_SIZE_MB_KEY, os.getenv("CLOUD_CHUNK_SIZE_MB", "15"))
    mb = to_int(raw, 15, min_value=1, max_value=20)
    return mb * 1024 * 1024


def cloud_storage_chat_id() -> str:
    value = (
        os.getenv("CLOUD_STORAGE_CHAT_ID")
        or os.getenv("CLOUD_TG_CHAT_ID")
        or os.getenv("TELEGRAM_STORAGE_CHAT_ID")
        or ""
    )
    return value.strip()


def _bot_token() -> str:
    return (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()


def _require_config() -> tuple[str, str]:
    token = _bot_token()
    chat_id = cloud_storage_chat_id()
    if not token:
        raise TelegramStorageError("TELEGRAM_BOT_TOKEN is not configured")
    if not chat_id:
        raise TelegramStorageError("CLOUD_STORAGE_CHAT_ID is not configured")
    return token, chat_id


def _api_url(token: str, method: str) -> str:
    return f"https://api.telegram.org/bot{token}/{method}"


def _file_url(token: str, file_path: str) -> str:
    return f"https://api.telegram.org/file/bot{token}/{file_path}"


def _telegram_request(method: str, url: str, **kwargs):
    # By default do not inherit system proxy env variables for Telegram calls.
    # Enable it explicitly if needed: TELEGRAM_USE_SYSTEM_PROXY=1
    use_system_proxy = _env_bool("TELEGRAM_USE_SYSTEM_PROXY", False)
    with requests.Session() as session:
        session.trust_env = use_system_proxy
        return session.request(method=method, url=url, **kwargs)


def _send_connect_timeout_sec() -> int:
    return _env_int("TELEGRAM_SEND_CONNECT_TIMEOUT_SEC", 15, min_value=3, max_value=120)


def _send_read_timeout_sec(settings: dict[str, object] | None = None) -> int:
    runtime = settings or _cloud_runtime_settings()
    raw = runtime.get(CLOUD_TELEGRAM_SEND_TIMEOUT_SEC_KEY, os.getenv("TELEGRAM_SEND_TIMEOUT_SEC", "300"))
    return to_int(raw, 300, min_value=30, max_value=1800)


def _send_retries(settings: dict[str, object] | None = None) -> int:
    runtime = settings or _cloud_runtime_settings()
    raw = runtime.get(CLOUD_TELEGRAM_SEND_RETRIES_KEY, os.getenv("TELEGRAM_SEND_RETRIES", "3"))
    return to_int(raw, 3, min_value=1, max_value=10)


def _send_retry_delay_sec(settings: dict[str, object] | None = None) -> int:
    runtime = settings or _cloud_runtime_settings()
    raw = runtime.get(CLOUD_TELEGRAM_SEND_RETRY_DELAY_SEC_KEY, os.getenv("TELEGRAM_SEND_RETRY_DELAY_SEC", "2"))
    return to_int(raw, 2, min_value=1, max_value=60)


def send_chunk_to_telegram(
    data: bytes,
    *,
    filename: str,
    caption: str | None = None,
) -> dict:
    token, chat_id = _require_config()
    runtime = _cloud_runtime_settings()

    form = {"chat_id": chat_id, "disable_notification": "true"}
    if caption:
        form["caption"] = caption[:1024]

    retries = _send_retries(runtime)
    retry_delay = _send_retry_delay_sec(runtime)
    timeout = (_send_connect_timeout_sec(), _send_read_timeout_sec(runtime))
    last_request_error: requests.RequestException | None = None

    response = None
    payload = None
    for attempt in range(1, retries + 1):
        with io.BytesIO(data) as fileobj:
            fileobj.name = filename
            files = {"document": (filename, fileobj, "application/octet-stream")}
            try:
                response = _telegram_request(
                    "POST",
                    _api_url(token, "sendDocument"),
                    data=form,
                    files=files,
                    timeout=timeout,
                )
                try:
                    payload = response.json()
                except ValueError as exc:
                    if attempt < retries:
                        time.sleep(retry_delay * attempt)
                        continue
                    raise TelegramStorageError("Telegram sendDocument returned non-JSON response") from exc

                status_code = int(response.status_code or 0)
                if status_code >= 500 and attempt < retries:
                    time.sleep(retry_delay * attempt)
                    continue

                if status_code == 429 and isinstance(payload, dict):
                    retry_after = ((payload.get("parameters") or {}).get("retry_after")) or 0
                    try:
                        retry_after = int(retry_after)
                    except (TypeError, ValueError):
                        retry_after = 0
                    if attempt < retries:
                        time.sleep(max(retry_delay * attempt, retry_after))
                        continue
                break
            except requests.RequestException as exc:
                last_request_error = exc
                if attempt < retries:
                    time.sleep(retry_delay * attempt)
                    continue
                break

    if last_request_error is not None and response is None:
        raise TelegramStorageError(f"Telegram sendDocument request failed: {last_request_error}") from last_request_error

    if response is None:
        raise TelegramStorageError("Telegram sendDocument request failed")

    if payload is None:
        try:
            payload = response.json()
        except ValueError as exc:
            raise TelegramStorageError("Telegram sendDocument returned non-JSON response") from exc

    if response.status_code >= 400 or not payload.get("ok"):
        description = payload.get("description") if isinstance(payload, dict) else None
        raise TelegramStorageError(description or f"Telegram sendDocument failed with status {response.status_code}")

    result = payload.get("result") or {}
    document = result.get("document") or {}
    message_id = result.get("message_id")
    file_id = document.get("file_id")
    if not message_id or not file_id:
        raise TelegramStorageError("Telegram sendDocument response is missing message_id/file_id")

    return {
        "chat_id": str(chat_id),
        "message_id": int(message_id),
        "file_id": str(file_id),
        "file_unique_id": str(document.get("file_unique_id") or ""),
    }


def iter_telegram_file_bytes(file_id: str, read_chunk_size: int = 64 * 1024):
    token = _bot_token()
    if not token:
        raise TelegramStorageError("TELEGRAM_BOT_TOKEN is not configured")

    try:
        file_resp = _telegram_request(
            "GET",
            _api_url(token, "getFile"),
            params={"file_id": file_id},
            timeout=(10, 60),
        )
    except requests.RequestException as exc:
        raise TelegramStorageError(f"Telegram getFile request failed: {exc}") from exc

    try:
        file_payload = file_resp.json()
    except ValueError as exc:
        raise TelegramStorageError("Telegram getFile returned non-JSON response") from exc

    if file_resp.status_code >= 400 or not file_payload.get("ok"):
        description = file_payload.get("description") if isinstance(file_payload, dict) else None
        raise TelegramStorageError(description or f"Telegram getFile failed with status {file_resp.status_code}")

    file_path = ((file_payload.get("result") or {}).get("file_path") or "").strip()
    if not file_path:
        raise TelegramStorageError("Telegram getFile response does not contain file_path")

    download_resp = None
    try:
        download_resp = _telegram_request(
            "GET",
            _file_url(token, file_path),
            stream=True,
            timeout=(10, 300),
        )
        download_resp.raise_for_status()
        for chunk in download_resp.iter_content(chunk_size=read_chunk_size):
            if chunk:
                yield chunk
    except requests.RequestException as exc:
        raise TelegramStorageError(f"Telegram file download failed: {exc}") from exc
    finally:
        try:
            download_resp.close()
        except Exception:
            pass


def delete_telegram_message(message_id: int) -> None:
    try:
        token, chat_id = _require_config()
    except TelegramStorageError:
        return
    try:
        _telegram_request(
            "POST",
            _api_url(token, "deleteMessage"),
            data={"chat_id": chat_id, "message_id": int(message_id)},
            timeout=(10, 60),
        )
    except requests.RequestException:
        # Best effort cleanup only.
        return
