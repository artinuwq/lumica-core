import os
import re
from typing import Any
from urllib.parse import urlparse

import requests
import json


class XUIClient:
    def __init__(
        self,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        token_header: str = "Authorization",
        token_prefix: str = "Bearer",
    ):
        self.base_url = (base_url or os.getenv("PANEL_BASE_URL", "http://127.0.0.1:2053/panel/api")).rstrip("/")
        self.username = username or os.getenv("PANEL_USER")
        self.password = password or os.getenv("PANEL_PASS")
        self.session = requests.Session()
        self._active_prefix: str = ""
        self.token = str(token or "").strip()
        if self.token:
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", token_header):
                raise ValueError("invalid API token header name")
            if "\r" in token_prefix or "\n" in token_prefix:
                raise ValueError("invalid API token prefix")
            value = f"{token_prefix.strip()} {self.token}".strip()
            self.session.headers[token_header] = value

    def _url_parts(self) -> tuple[str, str]:
        base = self.base_url.rstrip("/")
        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        path = parsed.path.rstrip("/") if parsed.path else ""
        return root, path

    def _candidate_prefixes(self) -> list[str]:
        root, path = self._url_parts()
        if not root:
            return [""]
        prefixes: list[str] = [""]
        if path:
            prefixes.append(path)
            if path.endswith("/panel/api"):
                prefixes.append(path[: -len("/panel/api")] or "")
            if path.endswith("/api"):
                prefixes.append(path[: -len("/api")] or "")
        deduped: list[str] = []
        for item in prefixes:
            clean = item.rstrip("/")
            if clean not in deduped:
                deduped.append(clean)
        return deduped

    def _build_url(self, prefix: str, suffix: str) -> str:
        root, _ = self._url_parts()
        prefix = prefix.rstrip("/")
        suffix = suffix if suffix.startswith("/") else f"/{suffix}"
        return f"{root}{prefix}{suffix}"

    def _extract_inbounds_from_payload(self, payload: Any) -> list[dict[str, Any]] | None:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]

        if not isinstance(payload, dict):
            return []

        candidates = [
            payload.get("data"),
            payload.get("obj"),
            payload.get("result"),
            payload.get("items"),
            payload.get("inbounds"),
        ]

        for value in candidates:
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, str):
                try:
                    parsed = json.loads(value)
                except ValueError:
                    continue
                if isinstance(parsed, list):
                    return [item for item in parsed if isinstance(item, dict)]

        # last-resort: find first list-of-dicts in top-level dict values
        for value in payload.values():
            if isinstance(value, list):
                rows = [item for item in value if isinstance(item, dict)]
                if rows:
                    return rows

        return None

    def login(self) -> None:
        if self.token:
            self._active_prefix = ""
            return
        if not self.username or not self.password:
            raise RuntimeError("PANEL_USER or PANEL_PASS not set")
        last_error: Exception | None = None
        for prefix in self._candidate_prefixes():
            login_urls = [
                self._build_url(prefix, "/login"),
                self._build_url(prefix, "/panel/api/login"),
                self._build_url(prefix, "/api/login"),
            ]
            # reduce duplicates while preserving order
            seen: list[str] = []
            for login_url in login_urls:
                if login_url in seen:
                    continue
                seen.append(login_url)
                try:
                    response = self.session.post(
                        login_url,
                        json={"username": self.username, "password": self.password},
                        timeout=8,
                    )
                    response.raise_for_status()
                except requests.RequestException as exc:
                    last_error = exc
                    continue
                # 2xx сам по себе - не успешный вход: заглушка/прокси может отвечать 200 HTML,
                # а 3x-ui на неверный пароль тоже отвечает 200 с {"success": false}.
                try:
                    payload = response.json()
                except ValueError:
                    last_error = RuntimeError(f"{login_url}: не JSON-ответ логина")
                    continue
                if not isinstance(payload, dict):
                    last_error = RuntimeError(f"{login_url}: неожиданный ответ логина")
                    continue
                if payload.get("success") is False:
                    # нашли настоящий эндпоинт логина, но панель отказала - дальше перебирать нечего
                    reason = str(payload.get("msg") or "без пояснения")
                    raise RuntimeError(
                        f"3X-UI отклонил вход ({login_url}): {reason}. "
                        "Проверь логин/пароль панели (и что не включена двухфакторка)."
                    )
                self._active_prefix = prefix
                return
        raise RuntimeError(f"3X-UI login failed for all base paths. Last error: {last_error}")

    def _auth_failure_hint(self, statuses: list[int | None]) -> str:
        # 3x-ui отвечает 404 (а не 401) на любой API-запрос без валидной авторизации,
        # поэтому "всё 404" почти всегда означает "панель не приняла наши креды".
        if not any(code in (401, 403, 404) for code in statuses):
            return ""
        if self.token:
            return (
                "3X-UI отвечает 404 на запросы без авторизации - API-токен не принят. "
                "Проверь: вставлен исходный токен (он показывается один раз при создании, "
                "в списке токенов панели виден только хэш), токен включён, не истёк и имеет scope admin."
            )
        return (
            "3X-UI отвечает 404 на запросы без авторизации - сессия не получена. "
            "Проверь логин/пароль панели и адрес с секретным путём (webBasePath)."
        )

    def get_inbounds(self) -> list[dict[str, Any]]:
        self.login()
        errors: list[str] = []
        statuses: list[int | None] = []
        prefix_candidates = [self._active_prefix] + [p for p in self._candidate_prefixes() if p != self._active_prefix]
        for prefix in prefix_candidates:
            candidate_urls = [
                self._build_url(prefix, "/panel/api/inbounds/list"),
                self._build_url(prefix, "/panel/api/inbounds"),
                self._build_url(prefix, "/api/inbounds/list"),
                self._build_url(prefix, "/api/inbounds"),
                self._build_url(prefix, "/inbounds/list"),
                self._build_url(prefix, "/inbounds"),
            ]
            seen: list[str] = []
            for url in candidate_urls:
                if url in seen:
                    continue
                seen.append(url)
                try:
                    response = self.session.get(url, timeout=8)
                    response.raise_for_status()
                    payload = response.json()
                    items = self._extract_inbounds_from_payload(payload)
                    if items is not None:
                        return items
                except requests.RequestException as exc:
                    errors.append(f"{url}: {exc}")
                    statuses.append(getattr(getattr(exc, "response", None), "status_code", None))
                    continue
        hint = self._auth_failure_hint(statuses)
        details = " | ".join(errors)
        if len(details) > 800:
            details = details[:800] + "..."
        raise RuntimeError(f"Failed to load inbounds. {hint} Details: {details}".replace(".  ", ". "))

    def _get_first_json(self, suffixes: list[str]) -> Any:
        self.login()
        errors: list[str] = []
        prefixes = [self._active_prefix] + [p for p in self._candidate_prefixes() if p != self._active_prefix]
        for prefix in prefixes:
            for suffix in suffixes:
                url = self._build_url(prefix, suffix)
                try:
                    response = self.session.get(url, timeout=8)
                    response.raise_for_status()
                    return response.json()
                except (requests.RequestException, ValueError) as exc:
                    errors.append(f"{url}: {exc}")
        raise RuntimeError(f"Failed to fetch 3X-UI endpoint: {' | '.join(errors)}")

    def _post_first_json(self, suffixes: list[str]) -> Any:
        self.login()
        errors: list[str] = []
        prefixes = [self._active_prefix] + [p for p in self._candidate_prefixes() if p != self._active_prefix]
        for prefix in prefixes:
            for suffix in suffixes:
                url = self._build_url(prefix, suffix)
                try:
                    response = self.session.post(url, json={}, timeout=8)
                    response.raise_for_status()
                    return response.json()
                except (requests.RequestException, ValueError) as exc:
                    errors.append(f"{url}: {exc}")
        raise RuntimeError(f"Failed to fetch 3X-UI endpoint: {' | '.join(errors)}")

    def get_status(self) -> Any:
        return self._get_first_json([
            "/panel/api/server/status",
            "/api/server/status",
            "/panel/api/status",
            "/api/status",
            "/status",
        ])

    def get_xray_version(self) -> Any:
        return self._get_first_json([
            "/panel/api/server/getXrayVersion",
            "/panel/api/getXrayVersion",
            "/api/server/getXrayVersion",
            "/api/getXrayVersion",
            "/getXrayVersion",
        ])

    def get_online_clients(self) -> Any:
        return self._post_first_json([
            "/panel/api/clients/onlines",
            "/api/clients/onlines",
            "/clients/onlines",
            "/panel/api/online/clients",
            "/api/online/clients",
            "/online/clients",
        ])

    def get_cpu_history(self, bucket: int = 60) -> Any:
        safe_bucket = str(bucket)
        if safe_bucket not in {"2", "30", "60", "120", "180", "300"}:
            raise ValueError("invalid CPU history bucket")
        return self._get_first_json([
            f"/panel/api/server/history/cpu/{safe_bucket}",
            f"/api/server/history/cpu/{safe_bucket}",
            f"/panel/api/server/cpuHistory/{safe_bucket}",
            f"/panel/api/cpuHistory/{safe_bucket}",
            f"/api/cpuHistory/{safe_bucket}",
            f"/cpuHistory/{safe_bucket}",
        ])

    def get_xray_observatory(self) -> Any:
        return self._get_first_json([
            "/panel/api/server/xrayObservatory",
            "/api/server/xrayObservatory",
        ])

    def get_update_status(self) -> Any:
        return self._get_first_json([
            "/panel/api/server/getUpdateStatus",
            "/api/server/getUpdateStatus",
        ])

    def set_client_enabled(self, inbound_id: int, client_identifier: str, enabled: bool) -> bool:
        self.login()
        prefix_candidates = [self._active_prefix] + [p for p in self._candidate_prefixes() if p != self._active_prefix]
        for prefix in prefix_candidates:
            update_urls = [
                self._build_url(prefix, "/panel/api/client/update"),
                self._build_url(prefix, "/api/client/update"),
                self._build_url(prefix, "/client/update"),
            ]
            seen: list[str] = []
            for url in update_urls:
                if url in seen:
                    continue
                seen.append(url)
                try:
                    response = self.session.post(
                        url,
                        json={"id": inbound_id, "settings": {"clients": [{"id": client_identifier, "enable": bool(enabled)}]}},
                        timeout=8,
                    )
                    if response.status_code >= 400:
                        continue
                    try:
                        payload = response.json()
                        if isinstance(payload, dict) and payload.get("success") is False:
                            continue
                    except ValueError:
                        pass
                    return True
                except requests.RequestException:
                    continue
        return False

    def disable_client(self, inbound_id: int, client_identifier: str) -> bool:
        return self.set_client_enabled(inbound_id, client_identifier, False)

    def enable_client(self, inbound_id: int, client_identifier: str) -> bool:
        return self.set_client_enabled(inbound_id, client_identifier, True)

    def add_client(self, inbound_id: int, client: dict[str, Any]) -> dict[str, Any]:
        self.login()
        errors: list[str] = []
        prefix_candidates = [self._active_prefix] + [p for p in self._candidate_prefixes() if p != self._active_prefix]

        payload_settings = {"clients": [client]}
        payload_variants = [
            {"id": inbound_id, "settings": json.dumps(payload_settings, ensure_ascii=False)},
            {"id": inbound_id, "settings": payload_settings},
            {"inboundId": inbound_id, "settings": json.dumps(payload_settings, ensure_ascii=False)},
        ]

        for prefix in prefix_candidates:
            add_urls = [
                self._build_url(prefix, "/panel/api/inbounds/addClient"),
                self._build_url(prefix, "/panel/api/inbounds/add-client"),
                self._build_url(prefix, "/panel/api/inbounds/addclient"),
                self._build_url(prefix, "/api/inbounds/addClient"),
                self._build_url(prefix, "/api/inbounds/add-client"),
                self._build_url(prefix, "/inbounds/addClient"),
            ]
            seen: list[str] = []
            for url in add_urls:
                if url in seen:
                    continue
                seen.append(url)
                for payload in payload_variants:
                    try:
                        response = self.session.post(url, json=payload, timeout=10)
                    except requests.RequestException as exc:
                        errors.append(f"{url}: {exc}")
                        continue
                    if response.status_code >= 400:
                        errors.append(f"{url}: HTTP {response.status_code}")
                        continue
                    try:
                        parsed = response.json()
                    except ValueError:
                        parsed = {"ok": True, "raw": response.text}
                    if isinstance(parsed, dict) and parsed.get("success") is False:
                        errors.append(f"{url}: success=false")
                        continue
                    return parsed if isinstance(parsed, dict) else {"ok": True, "payload": parsed}

        raise RuntimeError(f"Failed to add client to inbound {inbound_id}: {' | '.join(errors)[:1200]}")
