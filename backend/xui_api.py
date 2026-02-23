import os
from typing import Any
from urllib.parse import urlparse

import requests
import json


class XUIClient:
    def __init__(self, base_url: str | None = None, username: str | None = None, password: str | None = None):
        self.base_url = (base_url or os.getenv("PANEL_BASE_URL", "http://127.0.0.1:2053/panel/api")).rstrip("/")
        self.username = username or os.getenv("PANEL_USER")
        self.password = password or os.getenv("PANEL_PASS")
        self.session = requests.Session()
        self._active_prefix: str = ""

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

    def _extract_inbounds_from_payload(self, payload: Any) -> list[dict[str, Any]]:
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
                rows = [item for item in value if isinstance(item, dict)]
                if rows:
                    return rows
            if isinstance(value, str):
                try:
                    parsed = json.loads(value)
                except ValueError:
                    continue
                if isinstance(parsed, list):
                    rows = [item for item in parsed if isinstance(item, dict)]
                    if rows:
                        return rows

        # last-resort: find first list-of-dicts in top-level dict values
        for value in payload.values():
            if isinstance(value, list):
                rows = [item for item in value if isinstance(item, dict)]
                if rows:
                    return rows

        return []

    def login(self) -> None:
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
                    self._active_prefix = prefix
                    return
                except requests.RequestException as exc:
                    last_error = exc
                    continue
        raise RuntimeError(f"3X-UI login failed for all base paths. Last error: {last_error}")

    def get_inbounds(self) -> list[dict[str, Any]]:
        self.login()
        errors: list[str] = []
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
                    if items:
                        return items
                except requests.RequestException as exc:
                    errors.append(f"{url}: {exc}")
                    continue
        raise RuntimeError(f"Failed to load inbounds: {' | '.join(errors)}")

    def disable_client(self, inbound_id: int, client_identifier: str) -> bool:
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
                        json={"id": inbound_id, "settings": {"clients": [{"id": client_identifier, "enable": False}]}},
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
