"""Ссылки подписки клиента панели (3x-ui sub URL).

Единая логика для mini app и бота: собираем кандидатов (явный sub_url, шаблон,
PANEL_*_BASE_URL, корень панели клиента, PANEL_BASE_URL, PUBLIC_VPN_HOST:порт) и,
как mini app, выбираем первый, который реально отвечает.
"""

from __future__ import annotations

import logging
import os
import time
from urllib.parse import quote, urlparse

import requests

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 3.0
PROBE_BUDGET_SECONDS = 8.0
PROBE_CACHE_SECONDS = 300
_probe_cache: dict[str, tuple[float, bool]] = {}


def panel_root(base_url: str | None) -> str | None:
    parsed = urlparse(str(base_url or "").strip())
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return None


def build_subscription_urls(
    sub_id: str | None,
    explicit_url: str | None = None,
    *,
    extra_roots: tuple[str, ...] | list[str] = (),
    warn=None,
) -> list[str]:
    sid = str(sub_id or "").strip()
    sid_quoted = quote(sid) if sid else ""
    urls: list[str] = []

    def _append(raw: str | None) -> None:
        value = str(raw or "").strip()
        if value and urlparse(value).scheme in {"http", "https"} and value not in urls:
            urls.append(value)

    _append(explicit_url)

    public_base = os.getenv("PANEL_PUBLIC_BASE_URL", "").strip().rstrip("/")
    subscription_base = os.getenv("PANEL_SUBSCRIPTION_BASE_URL", "").strip().rstrip("/")
    template = os.getenv("PANEL_SUBSCRIPTION_URL_TEMPLATE", "").strip()
    if template:
        for base_url in (subscription_base, public_base, ""):
            try:
                _append(template.format(sub_id=sid, base_url=base_url))
            except Exception as exc:  # noqa: BLE001
                (warn or logger.warning)("invalid PANEL_SUBSCRIPTION_URL_TEMPLATE: %s", exc)
                break

    if sid:
        for base_url in (subscription_base, public_base):
            if base_url:
                _append(f"{base_url}/sub/{sid_quoted}")
                _append(f"{base_url}/subcrp/{sid_quoted}")

        roots = [root for root in extra_roots if root]
        env_root = panel_root(os.getenv("PANEL_BASE_URL", ""))
        if env_root:
            roots.append(env_root)
        for root in roots:
            _append(f"{root}/sub/{sid_quoted}")
            _append(f"{root}/subcrp/{sid_quoted}")

        public_host = os.getenv("PUBLIC_VPN_HOST", "").strip()
        sub_port = os.getenv("PANEL_SUBSCRIPTION_PORT", "").strip()
        if public_host and sub_port:
            for scheme in ("http", "https"):
                _append(f"{scheme}://{public_host}:{sub_port}/sub/{sid_quoted}")
                _append(f"{scheme}://{public_host}:{sub_port}/subcrp/{sid_quoted}")
    return urls


def probe_url(url: str, timeout: float = PROBE_TIMEOUT_SECONDS) -> bool:
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return bool((response.text or "").strip())
    except Exception:  # noqa: BLE001 - недоступный кандидат просто пропускаем
        return False


def pick_subscription_url(candidates: list[str]) -> str | None:
    """Первый отвечающий кандидат; если ни один не ответил - первый по списку
    (как в mini app). Результаты проверки кешируются на несколько минут."""
    if not candidates:
        return None
    deadline = time.monotonic() + PROBE_BUDGET_SECONDS
    now = time.time()
    for url in candidates:
        cached = _probe_cache.get(url)
        if cached and now - cached[0] < PROBE_CACHE_SECONDS:
            ok = cached[1]
        elif time.monotonic() > deadline:
            break
        else:
            ok = probe_url(url, PROBE_TIMEOUT_SECONDS)
            _probe_cache[url] = (now, ok)
        if ok:
            return url
    return candidates[0]


__all__ = ["build_subscription_urls", "pick_subscription_url", "panel_root", "probe_url"]
