"""
Resolves a template Button's symbolic `target` (e.g. "subscription:renew:200")
into a real Telegram deep link or Mini App URL. This is the only place that
needs to know the bot's username / Mini App base URL, so templates and the
renderer stay free of any concrete URL.
"""

from __future__ import annotations


class DeepLinkResolver:
    def __init__(self, bot_username: str, mini_app_url: str) -> None:
        self._bot_username = bot_username.lstrip("@")
        self._mini_app_url = mini_app_url.rstrip("/")

    def resolve(self, target: str) -> str:
        # Symbolic targets are "<route>:<action>[:<id>]". Route table is
        # intentionally small and explicit rather than clever/generic —
        # easy to extend when the Mini App adds new deep-linkable screens.
        parts = target.split(":")
        route = parts[0]

        if route == "subscription" and len(parts) >= 3 and parts[1] == "renew":
            return f"{self._mini_app_url}/subscription/{parts[2]}/renew"
        if route == "application" and len(parts) >= 3 and parts[1] == "open":
            return f"{self._mini_app_url}/applications/{parts[2]}"
        if route == "payment":
            if len(parts) >= 3 and parts[1] == "instructions":
                return f"{self._mini_app_url}/subscription/{parts[2]}/pay"
            if len(parts) >= 3 and parts[1] == "open":
                return f"{self._mini_app_url}/payments/{parts[2]}"
        if route == "vpn" and len(parts) >= 3 and parts[1] == "open":
            return f"{self._mini_app_url}/vpn/{parts[2]}"
        if route == "support":
            if len(parts) >= 2 and parts[1] == "new":
                return f"https://t.me/{self._bot_username}?start=support_new"
            if len(parts) >= 3 and parts[1] == "open":
                return f"{self._mini_app_url}/support/{parts[2]}"

        # Unknown route: fall back to opening the Mini App home rather than
        # producing a broken button.
        return self._mini_app_url
