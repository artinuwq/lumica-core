import base64
import json
import os
import secrets
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote, urlencode, urlparse, quote

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)

from lumica.api.helpers.vpn import build_vpn_helpers  # noqa: E402
from lumica.services.panels import extract_clients_from_panel_inbound  # noqa: E402


class _Logger:
    def warning(self, *args, **kwargs):
        return None


class VpnHelpersTest(unittest.TestCase):
    def setUp(self):
        self.helpers = build_vpn_helpers(
            {
                "app": SimpleNamespace(logger=_Logger()),
                "base64": base64,
                "extract_clients_from_panel_inbound": extract_clients_from_panel_inbound,
                "json": json,
                "os": os,
                "quote": quote,
                "secrets": secrets,
                "unquote": unquote,
                "urlencode": urlencode,
                "urlparse": urlparse,
            }
        )
        self.inbound = SimpleNamespace(
            protocol="vless",
            stream_settings={
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": ["google.com", "www.google.com"],
                    "shortIds": ["d209", "86932e"],
                    "settings": {
                        "publicKey": "u2ukTRmwwd9EisgCV8iSNozzFryvlgAHYt9mKnytkA0",
                        "fingerprint": "chrome",
                        "serverName": "",
                        "spiderX": "/",
                    },
                },
                "tcpSettings": {"header": {"type": "none"}},
            },
            settings={
                "clients": [
                    {
                        "id": "3e29f66a-c34c-460b-8052-8d4f28a057b3",
                        "email": "Chelovek-Main",
                        "flow": "xtls-rprx-vision",
                        "subId": "testsubid",
                    }
                ]
            },
        )

    def test_build_vless_url_from_inbound_uses_reality_settings(self):
        url = self.helpers["_build_vless_url_from_inbound"](
            identifier="3e29f66a-c34c-460b-8052-8d4f28a057b3",
            label="Chelovek-Main",
            host="lumica-de-1.duckdns.org",
            port=2095,
            inbound=self.inbound,
            meta={},
        )
        self.assertEqual(
            url,
            "vless://3e29f66a-c34c-460b-8052-8d4f28a057b3@lumica-de-1.duckdns.org:2095?"
            "type=tcp&encryption=none&security=reality&pbk=u2ukTRmwwd9EisgCV8iSNozzFryvlgAHYt9mKnytkA0&"
            "fp=chrome&sni=google.com&sid=d209&spx=%2F&flow=xtls-rprx-vision#Chelovek",
        )

    def test_apply_vless_display_name_includes_region_when_known(self):
        original = "vless://test@example.com:443?type=tcp#Old"
        renamed = self.helpers["_apply_vless_display_name"](original, "Chelovek-Main", "test", "de")
        self.assertEqual(unquote(renamed.split("#", 1)[1]), "Lumica[De] - Chelovek")

    def test_build_vless_display_name_skips_region_brackets_when_unknown(self):
        display_name = self.helpers["_build_vless_display_name"]("????????????", None, None)
        self.assertEqual(display_name, "Lumica - ????????????")

    def test_panel_public_host_uses_panel_base_url_hostname(self):
        host = self.helpers["_panel_public_host"]("https://lumica-de-1.duckdns.org/fPsmf7h12KqhtTJXpG/")
        self.assertEqual(host, "lumica-de-1.duckdns.org")


if __name__ == "__main__":
    unittest.main()
