from unittest.mock import Mock

from lumica.integrations.xui_client import XUIClient
from lumica.domain.models import Panel
from lumica.services.panels import xui_provider


def test_token_auth_skips_login_and_sends_bearer_header():
    client = XUIClient("https://panel.example/panel/api", token="test-secret")
    response = Mock()
    response.json.return_value = {"obj": [{"id": 1}]}
    client.session.get = Mock(return_value=response)
    client.session.post = Mock()

    assert client.get_inbounds() == [{"id": 1}]
    assert client.session.headers["Authorization"] == "Bearer test-secret"
    client.session.post.assert_not_called()


def test_token_auth_supports_custom_header_and_prefix():
    client = XUIClient(
        "https://panel.example/panel/api",
        token="test-secret",
        token_header="X-API-Key",
        token_prefix="",
    )

    assert client.session.headers["X-API-Key"] == "test-secret"


def test_empty_inbound_list_is_a_valid_connection_response():
    client = XUIClient("https://panel.example/panel/api", token="test-secret")
    response = Mock()
    response.json.return_value = {"obj": []}
    client.session.get = Mock(return_value=response)

    assert client.get_inbounds() == []


def test_documented_status_and_online_clients_paths():
    client = XUIClient("https://panel.example/panel/api", token="test-secret")
    status = Mock()
    status.json.return_value = {"success": True, "obj": {"cpu": 24}}
    client.session.get = Mock(return_value=status)
    assert client.get_status()["obj"]["cpu"] == 24
    assert client.session.get.call_args.args[0] == "https://panel.example/panel/api/server/status"

    online = Mock()
    online.json.return_value = {"success": True, "obj": ["alice"]}
    client.session.post = Mock(return_value=online)
    assert client.get_online_clients()["obj"] == ["alice"]
    assert client.session.post.call_args.args[0] == "https://panel.example/panel/api/clients/onlines"


def test_provider_extracts_component_versions_from_status_obj(monkeypatch):
    class FakeClient:
        def get_status(self):
            return {"success": True, "obj": {
                "cpu": 1,
                "panelVersion": "v3.0",
                "xray": {"state": "running", "version": "25.10.31"},
            }}

        def get_online_clients(self):
            return {"success": True, "obj": ["alice"]}

        def get_update_status(self):
            raise RuntimeError("unsupported")

        def get_xray_observatory(self):
            raise RuntimeError("not configured")

    monkeypatch.setattr(xui_provider, "XUIClient", lambda **_kwargs: FakeClient())
    snapshot = xui_provider.XuiProvider().monitoring_snapshot(
        Panel(base_url="https://panel.example", auth_type="api_token", provider="3xui"),
        {"token": "test"},
    )

    assert snapshot["status"]["cpu"] == 1
    assert snapshot["xray_version"] == "25.10.31"
    assert snapshot["panel_version"] == "v3.0"
    assert snapshot["online_clients"] == ["alice"]
    assert snapshot["update_status"] is None