import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from lumica.integrations.xui_client import XUIClient

SECRET = "NOPJsecretPath"


class FakePanel(BaseHTTPRequestHandler):
    """Имитация 3x-ui с кастомным webBasePath.

    Корневой /login отвечает 200 HTML (как реверс-прокси/заглушка), настоящий логин
    живёт под /<SECRET>/login, а API без сессии отвечает 404.
    """

    def log_message(self, *args):
        pass

    def _send(self, status, body, content_type="application/json", cookie=None):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/login":
            return self._send(200, "<html>stub</html>", "text/html")
        if self.path == f"/{SECRET}/login":
            if body.get("username") == "admin" and body.get("password") == "good":
                return self._send(200, json.dumps({"success": True}), cookie="session=abc; Path=/")
            return self._send(200, json.dumps({"success": False, "msg": "wrong username or password"}))
        return self._send(404, "not found", "text/plain")

    def do_GET(self):
        authorized = "session=abc" in (self.headers.get("Cookie") or "") or self.headers.get("Authorization") == "Bearer good-token"
        if self.path == f"/{SECRET}/panel/api/inbounds/list" and authorized:
            return self._send(200, json.dumps({"success": True, "obj": [{"id": 1, "remark": "main"}]}))
        return self._send(404, "not found", "text/plain")


@pytest.fixture()
def panel_url():
    server = HTTPServer(("127.0.0.1", 0), FakePanel)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/{SECRET}/panel/api"
    finally:
        server.shutdown()
        server.server_close()


def test_login_skips_bogus_root_2xx_and_uses_real_login(panel_url):
    client = XUIClient(base_url=panel_url, username="admin", password="good")
    assert client.get_inbounds() == [{"id": 1, "remark": "main"}]


def test_login_reports_panel_rejection_instead_of_404_noise(panel_url):
    client = XUIClient(base_url=panel_url, username="admin", password="bad")
    with pytest.raises(RuntimeError, match="wrong username or password"):
        client.get_inbounds()


def test_api_token_works_against_secret_base_path(panel_url):
    client = XUIClient(base_url=panel_url, token="good-token")
    assert client.get_inbounds() == [{"id": 1, "remark": "main"}]


def test_rejected_api_token_gives_actionable_error(panel_url):
    client = XUIClient(base_url=panel_url, token="wrong-token")
    with pytest.raises(RuntimeError, match="API-токен не принят") as err:
        client.get_inbounds()
    # в ошибке видно, что именно ушло в панель, но сам токен не раскрывается
    assert "заголовок Authorization" in str(err.value)
    assert "токен 11 симв., оканчивается на ...ken" in str(err.value)
    assert "wrong-token" not in str(err.value)


def test_wrong_header_name_is_visible_in_error(panel_url):
    client = XUIClient(base_url=panel_url, token="good-token", token_header="X-API-Key")
    with pytest.raises(RuntimeError, match="заголовок X-API-Key"):
        client.get_inbounds()
