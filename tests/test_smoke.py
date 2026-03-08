import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)

from lumica.api import create_app  # noqa: E402
from lumica.infra import ENV_FILE, load_dotenv  # noqa: E402
from lumica.infra.db import engine  # noqa: E402


class SmokeApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        load_dotenv(ENV_FILE)
        os.environ.setdefault("ENABLE_BACKGROUND_JOBS", "false")
        cls.app = create_app()
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        try:
            engine.dispose()
        except Exception:
            pass

    def test_health_ok(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIsInstance(payload, dict)
        self.assertTrue(payload.get("ok"))

    def test_index_served(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Lumica Mini App", html)
        self.assertIn("static/assets/js/app.js", html)
        self.assertIn("static/assets/css/app.css", html)

    def test_static_assets_served(self):
        with self.client.get("/static/assets/css/app.css") as css_response:
            self.assertEqual(css_response.status_code, 200)
            self.assertIn(".status-card", css_response.get_data(as_text=True))

        with self.client.get("/static/assets/js/app.js") as js_response:
            self.assertEqual(js_response.status_code, 200)
            self.assertIn("async function init()", js_response.get_data(as_text=True))

    def test_api_routes_registered(self):
        # These endpoints are auth-protected, so the expected baseline is 401
        # (or 403 for admin-only routes), but never 404.
        checks = [
            ("/api/cloud/list", {401}),
            ("/api/me", {401}),
            ("/api/vpn/config", {401}),
            ("/api/admin/settings", {401, 403}),
        ]
        for path, expected_codes in checks:
            response = self.client.get(path)
            self.assertIn(response.status_code, expected_codes, f"unexpected status for {path}")


if __name__ == "__main__":
    unittest.main()
