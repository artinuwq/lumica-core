"""Update engine: success, no-op, dirty tree, network error and automatic rollback.

Uses throw-away local git repos and a fake service controller, so it needs
neither network nor systemd.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)

from lumica.update import UpdateManager  # noqa: E402
from lumica.update import backup  # noqa: E402

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
}


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=GIT_ENV)


class FakeService:
    update_unit = "lumica-update.service"

    def __init__(self, healthy_after_restart=True, on_restart=None):
        self.healthy_after_restart = healthy_after_restart
        self.on_restart = on_restart
        self.calls = []
        self._restarted_once = False

    def restart(self):
        self.calls.append("restart")
        if self.on_restart:
            self.on_restart()
        return True, "ok"

    def stop(self):
        self.calls.append("stop")
        return True, "ok"

    def start(self):
        self.calls.append("start")
        self._restarted_once = True  # the old version is started again after rollback
        return True, "ok"

    def wait_healthy(self, url, timeout=60, stable_for=8):
        return (self.healthy_after_restart or self._restarted_once), "fake"

    def unit_exists(self, unit):
        return False


class UpdateEngineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        base = Path(self._tmp.name)
        self.origin, self.seed, self.app = base / "origin.git", base / "seed", base / "app"
        git(base, "init", "--bare", "-b", "main", str(self.origin))
        git(base, "clone", str(self.origin), str(self.seed))
        git(self.seed, "checkout", "-b", "main")
        (self.seed / "src").mkdir()
        (self.seed / "src" / "mod.py").write_text("VERSION = 1\n")
        (self.seed / ".gitignore").write_text("database/\n.env\n")
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-m", "v1")
        git(self.seed, "push", "origin", "main")
        git(base, "clone", str(self.origin), str(self.app))

        (self.app / ".env").write_text("TELEGRAM_BOT_TOKEN=123:secret\n")
        (self.app / "database").mkdir()
        self.db = self.app / "database" / "app_new.db"
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE alembic_version (version_num TEXT)")
            conn.execute("INSERT INTO alembic_version VALUES ('rev1')")
            conn.execute("CREATE TABLE users (name TEXT)")
            conn.execute("INSERT INTO users VALUES ('alice')")

    def tearDown(self):
        self._tmp.cleanup()

    def _publish(self, body="VERSION = 2\n", name="mod.py"):
        (self.seed / "src" / name).write_text(body)
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-m", f"change {name}")
        git(self.seed, "push", "origin", "main")

    def _manager(self, service):
        return UpdateManager(repo_dir=self.app, service=service)

    def _db_rev(self):
        with sqlite3.connect(self.db) as conn:
            return conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]

    def test_update_keeps_config_and_data_and_makes_backup(self):
        self._publish()
        service = FakeService()
        result = self._manager(service).apply()
        self.assertTrue(result.success, result.message)
        self.assertEqual((self.app / "src" / "mod.py").read_text(), "VERSION = 2\n")
        self.assertEqual((self.app / ".env").read_text(), "TELEGRAM_BOT_TOKEN=123:secret\n")
        self.assertEqual(service.calls, ["restart"])
        self.assertIsNotNone(backup.latest_backup(self.app / "database"))
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT name FROM users").fetchone()[0], "alice")

    def test_up_to_date_is_noop(self):
        service = FakeService()
        result = self._manager(service).apply()
        self.assertTrue(result.success)
        self.assertTrue(result.noop)
        self.assertEqual(service.calls, [])

    def test_service_that_does_not_start_triggers_rollback_incl_migrated_db(self):
        self._publish()

        def fake_migration():  # the new version migrated the schema before crashing
            with sqlite3.connect(self.db) as conn:
                conn.execute("UPDATE alembic_version SET version_num = 'rev2'")

        service = FakeService(healthy_after_restart=False, on_restart=fake_migration)
        result = self._manager(service).apply()
        self.assertFalse(result.success)
        self.assertTrue(result.rolled_back)
        self.assertEqual((self.app / "src" / "mod.py").read_text(), "VERSION = 1\n")
        self.assertEqual(self._db_rev(), "rev1")
        self.assertEqual(service.calls, ["restart", "stop", "start"])

    def test_broken_source_is_rejected_before_restart(self):
        self._publish("def broken(:\n", name="bad.py")
        service = FakeService()
        result = self._manager(service).apply()
        self.assertFalse(result.success)
        self.assertTrue(result.rolled_back)
        self.assertFalse((self.app / "src" / "bad.py").exists())
        self.assertEqual(service.calls, [])  # the running service was never touched

    def test_local_changes_block_update_unless_forced(self):
        self._publish()
        (self.app / "src" / "mod.py").write_text("VERSION = 'local hack'\n")
        result = self._manager(FakeService()).apply()
        self.assertFalse(result.success)
        self.assertEqual((self.app / "src" / "mod.py").read_text(), "VERSION = 'local hack'\n")

    def test_unreachable_remote_gives_network_error(self):
        git(self.app, "remote", "set-url", "origin", str(self.app / "no-such-repo.git"))
        status = self._manager(FakeService()).check()
        self.assertFalse(status.local_sha)
        self.assertIn("ошибк", status.message)

    def test_manual_rollback_returns_to_previous_version(self):
        self._publish()
        manager = self._manager(FakeService())
        self.assertTrue(manager.apply().success)
        result = manager.rollback()
        self.assertTrue(result.success, result.message)
        self.assertEqual((self.app / "src" / "mod.py").read_text(), "VERSION = 1\n")


if __name__ == "__main__":
    unittest.main()
