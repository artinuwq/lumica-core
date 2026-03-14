import sys
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import SimpleNamespace

from flask import Flask, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)

import lumica.api.helpers.admin as admin_helpers_module  # noqa: E402
from lumica.api.helpers.admin import build_admin_helpers  # noqa: E402
from lumica.domain.models import (  # noqa: E402
    Base,
    InboundGroup,
    InboundGroupMember,
    Panel,
    PanelInbound,
    PanelSecret,
    PendingBinding,
    Subscription,
    User,
    UserConnection,
    VpnAccount,
)


class _FakeQuery:
    def __init__(self, value):
        self._value = value

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def first(self):
        return self._value


class _FakeDb:
    def __init__(self, subscription):
        self.subscription = subscription
        self.added = []

    def query(self, model):
        if model is not Subscription:
            raise AssertionError(f"Unexpected model: {model}")
        return _FakeQuery(self.subscription)

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, Subscription):
            self.subscription = obj

    def flush(self):
        return None


class _FakePanelRegistry:
    def __init__(self):
        self.invalidated = []

    def invalidate_panel(self, panel_id):
        self.invalidated.append(panel_id)


class AdminHelpersSubscriptionTest(unittest.TestCase):
    def setUp(self):
        if hasattr(admin_helpers_module, "_latest_subscription"):
            delattr(admin_helpers_module, "_latest_subscription")

        self.app = Flask(__name__)
        self.helpers = build_admin_helpers(
            {
                "Subscription": Subscription,
                "jsonify": jsonify,
                "Decimal": Decimal,
                "InvalidOperation": InvalidOperation,
                "datetime": datetime,
                "timezone": timezone,
                "timedelta": timedelta,
                "utcnow": lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
                "_as_utc": lambda value: value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc),
            }
        )

    def test_apply_subscription_payload_switches_lifetime_to_active_without_auth_helper(self):
        subscription = Subscription(user_id=7, status="lifetime")
        user = SimpleNamespace(id=7, profile_data=None)
        db = _FakeDb(subscription)

        with self.app.app_context():
            error = self.helpers["_apply_admin_subscription_payload"](
                db,
                user,
                {
                    "status": "active",
                    "access_until": "2026-02-01T23:59:59",
                },
            )

        self.assertIsNone(error)
        self.assertEqual(subscription.status, "active")
        self.assertEqual(subscription.access_until, datetime(2026, 2, 1, 23, 59, 59, tzinfo=timezone.utc))
        self.assertEqual(db.added, [])


class AdminHelpersPanelDeleteTest(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
        self.Session = sessionmaker(bind=self.engine, autocommit=False, autoflush=False, future=True)
        Base.metadata.create_all(self.engine)
        self.panel_registry = _FakePanelRegistry()
        self.helpers = build_admin_helpers(
            {
                "Panel": Panel,
                "PanelInbound": PanelInbound,
                "PanelSecret": PanelSecret,
                "PendingBinding": PendingBinding,
                "VpnAccount": VpnAccount,
                "InboundGroupMember": InboundGroupMember,
                "UserConnection": UserConnection,
                "panel_registry": self.panel_registry,
            }
        )

    def tearDown(self):
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    def test_delete_panel_removes_related_rows_and_clears_selected_group_member(self):
        with self.Session() as db:
            user = User(telegram_id="10001", role="user")
            group = InboundGroup(key="vless", title="VLESS")
            secret = PanelSecret(
                id="secret-1",
                provider="3xui",
                auth_type="login_password",
                ciphertext="enc",
            )
            panel = Panel(
                id="panel-1",
                name="Old panel",
                provider="3xui",
                base_url="https://panel.example.test/panel/api",
                auth_type="login_password",
                auth_secret_ref=secret.id,
                is_active=1,
                health_status="green",
            )
            db.add_all([user, group, secret, panel])
            db.flush()

            inbound_one = PanelInbound(
                panel_id=panel.id,
                external_inbound_id="101",
                protocol="vless",
                port=443,
                enabled=1,
                show_in_app=1,
            )
            inbound_two = PanelInbound(
                panel_id=panel.id,
                external_inbound_id="102",
                protocol="http",
                port=8080,
                enabled=1,
                show_in_app=1,
            )
            db.add_all([inbound_one, inbound_two])
            db.flush()

            member_one = InboundGroupMember(group_id=group.id, panel_inbound_id=inbound_one.id)
            member_two = InboundGroupMember(group_id=group.id, panel_inbound_id=inbound_two.id)
            vpn_account = VpnAccount(
                user_id=user.id,
                protocol="vless",
                panel_inbound_id=101,
                panel_inbound_ref_id=inbound_one.id,
                identifier="client-1",
                status="active",
            )
            pending_binding = PendingBinding(
                telegram_id=user.telegram_id,
                protocol="vless",
                panel_inbound_id=101,
                panel_inbound_ref_id=inbound_one.id,
                identifier="pending-1",
                status="pending",
            )
            db.add_all([member_one, member_two, vpn_account, pending_binding])
            db.flush()

            user_connection = UserConnection(
                user_id=user.id,
                group_id=group.id,
                selected_member_id=member_one.id,
            )
            db.add(user_connection)
            db.commit()

            result = self.helpers["_delete_panel"](db, panel.id)
            db.commit()

            self.assertIsNotNone(result)
            self.assertEqual(result["panel_id"], panel.id)
            self.assertEqual(result["deleted"]["panels"], 1)
            self.assertEqual(result["deleted"]["panel_secrets"], 1)
            self.assertEqual(result["deleted"]["panel_inbounds"], 2)
            self.assertEqual(result["deleted"]["vpn_accounts"], 1)
            self.assertEqual(result["deleted"]["pending_bindings"], 1)
            self.assertEqual(result["deleted"]["group_members"], 2)
            self.assertEqual(result["deleted"]["user_connections_cleared"], 1)

            self.assertEqual(db.query(Panel).count(), 0)
            self.assertEqual(db.query(PanelSecret).count(), 0)
            self.assertEqual(db.query(PanelInbound).count(), 0)
            self.assertEqual(db.query(VpnAccount).count(), 0)
            self.assertEqual(db.query(PendingBinding).count(), 0)
            self.assertEqual(db.query(InboundGroupMember).count(), 0)
            self.assertEqual(db.query(InboundGroup).count(), 1)
            self.assertIsNone(db.query(UserConnection).first().selected_member_id)
            self.assertEqual(self.panel_registry.invalidated, [panel.id])


if __name__ == "__main__":
    unittest.main()
