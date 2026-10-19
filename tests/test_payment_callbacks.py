from decimal import Decimal
from types import SimpleNamespace

from lumica.bot.menus import format_subscription_message
from lumica.bot.payments import _parse_payment_target


def test_parse_single_subscription_payment_callback():
    assert _parse_payment_target("payment:send:41") == (41, False)


def test_parse_group_payment_callback():
    assert _parse_payment_target("payment:send-group:7") == (7, True)


def test_parse_payment_callback_rejects_invalid_targets():
    assert _parse_payment_target("payment:send-group:nope") is None
    assert _parse_payment_target("payment:unknown:41") is None


def test_family_member_subscription_message_hides_billing_amount_and_date():
    subscription = SimpleNamespace(status="active", access_until=None, price_amount=Decimal("120"))

    text = format_subscription_message(subscription, [], hide_billing=True)

    assert "120" not in text
    assert "только администратор" in text.lower()