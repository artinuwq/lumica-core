from datetime import datetime, timezone

from lumica.services.payments import add_calendar_month


def test_add_calendar_month_preserves_day_when_available():
    value = datetime(2026, 9, 15, 15, 30, tzinfo=timezone.utc)

    assert add_calendar_month(value) == datetime(2026, 10, 15, 15, 30, tzinfo=timezone.utc)


def test_add_calendar_month_clamps_to_short_month():
    january_31 = datetime(2026, 1, 31, 15, 30, tzinfo=timezone.utc)
    leap_january_31 = datetime(2024, 1, 31, 15, 30, tzinfo=timezone.utc)

    assert add_calendar_month(january_31) == datetime(2026, 2, 28, 15, 30, tzinfo=timezone.utc)
    assert add_calendar_month(leap_january_31) == datetime(2024, 2, 29, 15, 30, tzinfo=timezone.utc)


def test_add_multiple_calendar_months_preserves_month_day():
    value = datetime(2026, 11, 15, 15, 30, tzinfo=timezone.utc)

    assert add_calendar_month(value, 2) == datetime(2027, 1, 15, 15, 30, tzinfo=timezone.utc)