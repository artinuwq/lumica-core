from types import SimpleNamespace

from lumica.bot import onboarding


def test_admin_role_can_open_mini_app_without_bindings(monkeypatch):
    monkeypatch.setattr(onboarding, "load_role_bindings", lambda: {})

    assert onboarding._has_admin_mini_app_access(SimpleNamespace(role="admin"), 10001)
    assert onboarding._has_admin_mini_app_access(SimpleNamespace(role="owner"), 10002)


def test_role_binding_can_open_mini_app(monkeypatch):
    monkeypatch.setattr(onboarding, "load_role_bindings", lambda: {"10003": "admin"})

    assert onboarding._has_admin_mini_app_access(SimpleNamespace(role="user"), 10003)


def test_regular_user_does_not_get_admin_mini_app(monkeypatch):
    monkeypatch.setattr(onboarding, "load_role_bindings", lambda: {})

    assert not onboarding._has_admin_mini_app_access(SimpleNamespace(role="user"), 10004)