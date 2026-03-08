"""Subscription expiration background job."""

from lumica.services.subscriptions import run as run_expire_subscriptions

__all__ = ["run_expire_subscriptions"]
