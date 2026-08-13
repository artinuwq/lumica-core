"""
All tunables for the notification system in one place. Nothing in
services/jobs should hardcode an interval, a retry count, or a threshold —
see spec §7 ("не хардкодить 7, 3, 1 в бизнес-логике").

Load with `NotificationSettings.from_env()` / `.from_dict()` in real
lumica-core wiring (e.g. from the same YAML/env config the rest of the app
already uses). Defaults below are sane for MVP.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SubscriptionReminderSettings:
    enabled: bool = True
    # Days-before-expiry checkpoints. Configurable, not hardcoded in the job.
    intervals_days: tuple[int, ...] = (7, 3, 1)
    # Also notify once on the day it actually expires.
    notify_on_expiry: bool = True


@dataclass(frozen=True)
class ServerHealthSettings:
    # Consecutive failed checks before SERVER_UNAVAILABLE fires.
    failure_threshold: int = 3
    # Consecutive healthy checks before SERVER_RECOVERED fires (avoids
    # flapping on the way back up too).
    recovery_threshold: int = 2


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    # Seconds to wait before attempt N+1, indexed by attempt_number (1-based).
    # If more attempts than entries, the last entry is reused.
    backoff_seconds: tuple[int, ...] = (30, 120, 600, 1800, 3600)

    def delay_for_attempt(self, attempt_number: int) -> int:
        idx = min(attempt_number, len(self.backoff_seconds)) - 1
        return self.backoff_seconds[idx]


@dataclass(frozen=True)
class NotificationSettings:
    subscription_reminders: SubscriptionReminderSettings = field(
        default_factory=SubscriptionReminderSettings
    )
    server_health: ServerHealthSettings = field(default_factory=ServerHealthSettings)
    retry: RetryPolicy = field(default_factory=RetryPolicy)

    # A Notification stuck in PROCESSING longer than this is assumed to
    # belong to a crashed worker and is reset to PENDING by the stale sweeper.
    processing_timeout_seconds: int = 300

    # How many PENDING notifications a single delivery worker tick claims.
    delivery_batch_size: int = 50

    @staticmethod
    def from_dict(raw: dict) -> "NotificationSettings":
        """Merge a partial config dict (e.g. parsed from YAML) over defaults."""
        sr = raw.get("subscription_reminders", {})
        sh = raw.get("server_health", {})
        rt = raw.get("retry", {})
        return NotificationSettings(
            subscription_reminders=SubscriptionReminderSettings(
                enabled=sr.get("enabled", True),
                intervals_days=tuple(sr.get("intervals", [7, 3, 1])),
                notify_on_expiry=sr.get("notify_on_expiry", True),
            ),
            server_health=ServerHealthSettings(
                failure_threshold=sh.get("failure_threshold", 3),
                recovery_threshold=sh.get("recovery_threshold", 2),
            ),
            retry=RetryPolicy(
                max_attempts=rt.get("max_attempts", 5),
                backoff_seconds=tuple(rt.get("backoff_seconds", [30, 120, 600, 1800, 3600])),
            ),
            processing_timeout_seconds=raw.get("processing_timeout_seconds", 300),
            delivery_batch_size=raw.get("delivery_batch_size", 50),
        )


# Example YAML this maps to (spec §7):
#
# notifications:
#   subscription_reminders:
#     enabled: true
#     intervals: [7, 3, 1]
#     notify_on_expiry: true
#   server_health:
#     failure_threshold: 3
#     recovery_threshold: 2
#   retry:
#     max_attempts: 5
#     backoff_seconds: [30, 120, 600, 1800, 3600]
#   processing_timeout_seconds: 300
#   delivery_batch_size: 50
