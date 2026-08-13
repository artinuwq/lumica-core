"""
Classifies exceptions raised by the Telegram bot client into
(error_code, retryable) so channel.py and NotificationService don't need to
know aiogram/telegram-specific exception types.

Written against aiogram's exception hierarchy
(aiogram.exceptions.TelegramAPIError and subclasses); adjust the isinstance
checks if the real bot integration uses a different Telegram library.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ClassifiedError:
    error_code: str
    retryable: bool
    message: str


def classify(exc: Exception) -> ClassifiedError:
    name = type(exc).__name__
    text = str(exc).lower()

    # --- permanent, do-not-retry ---
    if "bot was blocked" in text or name == "TelegramForbiddenError":
        return ClassifiedError("USER_BLOCKED_BOT", retryable=False, message=str(exc))
    if "chat not found" in text or "user is deactivated" in text:
        return ClassifiedError("CHAT_UNAVAILABLE", retryable=False, message=str(exc))
    if "message is too long" in text or "wrong parameter" in text or name == "TelegramBadRequest":
        # A malformed request will fail identically on retry — treat as
        # permanent so it doesn't burn the retry budget for nothing, and
        # surfaces to admins quickly (bad template/context is a bug).
        return ClassifiedError("BAD_REQUEST", retryable=False, message=str(exc))

    # --- transient, retryable ---
    if "flood control" in text or name == "TelegramRetryAfter":
        return ClassifiedError("RATE_LIMITED", retryable=True, message=str(exc))
    if name in ("TelegramNetworkError", "TelegramServerError", "TimeoutError"):
        return ClassifiedError("NETWORK_ERROR", retryable=True, message=str(exc))

    # Unknown error: default to retryable so we don't silently drop a
    # notification because of an error shape we didn't anticipate, but it's
    # still budget-capped by RetryPolicy.max_attempts.
    return ClassifiedError("UNKNOWN_ERROR", retryable=True, message=str(exc))
