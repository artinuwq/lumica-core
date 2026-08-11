"""Self-update engine: the single source of truth for checking/applying
git-based updates and restarting the service.

Both the HTTP admin API (lumica.api.routes.update) and the Telegram
chat-ops bot (lumica.bot.chatops) are thin wrappers around UpdateManager -
neither reimplements this logic.
"""

from .manager import UpdateManager
from .manifest import UpdateResult, UpdateStatus

__all__ = ["UpdateManager", "UpdateResult", "UpdateStatus"]
