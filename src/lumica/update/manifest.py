from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class UpdateStatus:
    branch: str
    local_sha: str
    remote_sha: str
    up_to_date: bool
    dirty: bool
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class UpdateResult:
    success: bool
    message: str
    previous_sha: str | None = None
    current_sha: str | None = None
    restarted: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


__all__ = ["UpdateStatus", "UpdateResult"]
