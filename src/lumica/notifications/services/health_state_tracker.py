"""
Shared state machine backing ChannelState, used by both the VPN health job
and the server health job (ARCHITECTURE.md §9). A raw "healthy/unhealthy"
signal only produces a notification-worthy *transition* when it actually
flips the tracked status — repeated identical signals just update the
failure counter, so a resource stuck DOWN for hours doesn't re-notify.
"""

from __future__ import annotations

import datetime as dt
import enum
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from lumica.notifications.domain.enums import ChannelHealthStatus
from lumica.notifications.domain.models import ChannelState


class Transition(str, enum.Enum):
    NONE = "none"
    BECAME_DOWN = "became_down"
    BECAME_UP = "became_up"


@dataclass(frozen=True)
class CheckResult:
    transition: Transition
    # The state row's changed_at at the moment of *this* transition. Used by
    # callers as (part of) a dedup key: it's read under a row lock, so two
    # concurrent callers racing on the same state_key can never observe two
    # different "genuine" transitions with different timestamps for what is
    # really the same event — one of them will block on the lock and see
    # Transition.NONE once it proceeds.
    changed_at: dt.datetime


class HealthStateTracker:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_check(
        self,
        state_key: str,
        is_healthy: bool,
        failure_threshold: int = 1,
        recovery_threshold: int = 1,
    ) -> CheckResult:
        # Row-level lock so concurrent callers for the same state_key
        # serialize instead of racing on the read-modify-write below.
        result = await self._session.execute(
            select(ChannelState).where(ChannelState.state_key == state_key).with_for_update()
        )
        state = result.scalar_one_or_none()
        if state is None:
            state = ChannelState(
                state_key=state_key,
                status=ChannelHealthStatus.UP,
                consecutive_failures=0,
            )
            self._session.add(state)

        # `consecutive_failures` is reused directionally: while status==UP it
        # counts consecutive unhealthy signals (progress toward going DOWN);
        # while status==DOWN it counts consecutive healthy signals (progress
        # toward recovery). Any signal in the opposite direction resets it.
        if is_healthy:
            if state.status == ChannelHealthStatus.UP:
                state.consecutive_failures = 0
                await self._session.flush()
                return CheckResult(Transition.NONE, state.changed_at)

            # status == DOWN: accumulate recovery progress
            state.consecutive_failures += 1
            if state.consecutive_failures >= recovery_threshold:
                state.status = ChannelHealthStatus.UP
                state.consecutive_failures = 0
                state.changed_at = dt.datetime.now(dt.timezone.utc)
                await self._session.flush()
                return CheckResult(Transition.BECAME_UP, state.changed_at)
            await self._session.flush()
            return CheckResult(Transition.NONE, state.changed_at)

        # unhealthy signal
        if state.status == ChannelHealthStatus.DOWN:
            state.consecutive_failures = 0  # reset recovery progress
            await self._session.flush()
            return CheckResult(Transition.NONE, state.changed_at)

        # status == UP: accumulate failure progress
        state.consecutive_failures += 1
        if state.consecutive_failures >= failure_threshold:
            state.status = ChannelHealthStatus.DOWN
            state.consecutive_failures = 0
            state.changed_at = dt.datetime.now(dt.timezone.utc)
            await self._session.flush()
            return CheckResult(Transition.BECAME_DOWN, state.changed_at)

        await self._session.flush()
        return CheckResult(Transition.NONE, state.changed_at)
