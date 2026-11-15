"""Kill switch: stops all agents on device disconnect, out-of-scope traffic, or budget exceeded."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from vapt.core import RunContext, Scope

log = logging.getLogger(__name__)


class KillSwitch:
    def __init__(self, ctx: RunContext):
        self._ctx = ctx
        self._armed = True
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[], None]] = []

    @property
    def triggered(self) -> bool:
        return self._ctx.killed

    def register_callback(self, cb: Callable[[], None]) -> None:
        with self._lock:
            self._callbacks.append(cb)

    def trigger(self, reason: str) -> None:
        with self._lock:
            if self._ctx.killed:
                return
            self._ctx.killed = True
            self._ctx.kill_reason = reason
            log.critical("KILL SWITCH: %s", reason)
            for cb in self._callbacks:
                try:
                    cb()
                except Exception as e:
                    log.error("Kill callback error: %s", e)

    def check_device(self, device_online: Callable[[], bool]) -> None:
        if not device_online():
            self.trigger("Device disconnected")

    def check_host(self, host: str) -> None:
        if self._ctx.scope and not self._ctx.scope.check_host(host):
            self.trigger(f"Traffic to out-of-scope host: {host}")

    def check_budget(self, elapsed: float, budget: float) -> None:
        if elapsed > budget:
            self.trigger(f"Time budget exceeded: {elapsed:.0f}s > {budget:.0f}s")

    def check_step_budget(self, steps: int, budget: int) -> None:
        if steps > budget:
            self.trigger(f"Step budget exceeded: {steps} > {budget}")
