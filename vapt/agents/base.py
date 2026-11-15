"""Base agent class with budget enforcement and kill-switch integration."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from vapt.core import RunContext, Finding
from vapt.kill_switch import KillSwitch

log = logging.getLogger(__name__)


class AgentBudgetExceeded(Exception):
    pass


class BaseAgent(ABC):
    name: str = "base"
    step_budget: int = 200
    time_budget: float = 1800.0  # seconds

    def __init__(self, ctx: RunContext, kill_switch: KillSwitch, config: dict | None = None):
        self.ctx = ctx
        self.kill_switch = kill_switch
        self.config = config or {}
        self._steps = 0
        self._start_time: float = 0
        self._findings: list[Finding] = []
        self.log = logging.getLogger(f"vapt.agents.{self.name}")

    def _check_budgets(self) -> None:
        self._steps += 1
        elapsed = time.time() - self._start_time
        if self._steps > self.step_budget:
            raise AgentBudgetExceeded(f"{self.name}: step budget {self.step_budget} exceeded")
        if elapsed > self.time_budget:
            raise AgentBudgetExceeded(f"{self.name}: time budget {self.time_budget}s exceeded")
        if self.kill_switch.triggered:
            raise AgentBudgetExceeded(f"{self.name}: kill switch triggered")

    def run(self) -> list[Finding]:
        self._start_time = time.time()
        self.log.info("Starting agent: %s", self.name)
        try:
            self._findings = self.execute()
        except AgentBudgetExceeded as e:
            self.log.warning("Budget exceeded: %s", e)
            self.ctx.add_error(self.name, str(e))
        except Exception as e:
            self.log.error("Agent %s failed: %s", self.name, e, exc_info=True)
            self.ctx.add_error(self.name, str(e))
        elapsed = time.time() - self._start_time
        self.log.info(
            "Agent %s finished: %d findings in %.1fs (%d steps)",
            self.name, len(self._findings), elapsed, self._steps,
        )
        return self._findings

    @abstractmethod
    def execute(self) -> list[Finding]:
        ...

    def add_finding(self, f: Finding) -> None:
        f.agent = self.name
        self._findings.append(f)

    def step(self) -> None:
        self._check_budgets()
