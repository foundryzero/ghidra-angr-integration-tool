import os.path
import time
from datetime import timedelta
from typing import Any

import repl
from symbolic_field import brk

import angr


class ProgressReportExplorationTechnique(angr.ExplorationTechnique):
    """
    An ExplorationTechnique that prints the current progress, measured by stash sizes, at most once every delay period.
    """

    def __init__(self, prefix: str, delay: float):
        self.prefix = prefix
        self.delay = delay
        self.initial_clock: float = time.time()
        self.last_clock: float = 0

    def step(self, simgr: angr.SimulationManager, stash: str = "active", **kwargs: Any) -> None:
        if (time.time() - self.last_clock) >= self.delay:
            self.last_clock = time.time()

            status = ""
            for name, _stash in simgr.stashes.items():
                if len(_stash) != 0:
                    status += f"{len(_stash)} {name} | "
            if len(simgr.errored) != 0:
                status += f"{len(simgr.errored)} errored | "

            print(
                f"{self.prefix} progress_report {status[:-3]} \\n {str(timedelta(seconds=self.last_clock-self.initial_clock))[:-4]}"
            )

        simgr.step(stash=stash, **kwargs)


class BreakIntoREPLTechnique(angr.ExplorationTechnique):
    def __init__(self, break_filename: str):
        self.break_filename = break_filename

    def step(self, simgr: angr.SimulationManager, stash: str = "active", **kwargs: Any) -> None:
        if self.should_break():
            os.remove(self.break_filename)
            brk(sm=simgr, p=simgr._project)

        simgr.step(stash=stash, **kwargs)

    def should_break(self) -> bool:
        return os.path.isfile(self.break_filename)
