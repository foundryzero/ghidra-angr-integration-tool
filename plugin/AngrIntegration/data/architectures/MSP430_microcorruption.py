from typing import Any, cast

import archinfo
import cle
from architecture_interface import ArchitectureInterface

import angr
from angr.calling_conventions import SimCC, SimRegArg, SimStackArg

# ArchPcode assumes that you're either on 32 or 64 bit systems with sensible word sizes
# but this isn't the case here :( int is only 16 bits wide.
MSP430Arch = archinfo.ArchPcode(language="TI_MSP430:LE:16:default")
MSP430Arch.sizeof = {"short": 16, "int": 16, "long": 32, "long long": 64}


# https://www.ti.com/lit/an/slaa534a/slaa534a.pdf chapter 3
class SimCCMSP430(SimCC):
    ARG_REGS = ["r15", "r14", "r13", "r12"]
    RETURN_ADDR = SimStackArg(0, 2)
    RETURN_VAL = SimRegArg("r15", 2)
    STACKARG_SP_DIFF = 2
    CALLER_SAVED_REGS = ["r11", "r12", "r13", "r14", "r15"]
    ARCH = MSP430Arch  # type: ignore


class MSP430HaltTechnique(angr.exploration_techniques.ExplorationTechnique):
    def filter(self, simgr: angr.SimulationManager, state: angr.SimState, **kwargs: Any) -> str:
        if state.solver.is_true(state.regs.sr.chop(1)[11] == 0x1):  # CPUOFF flag in status register
            # print("hit cpuoff, halting path")
            return "deadended"
        else:
            return cast(str, simgr.filter(state, **kwargs))


class MSP430MicrocorruptionInterruptHook(angr.SimProcedure):
    NO_RET = True

    def run(self) -> None:
        state = self.state

        if self.successors is None:  # this is probably unreachable but helps with type checking
            raise TypeError("hook successors hasn't been setup correctly!")

        # Get the interrupt code, bit-indexing the sr register
        interrupt_code = state.regs.sr[14:8].zero_extend(1)  # type: ignore

        if not state.solver.is_false(interrupt_code == 0x0):  # putchar
            new_state = state.copy()
            new_state.history.jumpkind = (
                "Ijk_NoHook"  # Tell angr that this state is the result of exiting from a hook here
            )
            new_state.scratch.guard = interrupt_code == 0x0

            param1 = new_state.memory.load(state.regs.sp + 0x8, size=1)  # type: ignore  # The char to write
            stdout = new_state.posix.get_fd(1)  # This isn't 'real' posix but it's the standard way of buffering i/o
            stdout.write_data(param1)

            self.successors.add_successor(new_state, 0x0010, interrupt_code == 0x0, "Ijk_NoHook")

        if not state.solver.is_false(interrupt_code == 0x1):  # getchar
            new_state = state.copy()
            new_state.history.jumpkind = "Ijk_NoHook"
            new_state.scratch.guard = interrupt_code == 0x1

            stdin = new_state.posix.get_fd(0)
            (data, real_length) = stdin.read_data(1)
            new_state.regs.r12 = new_state.solver.If(
                real_length == 0, -1, data.zero_extend(new_state.arch.sizeof["int"] - 8)
            )  # taken from the libc shim for fgetc

            self.successors.add_successor(new_state, 0x0010, interrupt_code == 0x1, "Ijk_NoHook")

        if not state.solver.is_false(interrupt_code == 0x2):  # gets
            new_state = state.copy()
            new_state.history.jumpkind = "Ijk_NoHook"
            new_state.scratch.guard = interrupt_code == 0x2
            stdin = new_state.posix.get_fd(0)

            param1 = new_state.memory.load(state.regs.sp + 0x8, size=2)  # type: ignore # The address to write the data to
            param2 = new_state.memory.load(state.regs.sp + 0xA, size=1)  # type: ignore # Max size read

            (data, real_length) = stdin.read_data(state.solver.eval(param2))
            new_state.memory.store(param1.reversed, data)  # reverse the endianness for some reason

            self.successors.add_successor(new_state, 0x0010, interrupt_code == 0x2, "Ijk_NoHook")

        if not state.solver.is_false(interrupt_code == 0x7D):  # HSM-1 trigger
            new_state = state.copy()
            new_state.history.jumpkind = "Ijk_NoHook"
            new_state.scratch.guard = interrupt_code == 0x7D

            # Normally this would check the string at param1 against the password in the HSM, and set the flag at param2 if
            # it matches. However, angr can't know the password, so can just model it as always rejecting, i.e. a nop
            # This is fine because the exploit here shouldn't require knowledge of (or a specific) password

            self.successors.add_successor(new_state, 0x0010, interrupt_code == 0x7D, "Ijk_NoHook")

        if not state.solver.is_false(interrupt_code == 0x7E):  # HSM-1 trigger
            new_state = state.copy()
            new_state.history.jumpkind = "Ijk_NoHook"
            new_state.scratch.guard = interrupt_code == 0x7E

            # Normally this would check the string at param1 against the password in the HSM, and open the lock if
            # it matches. However, angr can't know the password, so can just model it as always rejecting, i.e. a nop
            # This is fine because the exploit here shouldn't require knowledge of (or a specific) password

            self.successors.add_successor(new_state, 0x0010, interrupt_code == 0x7E, "Ijk_NoHook")

        if not state.solver.is_false(interrupt_code == 0x7F):  # unlock door
            new_state = state.copy()
            new_state.history.jumpkind = "Ijk_NoHook"
            new_state.scratch.guard = interrupt_code == 0x7F

            # state.globals is a dict that gets passed down from a state to it's successors, so can be used to store values
            # relevant to a specific path through the program.
            new_state.globals["lock_unlocked"] = True
            self.successors.add_successor(new_state, 0x0010, interrupt_code == 0x7F, "Ijk_NoHook")


class MSP430ArchitectureIf(ArchitectureInterface):

    def is_compatible(self, lang: str) -> int:
        if lang == "TI_MSP430:LE:16:default":
            return 100
        else:
            return 0

    def get_calling_convention(self) -> type[angr.calling_conventions.SimCC]:
        return SimCCMSP430

    def get_main_obj_args(self) -> dict[str, Any]:
        return {
            "backend": "blob",
            "entry_point": 0x4400,
            "base_addr": 0x0,
            "segments": [(0x0, 0x0, 0x4FFF), (0x6000, 0x6000, 0xFFFF - 0x6000)],
        }

    def get_arch(self) -> archinfo.Arch:
        return MSP430Arch

    def get_extra_loader_args(self) -> dict[str, Any]:
        return {"rebase_granularity": 0x100}

    def get_engine(self) -> angr.engines.SimEngine:
        return angr.engines.UberEnginePcode

    def get_techniques(self) -> list[angr.ExplorationTechnique]:
        return [MSP430HaltTechnique()]  # type: ignore

    def get_hooks(self) -> dict[int, angr.SimProcedure]:
        return {0x0010: MSP430MicrocorruptionInterruptHook()}  # type: ignore

    def apply_state_options(self, st: angr.SimState) -> None:
        st.globals["lock_unlocked"] = False

    def extra_print_state(self, st: angr.SimState, detailed: bool) -> None:
        print(f"lock state: {"UNLOCKED" if st.globals["lock_unlocked"] else "LOCKED"}")


def get() -> ArchitectureInterface:
    return MSP430ArchitectureIf()
