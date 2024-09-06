import sys
from abc import ABC, abstractmethod
from typing import Any

import archinfo

import angr


class ArchitectureInterface(ABC):

    @abstractmethod
    def is_compatible(self, lang: str) -> int:
        """This MUST be overridden to define the languages your architecture interface supports. Should return an
        integer representing the degree of that support.

        Suggested return values:
        - 0   : no support
        - 10  : default/fallback interface
        - 50  : architecture specific support
        - 100 : project specific support

        When a program is opened in Ghidra, the plugin will look for the architecture interface with the highest support
        value for the architecture/language of the program to use by default.

        :param lang: The Ghidra language string being tested
        :return: An integer repesenting the level of support.
        """
        return 0

    def get_calling_convention(self) -> type[angr.calling_conventions.SimCC] | None:
        """Override this to specify the calling convention to use for SimProcedures and call states.

        :return: The calling convention to use, or None to let angr attempt to figure it out
        """
        return None

    def get_main_obj_args(self) -> dict[str, Any]:
        """Override this to specify any options passed to cle to load the main binary.

        :return: A dict containing any options required
        """
        return {}

    def get_arch(self) -> archinfo.Arch | None:
        """Override this to specify the archinfo.Arch object that angr will use for all operations.

        :return: The architecture to use, or None to let angr attempt to figure it out
        """
        return None

    def get_extra_loader_args(self) -> dict[str, Any]:
        """Override this to specify any extra loader arguments (outside of the main object ones)

        :return: A dict containing any additional options required
        """
        return {}

    def get_engine(self) -> angr.engines.SimEngine:
        """Override this to specify the engine angr should use.

        When working with a strange architecture, you probably want to return angr.engines.UberPcodeEngine, or some
        specialisation of that class. By default will use the UberEngine (VEX).

        :return: The engine to use
        """
        return angr.engines.UberEngine

    def get_hooks(self) -> dict[int, angr.SimProcedure]:
        """Override this to specify any architecture-wide hooks (e.g. to implement call gate interrupts, or syscalls)

        :return: A dictionary from address to SimProcedure to use.
        """
        return {}

    def get_techniques(self) -> list[angr.ExplorationTechnique]:
        """Override this to specify any architecture-wide exploration techinques (e.g. to tell angr when the machine has
        halted, for instance)

        :return: A list of ExplorationTechniques to use.
        """
        return []

    def get_loader_args(self) -> dict[str, Any]:
        """Get all the loader arguments as a single dictionary.

        :return: The arguments, ready to be passed to cle
        """
        kwargs = self.get_extra_loader_args()
        kwargs["main_opts"] = self.get_main_obj_args()
        arch = self.get_arch()
        if arch is not None:
            kwargs["arch"] = self.get_arch()
        return kwargs

    def apply_state_options(self, st: angr.SimState) -> None:
        """Apply any state options or other initialization to the state that will be used as the start of simulation.

        :param st: The state to modify
        """
        return

    def extra_print_state(self, st: angr.SimState, detailed: bool) -> None:
        """Print any relevant extra architecture-specific information about the state

        :param st: The state to print
        """
        pass


class DefaultArchitectureInterface(ArchitectureInterface):
    def is_compatible(self, lang: str) -> int:
        return 10  # the default interface provides support for most VEX targets, but is a general fallback


def get() -> ArchitectureInterface:
    """Every architecture module MUST override this function to provide the ArchitectureInterface it defines.

    :return: An instance of the ArchitectureInterface defined by this file.
    """
    return DefaultArchitectureInterface()
