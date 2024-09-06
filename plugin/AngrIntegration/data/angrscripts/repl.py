import code
import time
from typing import Any, NoReturn

import claripy
import symbolic_field

import angr


def graceful_exit(code: int | None = None) -> NoReturn:
    """A wrapper in place of python's exit that just raises SystemExit without closing stdout or other streams.

    NOTE: Once Python 3.13 can be reliably assumed, this can be replaced with a new parameter to `code.interact`.
    (see `local_exit` at https://docs.python.org/3.13/library/code.html#code.InteractiveConsole)

    :raises SystemExit: Unconditionally.
    """
    raise SystemExit(code)


def start_repl(
    prefix: str = "!<*",
    banner: str = "",
    sm: None | angr.SimulationManager = None,
    constrained_st: None | angr.SimState = None,
    locals: dict[str, Any] = locals(),
) -> None:
    print(prefix + " show_repl")  # instruct the plugin to set up the repl window
    input()  # wait for ghidra's ready signal to proceed
    locals["get_var"] = symbolic_field.get_var
    locals["get_vars"] = symbolic_field.get_vars
    locals["eval_vars"] = symbolic_field.eval_vars
    locals["exit"] = graceful_exit
    locals["quit"] = graceful_exit

    locals["angr"] = angr
    locals["claripy"] = claripy

    if sm is None and "sm" in locals.keys():
        sm = locals["sm"]

    # just printing the simulationmanager is almost always the first action in the REPL, so do that automatically
    real_interpreter_banner = banner + "\nsm: " + repr(sm) + "\n"

    if constrained_st is not None:
        real_interpreter_banner += "\nFound path to target address: see constrained_st\n"

    try:
        code.interact(local=locals, banner=real_interpreter_banner)
    except SystemExit:
        print(prefix + " exit_repl")

        # This input() call could be hit by (very fast) user input rather than ghidra's ready signal. Unfortunately,
        # there's not really any other option (beyond a dumb sleep() call), and if an issue occurs it should resolve
        # itself very quickly.
        input()  # wait for ghidra's ready signal to proceed
        return
