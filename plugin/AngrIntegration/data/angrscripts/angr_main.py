# isort: skip_file
import functools
import importlib.util
import json
import sys
import traceback
from typing import Any, Callable

import claripy
import cle
import angr
import psutil

import exploration_techniques
import repl
import symbolic_field


class AngrError(Exception):
    pass


interpreter_banner = """
Post-execution angr python REPL

Useful objects:
sm - the SimulationManager
st - the starting state
p  - the angr project
"""

# MUST match the equivalent constant on the java side
GHIDRA_COMMAND_PREFIX = "!<*"


class UnconstrainedWatcher(angr.ExplorationTechnique):
    """Tiny ExplorationTechinque that halts when an unconstrained state is reached."""

    def __init__(self) -> None:  # make mypy happy
        pass

    def complete(self, simgr: angr.SimulationManager) -> bool:
        return len(simgr.unconstrained) != 0


def main() -> None:
    """
    Runs angr using settings defined by a json configuration file. [For documentation on the file's contents, see
    AngrConfiguration.java, which gets serialized to create this file.]

    This function is intended to be run by the Ghidra plugin, not directly - when being run by Ghidra, the usual stdout
    / stderr are redirected to the Ghidra console or REPL, and a special prefix (GHIDRA_COMMAND_PREFIX) causes them to
    be interpreted by the plugin itself. This prefix is chosen because it's unlikely to be used accidentally by some
    other script that this ends up invoking.

    Current GHIDRA_COMMAND_PREFIX commands:

    - `!<* show_repl`: instructs Ghidra to setup a REPL window and start redirecting I/O to it rather than the read-only
        console
    - `!<* progress_report <str>`: provides a progress report to the Ghidra UI, to be displayed near the Start button.
    """
    if len(sys.argv) != 2:
        print("Usage: python angr_main.py <path to configuration>")
        exit(1)

    print("Loading config file...")
    file_path = sys.argv[1]

    with open(file_path, "r") as f:
        config = json.load(f)

    print("Loaded config file: " + str(config))

    # Load the base architecture_interface class
    sys.path.append(config["architectureSpecPath"])
    import architecture_interface

    # Attempt to dynamically load the specified architecture class
    spec = importlib.util.spec_from_file_location("archif_module", config["architectureName"])

    if spec is None:
        raise AngrError("Failed to load architecture spec!")

    module = importlib.util.module_from_spec(spec)
    if spec.loader is not None:
        sys.modules["archif_module"] = module
        spec.loader.exec_module(module)
    else:
        raise AngrError("Failed to load architecture spec!")

    # The ArchitectureInterface provided by the user
    archif: architecture_interface.ArchitectureInterface = module.get()

    # Instantiate any ExplorationTechniques to ALWAYS use
    techniques: list[angr.ExplorationTechnique] = [
        exploration_techniques.ProgressReportExplorationTechnique(GHIDRA_COMMAND_PREFIX, 0.05),
        exploration_techniques.BreakIntoREPLTechnique(config["breakPath"]),
        angr.exploration_techniques.MemoryWatcher(),
    ]

    # Attempt to register the provided calling convention as default, so that angr will apply it to everything without
    # requiring it to be provided each time
    cc = archif.get_calling_convention()
    arch = archif.get_arch()
    if cc is not None:
        if arch is None:
            raise AngrError("Must specify an architecture in archif when using a custom calling convention!")
        else:
            angr.calling_conventions.register_default_cc(arch.name, cc)

    loader_args = archif.get_loader_args()

    # mypy has issues with manipulating the dictionary structures here
    loader_args["main_opts"]["base_addr"] = config["baseAddr"]  # type: ignore
    loader_args["auto_load_libs"] = config["loadExternalLibraries"]
    loader = cle.Loader(config["binaryPath"], **loader_args)  # type: ignore

    p = angr.Project(loader, engine=archif.get_engine())

    # Setup the initial state according to the entrypoint
    st = create_state(config["entryPoint"], p)
    archif.apply_state_options(st)

    # Setup the conditions under which exploration should terminate
    run_func, target_stash = create_run_function(config, p, techniques)

    # Setup any initial symbolic variables and constraints
    apply_variables(st, config["symbolicVariables"])
    apply_constraints(st, config["constraints"])

    register_hooks(p, config["hooks"])

    # Apply the config's memory and register policy
    match config["memoryAccessPolicy"]:
        case "NONE":
            pass
        case "FILL_ZERO":
            st.options.ZERO_FILL_UNCONSTRAINED_MEMORY = True
        case "FILL_UNCONSTRAINED":
            st.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY = True

    match config["registerAccessPolicy"]:
        case "NONE":
            pass
        case "FILL_ZERO":
            st.options.ZERO_FILL_UNCONSTRAINED_REGISTERS = True
        case "FILL_UNCONSTRAINED":
            st.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS = True

    sm = p.factory.simgr(st)

    # Add any arch-provided techniques
    for tech in archif.get_techniques():
        sm.use_technique(tech)

    # Add in any system techniques
    for technique in techniques:
        sm.use_technique(technique)

    # Add in the MemoryWatcher hook as a failsafe to avoid crashing the computer
    sm.use_technique(angr.exploration_techniques.MemoryWatcher())

    # Add any arch-provided hooks
    for loc, hook in archif.get_hooks().items():
        p.hook_symbol(loc, hook)

    # Precompile the 'on complete' hook to catch syntax errors early
    when_done = None
    if "codeWhenDone" in config and config["codeWhenDone"] != "":
        try:
            when_done = compile(config["codeWhenDone"], "<ghidra>", "exec")
        except Exception as e:
            raise AngrError(e)

    # Go!
    run_func(sm)

    states_found = len(getattr(sm, target_stash))

    print("===== SYMBOLIC EXECUTION COMPLETE =====")
    if states_found > 0:
        print(f"Found {states_found} states.\n")
        for i, win_state in enumerate(getattr(sm, target_stash)):
            print(f"=================== STATE {target_stash}[{i}] ===================")
            print_state(win_state, archif, detailed=config["showDetails"])
            if config["showDetails"] and not is_memory_good():
                print("Force-disabling showDetails due to low system memory!")
                config["showDetails"] = False
    else:
        print(f"Found no states in '{target_stash}'!\nstashes: {str(sm)}\nShowing all states in 'deadended':")
        for i, win_state in enumerate(sm.deadended):
            print(f"=================== STATE deadended[{i}] ===================")
            print_state(win_state, archif, detailed=config["showDetails"])
            if config["showDetails"] and not is_memory_good():
                print("Force-disabling showDetails due to low system memory!")
                config["showDetails"] = False

    for i, err in enumerate(sm.errored):
        print(f"=================== STATE errored[{i}] ===================")
        print_state(err.state, archif, detailed=config["showDetails"])
        print(f"err: {err}")
        if config["showDetails"] and not is_memory_good():
            print("Force-disabling showDetails due to low system memory!")
            config["showDetails"] = False

    constrained_st = None

    # If the explorationgoal is 'unconstrained', attempt to resolve the unconstrained state to the target address:
    if (
        len(sm.unconstrained) == 1
        and config["exploreCondition"]["type"] == "UnconstrainedGoal"
        and "target" in config["exploreCondition"]
    ):
        print("Attempting to resolve unconstrained state to target IP...")
        target = config["exploreCondition"]["target"]
        constrained_st = sm.unconstrained[0]
        constrained_st.add_constraints(constrained_st.regs._ip == target)
        try:
            print("sample stdin: " + str(constrained_st.posix.dumps(0)))
            print(
                "ip: "
                + str(constrained_st._ip)
                + " = "
                + hex(constrained_st.solver.eval_exact(constrained_st._ip, n=1)[0])
            )
        except (angr.SimUnsatError, angr.SimValueError) as e:
            print("Failed to satisfy target address! ", e)

    when_done_locals: dict[str, Any] = locals()
    if when_done is not None:
        when_done_locals["get_var"] = symbolic_field.get_var
        when_done_locals["get_vars"] = symbolic_field.get_vars
        when_done_locals["eval_vars"] = symbolic_field.eval_vars
        try:
            exec(when_done, globals(), when_done_locals)
        except Exception as e:
            sys.stderr.write(f"Exception occured when running completion hook! \n{traceback.format_exc()}")
            global interpreter_banner
            interpreter_banner += f"\nException occured when running completion hook! \n{traceback.format_exc()}"

    if config["repl"]:
        repl.start_repl(GHIDRA_COMMAND_PREFIX, interpreter_banner, sm, constrained_st, when_done_locals)


def is_memory_good() -> bool:
    """Checks if there's still a reasonable amount of system memory left"""
    return psutil.virtual_memory().available > int(psutil.virtual_memory().total * 0.05)


def print_state(st: angr.SimState, archif: Any, detailed: bool = False) -> None:
    """
    Prints a state's basic information to stdin. If detailed is true, also shows **every** symbolic variable in the
    state.

    :param st: The state to print
    :param detailed: True if all symbolic variables be shown, defaults to False
    """
    print("sample stdin: " + str(st.posix.dumps(0)))
    print("stdout: " + str(st.posix.dumps(1)))
    print("ip: " + str(st._ip))
    archif.extra_print_state(st, detailed)
    if detailed:
        print("SAMPLE SOLUTION: ")
        all_vars = dict(st.solver.get_variables())
        user_var_names: list[str] = []
        angr_vars: dict[str, Any] = {}
        # Build a list of unique variable names (so that lists of variables are processed as one, rather than individually)
        for k, v in all_vars.items():
            if len(k) == 2 and k[0] not in user_var_names:  # i.e. an eternal variable that's not already been counted
                user_var_names.append(k[0])
            if len(k) == 3:
                angr_vars[k] = v

        if len(user_var_names) == 0:
            print("  <no user symbolic variables>")

        for var_name in user_var_names:
            try:
                var = symbolic_field.get_vars(st, var_name)
                if var is None:
                    raise AngrError(
                        "Symbolic variable {var_name} doesn't exist despite existing 5 lines ago! This is a bug."
                    )
                if len(var) == 1:
                    # then var is a single variable
                    if isinstance(var[0], str | bytes):
                        # just print concrete types directly, without forcing evaluation
                        print(f"  {var_name} : {var[0]} = {var[0]}")
                    elif isinstance(var[0], int):
                        print(f"  {var_name} : {var[0]} = {hex(var[0])}")
                    else:
                        print(f"  {var_name} : {var[0]} = {hex(st.solver.eval(var[0]))}")
                else:
                    # the var is a list of variables
                    print(f"  {var_name} = {st.solver.eval(claripy.Concat(*var), cast_to=bytes)!r}")
            except Exception as e:
                print(f" {var_name} ERRORED {e}")  # fallback

        if len(angr_vars) != 0:
            print("    ---")

        for k, v in angr_vars.items():
            k_hex = (k[0], hex(k[1]) if isinstance(k[1], int) else k[1], hex(k[2]))  # display numbers as hex in the key
            print(f"  {k_hex}: {v} = {hex(st.solver.eval(v))}")

    print("")  # spacer between states


def create_state(config_entry: dict[str, Any], p: angr.Project) -> angr.SimState:
    match config_entry["type"]:
        case "BlankState":
            st: angr.SimState = p.factory.blank_state(addr=config_entry["addr"])
        case "EntryState":
            st = p.factory.entry_state()
        case "FullInitState":
            st = p.factory.full_init_state()
        case "CallState":
            # To construct a call_state, the arguments to the function need to be constructed into symbolic variables.
            # As part of this process, named symbolic variables need to be saved so they can be recalled later, but
            # saving variables requires a solver with a linked state. To solve this, a dummy state is created for the
            # purpose of this link, and then the solver is copied out of the dummy state and into the real call state as
            # it's constructed.

            solver = angr.state_plugins.SimSolver()
            solver.state = p.factory.blank_state(addr=0x0)
            args = eval_args(config_entry["params"], solver=solver)
            st = p.factory.call_state(
                config_entry["addr"],
                *args,
                stack_base=config_entry["stackBase"],
                prototype=config_entry["signature"],
                plugins={"solver": solver},
            )

        case _:
            raise AngrError("Unknown entry point!")

    return st


def create_run_function(
    config: dict[str, Any], p: angr.Project, techniques: list[angr.ExplorationTechnique]
) -> tuple[Callable[[angr.SimulationManager], None], str]:
    match config["exploreCondition"]["type"]:
        case "TerminationGoal":  # Terminate only when symbolic execution has completely finished.

            def run_function(sm: angr.SimulationManager) -> None:
                sm.explore(avoid=config["avoidAddrs"])

            target_stash = "deadended"

        case "AddressGoal":  # Terminate once any state reaches a certain set of addresses

            def run_function(sm: angr.SimulationManager) -> None:
                sm.explore(find=config["exploreCondition"]["addresses"], avoid=config["avoidAddrs"])

            target_stash = "found"

        case "UnconstrainedGoal":  # Terminate once the instruction pointer becomes symbolic

            techniques.append(UnconstrainedWatcher())

            def run_function(sm: angr.SimulationManager) -> None:
                sm.explore(avoid=config["avoidAddrs"])

            target_stash = "unconstrained"

        case "CustomGoal":  # Terminate according to some custom condition provided as a python function
            try:
                run_lambda_definition = compile(config["exploreCondition"]["code"], "<ghidra>", "exec")
                clean_locals: dict[str, Any] = {}
                exec(run_lambda_definition, globals(), clean_locals)

                def run_function(sm: angr.SimulationManager) -> None:
                    sm.explore(find=clean_locals["filter"], avoid=config["avoidAddrs"])

                target_stash = "found"

            except Exception as ex:
                raise AngrError(f"Failed to compile custom condition:\n {ex}", ex)

        case _:
            raise AngrError("Unknown explore condition!")

    return (run_function, target_stash)


def apply_variables(st: angr.SimState, variables: list[dict[str, Any]]) -> None:
    """Applies some variables to the provided SimState.

    A variable should be a dict with the following keys:

    - loc: a string, such that if nonempty representing either a memory location or register that the symbolic variable
      should be bound to
    - name: the name of the symbolic variable, for further access to it. If name is empty, then the variable will be
      treated as anonymous and will not be accessible in future code or the repl.
    - width: the size of the variable, in bits.
    - value: a python string containing the value to be placed in the variable. See symbolic_field.py for more details.

    :param st: The state to apply variables to
    :param variables: The variables to apply
    """
    for i, v in enumerate(variables):
        target: str = v["loc"]
        name: str = v["name"]
        width: int = v["width"]
        value_code: str = v["value"]

        if name == "":
            name = f"__{i}"

        value = symbolic_field.eval_sym(value_code, width, name, st.solver)

        # Writes to memory or registers won't like a direct array, so convert it to a single bitvector first
        # Note: this differs from the argument list behavior, where a passed list will be allocated some memory
        # somewhere to hold it
        if isinstance(value, list):
            value = claripy.Concat(*value)

        if target == "":
            continue  # if the target is blank, then this is just an unbound symbolic variable

        try:
            if target.startswith("0x"):
                mem_loc = int(target, 16)
            else:
                mem_loc = int(target, 10)

            print(f"Writing {value} to memory {mem_loc}")
            st.memory.store(mem_loc, value)
        except ValueError:
            # then it must be a register name instead
            if hasattr(st.regs, target):
                print(f"Writing {value} to register {target}")
                setattr(st.regs, target, value)
            elif target == "stdin":
                print(f"Setting stdin to {value}")
                stdin_file = angr.SimFileStream("<stdin>", value)
                stdin_file.set_state(st)
                st.posix.stdin = stdin_file

                tty = angr.SimFileDescriptorDuplex(st.posix.stdin, st.posix.stdout)
                st.posix.fd[0] = tty

            else:
                # what is this then?
                sys.stderr.write(
                    f"Warning: Unknown variable target '{target}' for variable {name}, treating as unbound\n"
                )


def apply_constraints(st: angr.SimState, constraints: list[dict[str, Any]]) -> None:
    """Applies some set of constraints to a provided SimState.

    A constraint is a dict with the following keys:

    - code: a python string containing an expression representing the constraint or list of constraints.

    :param st: The state to apply constraints to
    :param constraints: The constraints to apply
    """
    for i, c in enumerate(constraints):
        code: str = c["code"]
        if code == "":
            continue

        constraint = symbolic_field.eval_cond(code, st)

        print(f"Adding constraint {constraint}")

        if type(constraint) == list:
            # then there's a list of constraints, rather than just a single one
            st.add_constraints(*constraint)
        else:
            st.add_constraints(constraint)


def register_hooks(p: angr.Project, hooks: list[dict[str, Any]]) -> None:
    """Registers all hooks for a project.

    A hook is a dict with the following keys:

    - target: the memory location that the hook should trigger on
    - variables: a set of new symbolic variables to apply when the hook is hit
    - constraints: a set of constraints to apply when the hook is hit
    - custom_code: a python string which will be executed when the hook is hit

    Additionally, hooks are either inline or simprocedures. An inline hook has additional key

    - length: increment the IP by this when returning from the hook

    and a simprocedure hook has

    - signature: the signature of the function that's being hooked

    :param p: The project to register hooks to
    :param hooks: The hooks to register
    """
    for hook in hooks:
        if "length" in hook.keys():  # if the hook is inline
            register_inline_hook(p, hook)
        else:
            register_simproc_hook(p, hook)


def register_inline_hook(p: angr.Project, hook: dict[str, Any]) -> None:
    length: int = hook["length"]
    target: int = hook["target"]
    constraints: list[dict[str, Any]] = hook["constraints"]
    variables: list[dict[str, Any]] = hook["variables"]
    custom_code = hook["customCode"]

    # precompile the code for performance and safety purposes
    # (better to check the hook compiles now than after potentially hours of runtime)
    try:
        code = compile(custom_code, filename="<ghidra>", mode="exec")
    except SyntaxError as e:
        raise AngrError("Could not compile provided custom hook handler!", e)

    def created_hook(st: angr.SimState) -> None:
        apply_variables(st, variables)
        apply_constraints(st, constraints)
        exec(
            code,
            globals(),
            symbolic_field.MagicLocals(
                st,
                locals()
                | {
                    "brk": functools.partial(symbolic_field.brk, st=st),
                    "get_var": functools.partial(symbolic_field.get_var, st),
                    "get_vars": functools.partial(symbolic_field.get_vars, st),
                },
            ),
        )

    p.hook(target, created_hook, length=length)


def register_simproc_hook(p: angr.Project, hook: dict[str, Any]) -> None:
    signature: str = hook["signature"]
    target: int = hook["target"]
    constraints: list[dict[str, Any]] = hook["constraints"]
    variables: list[dict[str, Any]] = hook["variables"]
    custom_code: str = hook["customCode"]

    # precompile the code for performance and safety purposes
    # (better to check the hook compiles now than after potentially hours of runtime)
    try:
        code = compile(custom_code, filename="<ghidra>", mode="exec")
    except SyntaxError as e:
        raise AngrError("Could not compile provided custom hook handler!", e)

    class CreatedSimProcedure(angr.SimProcedure):
        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs, prototype=signature)  # type: ignore
            self.arg_names = angr.types.parse_signature(signature).arg_names

        def run(self, *args: Any) -> Any:
            # modify the current state, that will then get copied into the new states if custom code modifies
            # self.successors
            apply_variables(self.state, variables)
            apply_constraints(self.state, constraints)

            augmented_locals = locals()
            augmented_locals["brk"] = symbolic_field.brk
            # translate args into locals based on the signature
            for arg, name in zip(args, self.arg_names):
                augmented_locals["_arg_" + name] = arg

            exec(code, globals(), augmented_locals)

    p.hook(target, CreatedSimProcedure())


def eval_args(args_list: list[Any], solver: angr.state_plugins.SimSolver) -> list[claripy.BV]:
    sym_list = []
    for i, arg in enumerate(args_list):
        sym_list.append(symbolic_field.eval_sym(arg["code"], arg["width"], arg["name"], solver))
    return sym_list


if __name__ == "__main__":
    main()
