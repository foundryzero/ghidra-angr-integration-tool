import functools
from collections.abc import Callable
from typing import Any, Protocol, cast, overload, override

import claripy
import repl
from claripy.ast import BV, Bool

import angr

# Provides an execution environment for symbolic fields to evaluate in
#
# Note: this makes no attempt to be secure (because securing this is impractical) - only open saved states from sources
# you trust!


# These functions have the first set of their arguments filled in with functools.partial, with any further arguments
# being provided by the caller, ideally being optional. This is done to reduce the verbosity of common actions, whilst
# still providing the variable tracking needed to refer back to these variables later.


def sym(
    # provided by the environment
    default_name: "NameTracker",
    default_width: int,
    solver: angr.state_plugins.SimSolver,
    i: int = 0,
    # provided by the caller
    name: str | None = None,
    width: int | None = None,
) -> BV:
    """Creates a new symbolic variable.

    :param name: The name of the symbolic variable, defaults to the name of the field
    :param width: The width of the symbolic variable, defaults to the width of the field
    :return: The constructed symbolic variable
    """
    if width is None:
        width = default_width
    if name is None:
        name = default_name.get()
    return cast(BV, solver.BVS(name, width, key=(name, i), eternal=True))


def alloc(data: Any) -> angr.PointerWrapper:
    """Allocates some memory, copies the passed data to it, and returns a pointer to that data.

    NOTE: due to an angr limitation, will only work in argument lists, NOT general purpose symbolic variables.

    :param data: The data to wrap in a pointer
    :return: The wrapped pointer
    """
    return angr.PointerWrapper(data, buffer=True)


def sym_str(
    # provided by the environment
    default_name: "NameTracker",
    solver: angr.state_plugins.SimSolver,
    # provided by the caller
    length: int,
    name: str | None = None,
    null: bool = True,
) -> BV:
    """Create a string composed of _length_ symbolic variables, plus an optional null terminator.

    :param length: The length of the string to create
    :param name: The base name to use for the newly created variable, defaults to the name of the field.
    :param null: Automatically add a null terminator to the created string, defaults to True
    :return: A single long symbolic variable representing the string.
    """
    if name is None:
        name = default_name.get()
    sym_chars = [solver.BVS(name, 8, key=(name, i), eternal=True) for i in range(length)]

    if null:
        sym_chars.append(solver.BVV(0, 8))
    sym_ast = claripy.Concat(*sym_chars)
    return sym_ast


def get_var(st: angr.SimState, name: str, i: int = 0) -> BV | None:
    """Extracts a symbolic variable from the provided state.

    :param st: The state to look for variables in
    :param name: The name of the variable to look for
    :param i: If the search target is a symbolic string, return the ith character of the string, defaults to 0
    :return: The symbolic variable if found, otherwise None
    """
    vars = dict(st.solver.get_variables(name))
    # vars is now a dict mapping tuples (name, i) to the actual symbolic variables.
    # Even if the variable isn't a symstr, i is still present, just set to 0

    # require an exact match, since here there are lots of variables with awkward suffixes in their names
    search = (name, i)
    return cast(BV | None, vars.get(search, None))


def get_vars(st: angr.SimState, name: str) -> list[BV]:
    """Extracts a symbolic string from the provided state.

    If the name refers to a variable that isn't a symstr, then that variable will be wrapped in a list and returned.

    :param st: The state to look for variables in
    :param name: The name of the variable to look for
    :return: A list of symbolic variables representing the found string, or the empty list if nothing was found.
    """
    vars = dict(st.solver.get_variables(name))
    found_vars = []
    i = 0
    while True:
        search = (name, i)
        found_var = vars.get(search, None)
        if found_var is None:
            break
        i += 1
        found_vars.append(found_var)

    return found_vars


def eval_vars(st: angr.SimState, name: str) -> bytes:
    return st.solver.eval(claripy.Concat(*get_vars(st, name)), cast_to=bytes)


def brk(**kwargs: Any) -> None:
    """
    Causes the simulation to immediately pause and open a REPL
    """
    repl.start_repl(
        locals=locals() | kwargs,
        banner="BREAK\nuse exit() to continue execution!\n",
    )


class MagicLocals(dict[str, Any]):
    """
    Provides a mapping such that any locals not defined shall be rewritten to possibly point to a symbolic variable
    that's been previously defined.
    """

    def __init__(self, st: angr.SimState, src: dict[str, Any]):
        super().__init__(src)
        self.state = st

    def __missing__(self, key: str) -> list[BV] | BV:  # called when a 'normal' lookup in the dict fails
        var = get_vars(self.state, key)
        if var == []:
            # IMPORTANT: the fact that this works may well by a cpython impl detail. I can't find anything in the python
            # specification about how exactly name resolution is supposed to work, but cpython will treat __missing__
            # raising a KeyError to mean 'it's not here, check globals instead'.

            # There's a PR https://github.com/python/cpython/pull/121389 currently triaged for 3.14 that will let
            # globals be a mapping, which would resolve this issue, since it doesn't really matter if globals raises a
            # keyerror.
            raise KeyError
        if len(var) == 1:
            return var[0]  # unwrap the array for convenience
        else:
            return var


class NameTracker:
    """
    Provides default names for unnamed symbolic variables, and tracks an incrementing disambiguator for use when
    multiple symbolic variables are being used in the same expression (and therefore would have the same name otherwise,
    which would result in them being bound together (bad))

    Example: given name="hello", successive calls to get() will return:

    "hello" "hello_1" "hello_2" "hello_3" ...
    """

    def __init__(self, name: str, starting_val: int = 0):
        self.name = name
        self._disambiguator = starting_val

    def get(self) -> str:
        if self._disambiguator == 0:
            self._disambiguator += 1
            return self.name
        else:
            self._disambiguator += 1
            return f"{self.name}_{self._disambiguator - 1}"  # the disambiguator before incrementing

    def __str__(self) -> str:
        return self.get()

    def __repr__(self) -> str:
        return self.get()


def eval_sym(code: str, width: int, name_str: str, solver: angr.state_plugins.SimSolver) -> Any:
    """Evaluates a python string to create an object that can be written to simulated memory or used as a parameter to
    a function call.

    The created object could be a claripy AST object, a raw python value, a list, or essentially anything that angr
    knows how to write to memory. The python string will be evaluated in a special environment with some useful
    functions defined in this file to ease in writing these strings.

    :param code: The python expression to evaluate
    :param width: The width of the field the object will be placed in
    :param name_str: The name of the field, for use if only a single variable will be placed in it
    :param solver: The SimSolver to write named variables to
    :return: The created object
    """
    # wrap the name in a tracker that provides a way for subcomponents of an expression to be disambiguated
    name = NameTracker(name_str, starting_val=1)

    locals = MagicLocals(solver.state, {})

    if code == "":
        code = "sym()"  # any empty code refers to a simple symbolic variable

    result = eval(
        code,
        {
            "sym": functools.partial(sym, name, width, solver),
            "alloc": alloc,
            "sym_str": functools.partial(sym_str, name, solver),
            "get_var": functools.partial(get_var, solver.state),
            "get_vars": functools.partial(get_vars, solver.state),
            "angr": angr,
            "claripy": claripy,
        },
        locals,
    )

    if name_str is not None and name_str != "" and type(result) != list:
        solver.register_variable(result, (name_str, 0))

    return result


def eval_cond(code: str, state: angr.SimState) -> bool | Bool | list[Bool]:
    """Evaluates a python string to create a symbolic Boolean value (or list of such Booleans)

    The python string will be evaluated in a special environment with some useful functions defined in this file, and a
    special locals mapping that effectively adds all the symbolic variables in the current state to local scope.

    :param code: The python expression to evaluate
    :param state: The current state, to read symbolic variables from
    :raises TypeError: if the code does not return a raw or symbolic Boolean, or list of either
    :return: The created condition
    """
    locals = MagicLocals(state, {})
    if code == "":
        return True

    # make the utility functions global rather than local because a list comprehension creates it's own scope which
    # hides the locals?

    # see https://github.com/python/cpython/issues/47942
    condition = eval(
        code,
        {
            "get_var": get_var,
            "get_vars": get_vars,
            "st": state,
            "angr": angr,
            "claripy": claripy,
            "And": claripy.And,
            "Or": claripy.Or,
            "Not": claripy.Not,
            "If": claripy.If,
            "is_printable": is_printable,
            "is_numeric": is_numeric,
            "is_alphanumeric": is_alphanumeric,
            "is_alphabetic": is_alphabetic,
            "is_uppercase": is_uppercase,
            "is_lowercase": is_lowercase,
        },
        locals,
    )

    if not (isinstance(condition, Bool) or isinstance(condition, bool) or isinstance(condition, list)):
        raise TypeError(
            f"Provided condition {code} did not return a boolean or list of booleans! Instead: {type(condition)}"
        )

    return condition


# Allow type checking the return value of create_condition_preset
class _ConditionPreset(Protocol):
    @overload
    def __call__(self, variable: BV, allow_nulls: bool = True) -> bool | Bool: ...

    @overload
    def __call__(self, variable: list[BV], allow_nulls: bool = True) -> list[bool | Bool]: ...

    def __call__(
        self,
        variable: BV | list[BV],
        allow_nulls: bool = True,
    ) -> bool | Bool | list[bool | Bool]: ...


def create_condition_preset(condition: Callable[[BV], Bool]) -> _ConditionPreset:
    """Constructs a condition preset function from a callable representing the condition on a single byte.

    :param condition: The condition to be checked on each byte
    :return: A condition preset function with all the usual features
    """

    @overload
    def f(variable: BV, allow_nulls: bool = True) -> bool | Bool: ...

    @overload
    def f(variable: list[BV], allow_nulls: bool = True) -> list[bool | Bool]: ...

    def f(variable: BV | list[BV], allow_nulls: bool = True) -> bool | Bool | list[bool | Bool]:
        """Construct a set of constraints around a given variable or list of variables.

        This function will have a condition closured into it, representing the condition to be constructed

        :param variable: The variable or list of variables to check
        :param allow_nulls: True if null characters should additionally be allowed, defaults to True
        :return: A condition or list of conditions that restricts the variables to those allowed by the constraint
        """

        if isinstance(variable, list):
            return [f(v, allow_nulls=allow_nulls) for v in variable]

        if allow_nulls:
            return claripy.Or(condition(variable), variable == 0x0)  # type: ignore
        else:
            return condition(variable)

    return f


is_printable = create_condition_preset(lambda x: claripy.And(x >= 0x20, x <= 0x7E))
is_numeric = create_condition_preset(lambda x: claripy.And(x >= 0x30, x <= 0x39))
is_alphanumeric = create_condition_preset(
    lambda x: claripy.Or(
        claripy.And(x >= 0x30, x <= 0x39),  # 0-9
        claripy.And(x >= 0x41, x <= 0x5A),  # A-Z
        claripy.And(x >= 0x61, x <= 0x7A),  # a-z
    )
)
is_alphabetic = create_condition_preset(
    lambda x: claripy.Or(
        claripy.And(x >= 0x41, x <= 0x5A),  # A-Z
        claripy.And(x >= 0x61, x <= 0x7A),  # a-z
    )
)
is_uppercase = create_condition_preset(lambda x: claripy.And(x >= 0x41, x <= 0x5A))
is_lowercase = create_condition_preset(lambda x: claripy.And(x >= 0x61, x <= 0x7A))
