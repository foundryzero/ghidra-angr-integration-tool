# Working with pcode in angr

This is an example of using angr's pcode backend in a Python REPL or notebook. It does not (directly) use Ghidra, the Ghidra Angr Integration Tool plugin or any of the helpers that that tool provides, it is simply an illustration of how one can use Ghidra's processor module definitions to perform symbolic execution of a binary from an architecture which is not supported directly by angr. This document describes some of the concepts and tools used in this approach; there is also a [worked example](worked-example.md) which walks through solving a CTF problem using this technique.

## Requirements

- Some binary file you want to analyze in angr, in an architecture ghidra supports
    - This document mostly assumes it's a binary blob
- Python 3.10 or later

## Installing angr

- Create and activate a new python virtual environment:

```commandline
python -m venv .venv
source .venv/bin/activate
```

- Install angr and it's dependencies - angr 9.2.117 or later is required:

```commandline
(.venv) $ pip install angr setuptools pypcode 
```

`setuptools` is needed for unicorn (angr's fork of qemu) support to work properly, and `pypcode` lifts executables that Ghidra supports into their pcode representation.

- Verify angr is installed succesfully:

```pycon
>>> import angr
# [ideally no warnings output]
>>> angr.__version__
'9.2.117'
>>> angr.Project('/bin/ls', engine=angr.engines.UberEnginePcode).loader.all_objects
# [should print various shared objects]
```

## Background: Symbolic Execution

For a full introduction to angr, see [the official docs](https://docs.angr.io/en/latest/core-concepts/toplevel.html). This section will just cover the basics to understand the rest of the document.

The core idea of angr is that rather than giving the program a single input, it can be simulated on _all_ (or some subset) of inputs, and then angr will compute each possible outcome and a set of constraints on the input that will lead to that outcome. To accomplish this, angr has the concept of a `SimState` (usually just called a state) that stores memory, registers, and other properties representing a single moment of execution. Any read to those properties will return a _symbolic value_, which may well just be a constant value as with 'standard' debugging, but could also be a (possibly very complex) expression based on any number of _symbolic variables_, which have _constraints_ placed on them as part of the simulation process.

<img alt="angr structure" src="img/angr-structure.svg" width=1000>

Internally, angr lifts it's inputs to a low level IR, by default valgrind's VEX (but this document mostly discusses Ghidra's pcode IR. This is executed by a simulation engine, which executes the lifted code basic block by block. When it hits a read from a location with symbolic data, it will create symbolic variables rather than read a concrete value, and if that value is used as part of the condition for some control flow, the execution state will split into multiple possible succession states:

<img alt="Execution flow splitting into multiple states" src="img/execution-flow-1.svg" width=1000>

These symbolic variables will propagate into expressions through the program: If you have symbolic variables 𝖆, 𝖇 in registers `r10`, `r11`, then `add r10, r11` will result in the symbolic variable 𝖆+𝖇 in `r10`! Constraints also propogate from their earlier states, such that by the end of program execution there will probably be a rather large set of constraints on, say, the data written to `stdout`, perhaps using variables ranging over the input from `stdin`.

Once you find a state you're interested in, you can use the solver engine `claripy` to solve the system of constraints, giving a concrete value to each symbolic variable in the state, such that every constraint holds. You may add your own constraints to the system as well - suppose you've found a state where the instruction pointer is overwritten by some complex symbolic expression derived from user input (angr will usually stop simulating at that point because the behavior of the program at that point is essentially arbitrary). You could then add a constraint `rip == 0x12345678`, then solve the whole system to find a concrete input that must lead to that address.

<img alt="constraint solving example" src="img/constraint-solving.svg" width=1000>

## Loading the binary

Just mapping a binary file into flat address space isn't enough - it may depend on certain shared libraries, or have an interesting structure, or require some sort of transformation at load time. Even in cases where you have a full memory image, you still need to specify an entry point and other initialisation data. To resolve this, angr uses another project, `cle` (CLE Loads Everything), to load files for analysis.

### Binary blobs

If all you have is a memory image, it can be loaded with the blob cle backend, specifying an entry point and optionally a set of segments that split up the file. For example, loading a MSP430 microcorruption image, which happens to have it's entry point at `0x4400`:

```python
import angr, cle, archinfo

loader = cle.Loader("memory1.bin",
                    main_opts={
                        "backend": "blob",
                        "entry_point": 0x4400,
                        "base_addr": 0x0,
                        "segments": [(0x0, 0x0, 0x4fff),(0x6000, 0x6000, 0xffff-0x6000)]
                    },
                    arch=archinfo.ArchPcode(language="TI_MSP430:LE:16:default"),
                    rebase_granularity=0x100)
p = angr.Project(loader, engine=angr.engines.UberEnginePcode)
```

This creates a `cle.Loader` and then wraps an angr `Project` around it. The `Project` is then used to create all any other objects you might need for analysis. The precise options to the `Loader` constructor are heavily dependent on the binary -- some important ones are:

- `main_opts`: Arguments to the loader used when loading the object (in non-blob situations you may have other objects
  being loaded, where you would use `lib_opts`, but here this is the only one)
    - `"backend"`: The loader backend - usually either "elf" or "blob" (but backends exist for "pe" and "mach-o")
    - `"entry_point"`: Only relevant if using the "blob" backend. The entry point of the binary. This should be the true entry point, even if you want to only analyse a single function.
    - `"base_addr"`: If the binary is position independent, this sets it's base address. You may wish to set this to `0x100000` to match Ghidra's behavior.
    - `"segments"`: Only relevant if using the "blob" backend. This array of 3-tuples `(file_offset, mem_addr, size)` defines exactly what sections of the binary should be loaded into memory. By default, `cle` will load the entire file, starting at `base_addr`. If you're in a very small address space, such as a 16-bit architecture, you might not want this! angr requires a small area of address space for internal use, so if you have a firmware image covering the full space, find an unused area and exclude it from mapping. Note that you'll also have to reduce the `rebase_granularity`, see below.
- `arch`: A `archinfo.Arch` object representing the architecture of the loaded binary. This is used to determine the word size, default calling convention, register and memory layout, and other architecture specific details. For loading pcode, use `archinfo.ArchPcode(language=...)` with the Language ID given by Ghidra (in the `About Program` modal). This will use the same compiled SLEIGH files that Ghidra uses internally to provide this data.
  
  Unfortuntely, `ArchPcode` makes some rather unfortunate assumptions regarding data type size, which causes problems when simulating only a specific function rather than the whole program. The simplest way to work around this is to create a `ArchPcode` object, and then modify it's `sizeof` field to adjust the size of `int` and other standard types.  Much of the architecture value is not really used for much -- for example, there's a field to define function prologs, but it's only used by the fast cfg analysis module, and if you have an object that can be loaded into ghidra it's likely that you have little need for that.  
- `rebase_granularity`: Probably not needed for machines larger than 16 bits. Each loaded object will be placed at a base address that is an integer multiple of this. The default, `0x100000`, is far too large for a small address space, so setting a lower value gives angr room to place it's scratch space somewhere else.

In the above example, the segment map is used to create an area of empty space `0x500 - 0xfff`, which will be used by angr as a scratch space to store function pointers to custom hooks and other data that needs to have a concrete address. The MSP430 memory model defines that area as part of RAM, so it's possible that the program could attempt to write to it -- in this case the program `memory1.bin` does not, but if it did, unexpected things could occur when using `SimProcedure`s (see below).

Once the binary is loaded, create a `Project` around it, specifying to use the `UberEnginePcode` rather than the default `UberEngine`. This engine is ultimately responsible for lifting and symbolically simulating the binary, and defines a lot of angr's capibilities. The engine is built up using mixins that act as layers of functionality:

```python
class UberEngine(
    SimEngineFailure,       # Final fallback if no engine can handle things
    SimEngineSyscall,       # Handles syscalls
    HooksMixin,             # Handles user & builtin hooks
    SimEngineUnicorn,       # Support for the Unicorn qemu fork for fast concrete simulation
    SuperFastpathMixin,     # Handles the SuperFastpath mode where only the last few instructions of each block are simulated
    TrackActionsMixin,      # Populates the state.history field for analysis purposes 
    SimInspectMixin,        # Used for dropping into a debugger at certain addresses
    HeavyResilienceMixin,   # Recovers from errors such as unhandled syscalls
    SootMixin,              # Engine for java bytecode support
    HeavyVEXMixin,          # Main VEX simulation and lifting engine
    TLSMixin,               # Multithreading support
):
    pass

class UberEnginePcode(
    SimEngineFailure, SimEngineSyscall, HooksMixin, HeavyPcodeMixin
):  # pylint:disable=abstract-method
    pass
```

As you can see above, the provided `UberEnginePcode` supports a subset of functionality of the VEX-based `UberEngine`. There's no reason why much of the functionality of the `UberEngine` couldn't be implemented in pcode, but right now the mixins used are very VEX specific -- if you want to implement similar features yourself, you can define a new engine that inherits from the same base classes as the `UberEnginePcode` plus your custom mixins!

## Symbolic Execution in Practice

You can get some initial `SimState`s using a family of `*_state()` methods, but the most commonly used are `entry_state()` representing the top of the program's `main` function (or raw entry point, if that cannot be determined), and `call_state()` representing a single function call. Once given a state, you can advance it through the next block using `state.step()`, inspect it with `state.regs` / `state.mem`, or even write to memory using `state.mem.write()`.

When you advance a state using `state.step()`, it doesn't just simulate a single instruction -- it simulates until the next jump or other control flow, which defines a _block_. You can view the disassembly of the current block through `state.block().pp()`, or it's pcode representation through

```python
lifter = angr.engines.pcode.lifter.PcodeLifterEngineMixin()  # This is usually mixed into the UberEnginePcode
                                                             # that was specified when creating the project. 
lifter.lift_pcode(state.block()).pp()
```

`state.step()` returns a _list_ of potential next states -- if some control flow is dependent on some symbolic data, there could be multiple possible successors, or the program could terminate leading to no successors. Shuffling around states can get complex fast, so angr provides a `SimulationManager` that can abstract the simultaneous execution for you:

```python
state = p.factory.entry_state()  # Create a state at the binary entry point
sm = p.factory.simulation_manager(state)

# Setup inputs here

sm.explore(find=lambda st: some_interesting_condition(st))  # Run the simulation until a state is found such the lambda 
                                                            # returns true
```

A `SimulationManager` (`sm` in the above code) simulates a group of states at a time, advancing all states to the next `.step()`, and running various `ExplorationTechnique`s (such as the one set up by the `find` lambda above) to control aspects of the process such as when to stop exploring. `ExplorationTechnique`s have a range of uses - for example, you can use the `MemoryWatcher` to automatically stop exploration if host memory usage reaches about 95%, or `LengthLimiter` to cease exploration of paths over a certain length. To use them, run

```python
sm.use_technique(MemoryWatcher())
```  

before starting the `SimulationManager`.

### `SimulationManager` stashes

Each state under consideration by a `SimulationManager` exists in a _stash_, depending on where it is in the execution pipeline:

- `deadended`: The state has stopped, and execution cannot continue, due to the machine halting or program termination.
- `found`: The condition given in a `sm.explore` has succeeded for this state
- `active`: The state is still under evaluation (calling `sm.step` will simulate it)
- `errored`: Some exception occurred when simulating.

These can be accessed on the simulation manager object, as just `sm.deadended` etc, and iterated over or indexed as lists of states. Once you have a state of interest, you can get concrete values for any symbolic data in it by using the solver.eval() function, which will return a single possible value of the symbolic expression passed in:

```python
for state in sm.deadended:  # For each state that's finished execution...
  print(state.constraints)  # print each constraint on symbolic variables in it
  print(state.solver.eval(state.regs.rax))  # and then find a sample possible concrete value of the rax register
```

For a given state, each call to `eval` is guaranteed to be _consistent_, i.e. that separate calls to eval() refer to a single solution - if this was not the case, then for some constraint `⟨ 𝖕 + 𝖖 == 20 ⟩` the solver could eval both 𝖕 and 𝖖 as 20, because some solution exists where 𝖕 is 20, and another solution exists where 𝖖 is 20.

Extracting and constraining I/O is covered in the I/O section below.

## Modelling the Machine

The above techniques work well when using an architecture that angr explicitly supports, but under pcode angr doesn't know when a program has halted or any machine specific quirks such as interrupts. There are two main tools to implement these: Exploration Techniques and `SimProcedure`s.

### Exploration Techniques

More concretely, exploration techniques are hooks that the `SimulationManager` triggers on each state it explores. There are [a few different methods](https://docs.angr.io/en/latest/api.html#angr.exploration_techniques.ExplorationTechnique) that can be hooked on, but for the purpose of adding a halting condition you should use `filter()`:

```python
class MSP430HaltTechnique(angr.exploration_techniques.ExplorationTechnique):
    def filter(self, simgr, state, **kwargs):
        if state.solver.is_true(state.regs.sr.chop(1)[11] == 0x1):  # CPUOFF flag in status register
            return 'deadended'
        else:
            return simgr.filter(state, **kwargs)
```

This method returns the name of the stash that the passed state should be placed into. If the CPUOFF flag is set, it's placed in the `deadended` stash, to mark it as not to be further explored. Otherwise, execution is deferred to the next `ExplorationTechnique` in the stack.

To use the technique, run

```python
sm.use_technique(MSP430HaltTechnique())
```

passing in an _instance_ of the technique.

## `SimProcedure` hooking

Sometimes angr's simulation is too heavyweight for a certain function, or perhaps that function uses machine-specific features such as custom hardware or interrupts, that angr doesn't know about. A `SimProcedure` lets you run python code when execution reaches a certain point, either for analysis purposes or to modify the behavior of the program:

```python
@p.hook(0xabcd, length=0)
def my_hook(state):
    print(state.regs.r11)
    state.regs.r12 = 0x00F3
```

The length parameter specifies how long to skip forward on program completion, allowing you to completely replace a native function with your own, running in python. There's a lot more you can do with `SimProcedure`s, especially if you have symbols, but that's better covered by [angr's documentation on the subject](https://docs.angr.io/en/latest/extending-angr/simprocedures.html#hooks-and-simprocedures).

This can be used to implement hardware features - just hook the address where it should occur, arrange for some best-effort simulation of the hardware to happen, then seamlessly return back to the program. Note that **you need to write your hooks with symbolic execution in mind!** This means that you must be careful with any control flow you use -- boolean comparisons as the condition in an if statement will not work! Instead, come up with a condition that can be tested for satisfiability. A common example of something like this is a single hook that has to do a variety of
different things depending on the state of some code. The following example is an example of that pattern. The function code is read from the lower byte of r8, but could be symbolic, so any branches that are possible to be taken are
simulated:

```python
@p.hook(0xabcd, length=1)
def multi_hook(state):
    successors = []  # This will hold the set of possible symbolic states after running the interrupt

    # Somehow decide which call we're doing
    # NOTE: function_code could be symbolic
    function_code = state.regs.r8[7:0]

    # If it's possible for function_code to ever be 0
    # (solver.is_false() returns true if it's condition is absolutely definitely false in every real state represented
    # by this symbolic state.) 
    if not state.solver.is_false(function_code == 0x0): 
        new_state = state.copy()  # Preserves some important things such as state.globals
        new_state.history.jumpkind = "Ijk_NoHook"  # Tell angr that this state is the result of exiting from a hook here
        new_state.solver.add(function_code == 0x0)  # This call is occuring in this state so it must occur in this state

        # Implement function 0 here
        
        successors.append(new_state)

    if not state.solver.is_false(function_code == 0x1):
        new_state = state.copy()
        new_state.history.jumpkind = "Ijk_NoHook"
        new_state.solver.add(function_code == 0x1)

        # Implement function 1 here
        
        successors.append(new_state)
    
    ...

    return successors

```

A very similar instance pattern is used in `load.py` to implement the microcorruption machine's syscall-like interrupts. This snippet reads a (potentially symbolic) function from a register, and if it's _not always false_ i.e. possible for the function code to be equal to the code for each branch, that code's operation is simulated.

### Calling Conventions

angr has a lovely feature where you can hook onto a function, completely replacing it, and angr will automatically marshall the arguments into arguments to your hook, and your hook's return value to the function's. To set this up through pcode, you need to specify the calling convention to use. For every non-pcode [(and some pcode)](https://github.com/angr/angr/blob/master/angr/engines/pcode/cc.py#L94) architecture angr supports, there's a `SimCC` subclass that defines how arguments are passed, where the return address is stored, etc.

If your architecture isn't one that angr already has a `SimCC` for, you should define your own:

```python
import archinfo
from angr.calling_conventions import SimStackArg, SimRegArg, SimCC

# Basic (not fully accurate) calling convention for the MSP430
# https://www.ti.com/lit/an/slaa534a/slaa534a.pdf Chapter 3
class SimCCMSP430(SimCC):
    ARG_REGS = ["r15", "r14", "r13", "r12"]  # The first 4 arguments are passed in registers
    RETURN_ADDR = SimStackArg(0, 2)  # Return address is pushed on the stack
    RETURN_VAL = SimRegArg("r15", 2)  # Return value is stored in r15
    STACKARG_SP_DIFF = 2  # Any stack args are after the return address
    CALLER_SAVED_REGS = ["r11", "r12", "r13", "r14", "r15"]
    ARCH = archinfo.ArchPcode(language="TI_MSP430:LE:16:default")
```

If your architecture has a strange calling convention that doesn't fit into the format above, overriding methods of `SimCC` provides ways to have control over how arguments are extracted from the state. Once you have a calling convention, you need to register it:

```python
angr.calling_conventions.register_default_cc(archinfo.ArchPcode(language="TI_MSP430:LE:16:default").name, SimCCMSP430)
```

This should be done _before_ the project is created, because angr will determine which calling convention to use by default at that time. Now that it's registered, you can hook procedures using the full SimProcedure form:

```python
class ReadHook(angr.SimProcedure):
  def run(self, fd, buf, count):
    # evil read(2) hooking logic goes here
    return 0

p.hook_symbol("read", ReadHook())  # if you have symbols...
p.hook_symbol(0x123456, ReadHook())  # ...or not (note that the call is still p.hook_symbol)
```

## Input/Output

If you've used angr before, you might be familiar with the [`state.posix` interface](https://docs.angr.io/en/latest/api.html#angr.state_plugins.posix.SimSystemPosix) for providing various functions related to files and I/O. This is always present, even if the system you're working with is very much not posix, and you can use it as a nice way to handle input or output from any source. For example, if your program has a debug serial interface, you could hook reads and writes to that to instead read from the `state.posix` I/O streams.

To do this inside a hook, use `state.posix.get_fd(0)` to get a `stdin` file, or `get_fd(1)` for `stdout`, then just call `.read_data(size)` or `.write_data(bitvector)` as needed.

## Simulating a single function

Sometimes you might want to just symbolically simulate a single function in isolation, without going through `main` to get to a state where it's naturally called. Assuming you have a working calling convention, angr makes this possible through it's `call_state()` constructor, which (attempts to) initialise a stack frame for a given function, with arguments you provide, ready to call it. For example, suppose we have some implementation of `putchar` at `0x455a`:

```python
ch = ord('a')
st = p.factory.call_state(0x455a, ch, stack_base=0x2000, prototype="void putchar(char)")

sm = p.factory.simgr(st)
sm.run()

print(sm.deadended[0].posix.dumps(1))  # should deadend once the called function exits
```

- call_state's positional arguments after the first are turned into raw data types based on the function prototype and passed as the function's arguments. They can of course be symbolic expressions too.
- It is very important that you set the stack_base - by default it will be set arbitrarily, **which may not be aligned correctly**, which can lead to very strange results.
- The function prototype is just standard C syntax.
- Between constructing the state and simulating it, you can set up any particular other state that the function needs to run (for example, data pointed to by arguments of the function).
- `ArchPcode` assumes some dangerous things about sizes of common C types such as `int`s. If the defaults are causing issues, create a single `ArchPcode` object, modify it's `.sizeof` attribute from the default `{"short": 16, "int": 32, "long": 32, "long long": 64}`, and pass that where an arch is required.
- If you want to be able to pass arguments larger than the size of a single register in, say, several registers, you'll need to override `next_arg` in the calling convention to define how to do that. [If the large args are already being passed on the stack, the default `SimCC` behavior should suffice]
