# type: ignore 

# this file is intended to be instructive rather than production-ready code, so adding things like cast()s to make the
# type checker happy would be counterproductive 

import archinfo
import claripy
import cle

import angr
import msp430cc

# Tell angr about our custom calling convention
angr.calling_conventions.register_default_cc(archinfo.ArchPcode(language="TI_MSP430:LE:16:default").name, msp430cc.SimCCMSP430)

loader = cle.Loader("memory3.bin",
                    main_opts={
                        "backend": "blob",
                        "entry_point": 0x4400,
                        "base_addr": 0x0,
                        "segments": [(0x0, 0x0, 0x4fff),(0x6000, 0x6000, 0xffff-0x6000)]
                    },
                    arch=msp430cc.MSP430Arch,  # imported to change the sizeof field.
                    rebase_granularity=0x100)

p = angr.Project(loader, engine=angr.engines.UberEnginePcode)


def print_state(st: angr.SimState) -> None:
    """
    Print various data about a state, including all registers, stdout, constraints, and a sample stdin giving that outcome.
    """
    if st.globals["lock_unlocked"]:
        print("=============== SOLUTION ==============")
    else:
        print("================ STATE ================")
    print(f"stdout:      {st.posix.dumps(1)}")  # stdout = fd 1
    print(f"constraints: {st.solver.constraints}")
    print(f"stdin:       {"".join([chr(st.solver.eval(x)) for x in stdin_chars])}")
    print(f"stdin (hex): {"".join(["{:02x}".format(st.solver.eval(x)) for x in stdin_chars])}")
    print(f"pc: {st.regs.pc}\tsp: {st.regs.sp}\tsr: {st.regs.sr}")
    print(f"r4: {st.regs.r4}\tr5: {st.regs.r5}\tr6: {st.regs.r6}")
    print(f"r7: {st.regs.r7}\tr8: {st.regs.r8}\tr9: {st.regs.r9}")
    print(f"r10: {st.regs.r10}\tr11: {st.regs.r11}\tr12: {st.regs.r12}")
    print(f"r13: {st.regs.r13}\tr14: {st.regs.r14}\tr15: {st.regs.r15}")


# the microcorruption machine has an interrupt call gate at 0x0010
# the instruction at 0x0010 is just a return so we don't need to do anything to handle it on our end, just implement
# the interrupt
# see https://microcorruption.com/public/manual.pdf section 4.3 for interrupt definitions
# params are passed on the stack, with the interrupt code in the high byte of sr (ignoring the top bit?)
@p.hook(0x0010, length=0) 
def int_hook(state: angr.SimState) -> None:
    successors = []  # This will hold the set of possible states after running the interrupt

    # Get the interrupt code, bit-indexing the sr register
    interrupt_code = state.regs.sr[14:8].zero_extend(1)

    if not state.solver.is_false(interrupt_code == 0x0):  # putchar
        new_state = state.copy()
        new_state.history.jumpkind = "Ijk_NoHook"  # Tell angr that this state is the result of exiting from a hook here
        new_state.scratch.guard = interrupt_code == 0x0

        param1 = new_state.memory.load(state.regs.sp+0x8, size=1)  # The char to write
        stdout = new_state.posix.get_fd(1)  # This isn't 'real' posix but it's the standard way of buffering i/o
        stdout.write_data(param1)

        successors.append(new_state)

    if not state.solver.is_false(interrupt_code == 0x1):  # getchar
        new_state = state.copy()
        new_state.history.jumpkind = "Ijk_NoHook"
        new_state.scratch.guard = interrupt_code == 0x1

        # taken from the libc shim for fgetc
        stdin = new_state.posix.get_fd(0)
        (data, real_length) = stdin.read_data(1)
        new_state.regs.r12 = new_state.solver.If(real_length == 0, -1, data.zero_extend(new_state.arch.sizeof["int"] - 8))

        successors.append(new_state)

    if not state.solver.is_false(interrupt_code == 0x2):  # gets
        new_state = state.copy()
        new_state.history.jumpkind = "Ijk_NoHook"
        new_state.scratch.guard = interrupt_code == 0x2
        stdin = new_state.posix.get_fd(0)

        param1 = new_state.memory.load(state.regs.sp+0x8, size=2)  # The address to write the data to
        param2 = new_state.memory.load(state.regs.sp+0xA, size=1)  # Max size read

        (data, real_length) = stdin.read_data(state.solver.eval(param2))
        new_state.memory.store(param1.reversed, data)  # reverse the endianness for some reason

        successors.append(new_state)

    if not state.solver.is_false(interrupt_code == 0x7D):  # HSM-1 trigger
        new_state = state.copy()
        new_state.history.jumpkind = "Ijk_NoHook"
        new_state.scratch.guard = interrupt_code == 0x7D

        param1 = new_state.memory.load(state.regs.sp+0x8, size=2)
        param2 = new_state.memory.load(state.regs.sp+0xA, size=2)

        # Normally this would check the string at param1 against the password in the HSM, and set the flag at param2 if
        # it matches. However, angr can't know the password, so can just model it as always rejecting, i.e. a nop
        # This is fine because the exploit here shouldn't require knowledge of (or a specific) password

        successors.append(new_state)

    if not state.solver.is_false(interrupt_code == 0x7F):  # unlock door
        new_state = state.copy()
        new_state.history.jumpkind = "Ijk_NoHook"
        new_state.scratch.guard = interrupt_code == 0x7F

        # state.globals is a dict that gets passed down from a state to it's successors, so can be used to store values
        # relevant to a specific path through the program.
        new_state.globals["lock_unlocked"] = True
        successors.append(new_state)

    if len(successors) == 0:  # If none of the interrupt handlers fired
        # oh no! fallback to modelling the interrupt as a nop
        new_state = state.copy()
        new_state.history.jumpkind = "Ijk_NoHook"
        successors.append(new_state)
        print("Error: unhandled interrupt ", interrupt_code)

    return successors

class TestHook(angr.SimProcedure):
    def run(self, a0, a1, a2, a3):
        print(f"HIT HOOK {a0}, {a1}, {a2}, {a3}")
        print(f"MEM = {"".join([chr(self.state.solver.eval(x)) for x in self.state.mem[a0].string.resolved.chop(8)])}")
        return 0

#p.hook_symbol(0x45de, TestHook())

#@p.hook(0x458e, length=0)
#def debughook(state):
#    print_state(st)
#    print(state.memory.load(state.regs.sp, size=32))

# The MSP430 uses a bit set in the status register to turn off the CPU
# angr doesn't natively understand this, so we provide a custom ExplorationTechinque that redirects any state
# with that register set to the deadended state.
class MSP430HaltTechnique(angr.exploration_techniques.ExplorationTechnique):
    def filter(self, simgr, state, **kwargs):
        if state.solver.is_true(state.regs.sr.chop(1)[11] == 0x1):  # CPUOFF flag in status register
            # print("hit cpuoff, halting path")
            return 'deadended'
        else:
            return simgr.filter(state, **kwargs)

# Setup a symbolic input string to be fed to the gets interrupt
# A single 8-bit symbolic variable for each char of the input.
stdin_len = 32
stdin_chars = [claripy.BVS(f"stdin_{i}", 8) for i in range(stdin_len)]
stdin_ast = claripy.Concat(*stdin_chars)

# the stdin argument here is misleading - this isn't any kind of 'normal' posix compliant stdin
# however, in the hook above, we redirect the i/o ops to angr's posix interface for ease of use
#st = p.factory.entry_state(stdin=stdin_ast)
st = p.factory.call_state(addr=0x4520, stack_base=0x0500)

# Normally reads to uninitialized memory are symbolically modelled
st.options.add(angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY)
st.options.add(angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

# The lock starts locked
st.globals["lock_unlocked"] = False

sm = p.factory.simulation_manager(st)
sm.use_technique(MSP430HaltTechnique())
sm.explore(find=lambda x: x.globals["lock_unlocked"])

# If any states errored, where and why did they error?
for d in sm.errored:
    print(sm.errored)
    print(sm.errored[0].state.regs.pc)
    for t,j in zip(sm.errored[0].state.history.jump_sources, sm.errored[0].state.history.jump_targets):
        print(hex(t) + " -> " + hex(j))
    print(str(sm.errored[0].state.history.jump_sources))

# If any states somehow jumped to an unconstrained address, how did that happen?
if len(sm.unconstrained) > 0:
    print(sm.unconstrained)
    d = sm.unconstrained[0]
    print_state(d)
    d.add_constraints(d.regs.pc == 0x4446)  # Add a new constraint that the pc is somewhere nice
    #d.add_constraints(d.mem[d.regs.pc] == 0x073c)
    print_state(d)  # Should hopefully print an input that leads to this state

# If the lock is ever unlocked, how?
for d in sm.found:
    print_state(d)

# Finally, print all the different possible paths execution followed, if none of them lead to the unlocking of the lock
for d in sm.deadended:
    print_state(d)


#              MSP430 MEMORY MAP
# 
# 0xFFFF ┌───────────────────────────┐
#        │                           │
#        │                           │
#        │   interrupt vectors       │
#        │         (mostly unused)   │
#        │                           │
#        ├───────────────────────────┤
#        │                           │
#        │                           │ ]
#        │                           │ ] empty area mapped to angr's scratch space
#        │                           │ ]
#        │                           │
#        │                           │
#        │            ▲              │
#        │            │              │
#        │                           │
#        │        flash rom          │
#        │                           │
# 0x4400 ├───────────────────────────┤ <-- entry point
#        │                           │
#        │          stack            │
#        │                           │
#        │            │              │
#        │            ▼              │
#        │                           │
#        │                           │
#        │           RAM             │
#        ├───────────────────────────┤
#        │                           │
#        │    weird stuff            │
#        │       (interrupt trap)    │
#        │                           │
# 0x0000 └───────────────────────────┘


class SquareRootProcedure(angr.SimProcedure):
    def run(self, x, y):
        return x**y
