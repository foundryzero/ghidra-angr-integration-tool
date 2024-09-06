import archinfo

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
