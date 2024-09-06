import architecture_interface

import angr
from angr.sim_state import SimState


class UnicornIF(architecture_interface.ArchitectureInterface):
    def apply_state_options(self, st: SimState) -> None:
        st.options.update(angr.options.unicorn)
        return super().apply_state_options(st)

    def is_compatible(self, lang: str) -> int:
        return 5 


def get() -> architecture_interface.ArchitectureInterface:
    return UnicornIF()
