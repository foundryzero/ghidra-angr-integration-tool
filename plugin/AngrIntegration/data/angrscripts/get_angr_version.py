"""A tiny script that returns the currently installed angr version."""

try:
    import angr

    print(angr.__version__)
except ImportError:
    print("NONE")
