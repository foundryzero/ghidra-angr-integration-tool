import importlib
import importlib.util
import pathlib
import sys

# MUST match the equivalent constant on the java side
GHIDRA_COMMAND_PREFIX = "!<*"


def main(path: str, lang: str) -> None:
    """Using the compatibility ratings provided by each archif module, find the best archif to use for a given language.

    :param path: The path to the archif directory
    :param lang: The language to find the best archif for
    """
    archifs = pathlib.Path(path).glob("*.py")

    sys.path.append(path)

    scores: dict[str, int] = {}

    for archif_path in archifs:
        # try to import it, and call it's compat function
        spec = importlib.util.spec_from_file_location("archif_module", archif_path)
        if spec is None:
            print(f"Failed to create spec for {archif_path}")
            continue
        try:
            module = importlib.util.module_from_spec(spec)
            if spec.loader is not None:
                spec.loader.exec_module(module)

            scores[str(archif_path)] = module.get().is_compatible(lang)
        except Exception as e:  # intentional catch-all - we're loading random modules, anything could happen
            print(f"Failed to load archif module {spec}, {e}")

    print(f"{GHIDRA_COMMAND_PREFIX} result {max(scores, key=scores.get)}")  # type: ignore


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: get_best_archif archpath lang")
        exit(1)

    main(sys.argv[1], sys.argv[2])
