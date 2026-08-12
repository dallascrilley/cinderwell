"""Console entrypoint: ``python -m cinderwell <command> …`` / ``cinderwell``."""

from __future__ import annotations

import sys
from typing import Callable

COMMANDS: dict[str, str] = {
    "lifecycle": "lifecycle",
    "provision": "provision",
    "teardown": "teardown",
    "reaper": "reaper",
    "approve": "approve",
    "doctor": "doctor",
}

USAGE = (
    "usage: cinderwell <command> [options]\n"
    "\n"
    "commands:\n"
    "  lifecycle   inventory, price, and plan a host (mutates nothing)\n"
    "  approve     write an approval naming one plan's exact hash\n"
    "  provision   apply an approved plan, or abort a half-created host\n"
    "  teardown    destroy a host and prove it is gone\n"
    "  reaper      enforce the lease on a schedule\n"
    "  doctor      report on configuration and state locations\n"
    "\n"
    "Every command takes --help.\n"
)


def _dispatch(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        sys.stdout.write(USAGE)
        return 0 if argv else 2

    command, rest = argv[0], argv[1:]

    def load(name: str) -> Callable[[list[str] | None], int]:
        return __import__(f"cinderwell.{name}", fromlist=["main"]).main

    module = COMMANDS.get(command)
    if module is None:
        sys.stderr.write(f"cinderwell: unknown command {command!r}\n")
        sys.stderr.write(USAGE)
        return 2

    try:
        return load(module)(rest)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else (0 if code is None else 1)


def main(argv: list[str] | None = None) -> int:
    return _dispatch(list(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    raise SystemExit(main())
