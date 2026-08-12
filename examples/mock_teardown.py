#!/usr/bin/env python3
"""Run one full teardown against fakes and print the receipt it produces.

No credentials, no network, no provider. The fakes are the ones the test suite
uses -- `tests/test_lifecycle.py` and `tests/test_provision.py` -- rather than
a friendlier set written for the demo, so what this prints is the same shape a
real run writes.

    python3 examples/mock_teardown.py

The host it destroys is in phase READY with a lease that has expired: the case
where every guard is mandatory rather than vacuous, so the receipt shows the
guards actually running.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from cinderwell import lifecycle, provision, teardown  # noqa: E402
from test_lifecycle import FakeProvider, authority_for, example_config  # noqa: E402
from test_provision import FakeMutator, FakeTailscale  # noqa: E402
from test_teardown import FakeProbes, live_surfaces, state_in  # noqa: E402


class DisappearingProvider(FakeProvider):
    """A provider whose inventory reflects the deletions actually issued.

    Teardown reads the provider twice: once to evaluate the drift guard while
    the host still exists, and once after the delete calls to prove absence. A
    fake that answered "empty" both times would make the second read pass
    without the first one ever having seen the machine -- which is the exact
    thing `_prove_absence` exists to rule out.
    """

    def __init__(self, mutator: FakeMutator) -> None:
        self._mutator = mutator
        super().__init__(surfaces=live_surfaces())

    def inventory(self) -> dict:
        deleted = {call[0] for call in self._mutator.calls}
        self._surfaces = live_surfaces(
            server="delete_server" not in deleted,
            primary_ip="delete_primary_ip" not in deleted)
        return super().inventory()


def main() -> int:
    config = example_config()
    state = state_in("READY", config=config, expires_at="2026-08-11T13:00:00Z")

    with tempfile.TemporaryDirectory() as directory:
        state_path = Path(directory) / "host.json"
        provision.save_state(state_path, state)

        plan = teardown.plan_down(config, state)
        authority = authority_for(plan)
        mutator = FakeMutator()

        receipt = teardown.apply_down(
            config, state, plan,
            state_path=state_path,
            provider=DisappearingProvider(mutator),
            mutator=mutator,
            tailscale=FakeTailscale(),
            # A clean, idle host: the work guard and the session guard both run
            # and both answer, rather than being skipped.
            probes=FakeProbes(dirty=False, sessions=False),
            recorded_at="2026-08-11T13:00:04Z",
            authority=authority)

        print(json.dumps(receipt, indent=2, sort_keys=True))
        print()
        print("state after teardown:",
              json.loads(state_path.read_text())["primary"]["phase"])
    return 0 if receipt["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
