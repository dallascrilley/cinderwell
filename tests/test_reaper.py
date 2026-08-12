#!/usr/bin/env python3
"""Tests for the lease and the reaper (unit U6).

Two properties, and the second is the one worth being careful about.

**A host destroys itself on schedule.** An expiry travels inside the hash-bound
plan, is copied verbatim into state, and something outside the agent enforces
it. Nothing here may reap a host whose lease has not passed, and nothing may
reap one whose lease nobody recorded.

**Automatic teardown never destroys work that exists nowhere else.** The reaper
gets no private path: it goes through `teardown.apply_down` and its ordinary
guards. So the tests below assert on the *call* as well as the outcome -- that
the ordinary function was the one used, that the reaper never passes an
attestation, and that a preservation failure leaves the host running rather than
tidying up after itself.

The hazard was never automation. It is automation that skips a check to avoid
getting stuck, and a test that only checked the happy path would not notice the
difference.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import io
import json
import plistlib
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPOSITORY_ROOT / "cinderwell" / "resources"
EXAMPLE_CONFIG = REPOSITORY_ROOT / "examples" / "config.example.json"
sys.path.insert(0, str(REPOSITORY_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cinderwell import lifecycle  # noqa: E402
from cinderwell import provision  # noqa: E402
from cinderwell import reaper  # noqa: E402
from cinderwell import teardown  # noqa: E402
from test_lifecycle import (FakeProvider, TemporaryTree,  # noqa: E402
                            example_config)
from test_provision import FakeMutator, FakeTailscale  # noqa: E402
from test_teardown import (FakeProbes, SERVER_ID, live_surfaces,  # noqa: E402
                           retained_entry, state_in)

BEFORE = "2026-08-11T09:00:00Z"
EXPIRY = "2026-08-11T13:00:00Z"
AFTER = "2026-08-11T13:00:01Z"

def _primary_checkout() -> Path:
    """The primary checkout, as distinct from a linked worktree.

    Derived from git rather than assumed, so the plist tests mean something
    wherever they run -- and falling back to the repository root when git is
    absent or this is not a checkout at all, so the suite stays runnable from
    an extracted archive.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=REPOSITORY_ROOT, capture_output=True, text=True, check=False)
    except (OSError, subprocess.SubprocessError):
        return REPOSITORY_ROOT
    if result.returncode != 0 or not result.stdout.strip():
        return REPOSITORY_ROOT
    return Path(result.stdout.strip()).parent


REPOSITORY_ROOT_PRIMARY = _primary_checkout()


def source_without_prose(name: str) -> str:
    """A module's code with comments and docstrings removed.

    Structural tests here assert that a string is absent from a code path. Every
    one of these strings also appears in the prose explaining why the code path
    does not exist -- which is exactly the kind of comment this project writes,
    and would make the assertion unwritable if prose counted.
    """
    tree = ast.parse((REPOSITORY_ROOT / "cinderwell" / name).read_text())
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (isinstance(body, list) and body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            # A body that was only a docstring must not become an empty
            # block: `ast.unparse` would emit a class header with nothing
            # under it, and re-parsing that raises IndentationError.
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def preserve_runner(stdout: str = "", returncode: int = 0, stderr: str = "",
                    raises: Exception | None = None, calls: list | None = None):
    """Drive the real Preserver through its runner seam, not around it."""
    def runner(argv, *, stdin, timeout):
        if calls is not None:
            calls.append((argv, stdin))
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
    return runner


class ReapFixture:
    """A READY host with a recorded expiry, and nothing real behind it.

    READY is the phase after rehydrate — the only phase that can hold a
    factory workspace. TRUSTED never rehydrated and cannot carry work.
    """

    def __init__(self, *, phase: str = "READY", expires_at: str | None = EXPIRY,
                 config: dict | None = None):
        self.tree = TemporaryTree(config=config)
        self.state_path = self.tree.root / "state.json"
        self.state = state_in(phase, config=self.tree.config,
                              expires_at=expires_at)
        provision.save_state(self.state_path, self.state)

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        # The fallback record lives outside the temporary tree, under the real
        # home directory, so it outlives this fixture unless something removes
        # it. Leaving it there is not merely untidy: the runbook tells an
        # operator to read exactly that directory to find stranded hosts, and a
        # test's leftovers would be indistinguishable from a real one.
        reaper.fallback_escalation_path(self.state_path).unlink(missing_ok=True)
        self.tree.__exit__()

    def still_there(self):
        """A provider that still reports the server.

        The default fixture provider reports it absent, because the successful
        path has to prove absence. Any test whose host is NOT destroyed must
        say so: the escalation reads the provider back rather than assuming,
        so a fixture claiming the server is gone would produce -- correctly --
        a message about a destroyed host.
        """
        return FakeProvider(surfaces=live_surfaces())

    def reap(self, *, now: str = AFTER, probes=None, preserver=None,
             mutator=None, provider=None, tailscale=None, approval_dir=None):
        return reaper.reap(
            self.tree.config, self.state, now=now, recorded_at=now,
            state_path=self.state_path, approval_dir=approval_dir,
            provider=provider or FakeProvider(surfaces=live_surfaces(
                server=False, primary_ip=False)),
            mutator=mutator or FakeMutator(),
            tailscale=tailscale or FakeTailscale(),
            probes=probes or FakeProbes(),
            preserver=preserver or reaper.Preserver(
                preserve_runner("PRESERVE-OK abc1234\n")))

    def saved(self) -> dict:
        return json.loads(self.state_path.read_text())


# ── The lease arithmetic ──────────────────────────────────────────────────────

class DurationTest(unittest.TestCase):

    def test_units_are_read_as_written(self) -> None:
        for text, seconds in (("45s", 45), ("30m", 1800), ("4h", 14400),
                              ("2d", 172800)):
            with self.subTest(text):
                self.assertEqual(seconds, lifecycle.parse_duration(text))

    def test_a_bare_number_is_refused(self) -> None:
        """`--lease 4` must not silently mean four seconds."""
        for text in ("4", "", "4 hours", "-2h", "4H", "1w", "abc"):
            with self.subTest(text):
                with self.assertRaises(lifecycle.LeaseError):
                    lifecycle.parse_duration(text)

    def test_a_timestamp_without_a_timezone_names_no_instant(self) -> None:
        with self.assertRaises(lifecycle.LeaseError):
            lifecycle.parse_timestamp("2026-08-11T09:00:00")

    def test_an_unreadable_timestamp_is_refused(self) -> None:
        with self.assertRaises(lifecycle.LeaseError):
            lifecycle.parse_timestamp("last tuesday")

    def test_an_offset_and_a_zulu_time_are_the_same_instant(self) -> None:
        """Otherwise an expiry means different moments on two machines."""
        self.assertEqual(lifecycle.parse_timestamp("2026-08-11T13:00:00Z"),
                         lifecycle.parse_timestamp("2026-08-11T15:00:00+02:00"))


class LeaseTest(unittest.TestCase):

    def test_the_expiry_is_the_start_plus_the_lease(self) -> None:
        lease = lifecycle.lease_for(example_config(), BEFORE, "4h")
        self.assertEqual({"seconds": 14400, "expires_at": EXPIRY}, lease)

    def test_the_default_is_used_when_no_lease_is_named(self) -> None:
        config = example_config()
        lease = lifecycle.lease_for(config, BEFORE, None)
        self.assertEqual(config["lease"]["default_seconds"], lease["seconds"])

    def test_a_lease_above_the_ceiling_is_refused(self) -> None:
        config = {**example_config(),
                  "lease": {**example_config()["lease"], "max_seconds": 3600}}
        with self.assertRaises(lifecycle.LeaseError) as raised:
            lifecycle.lease_for(config, BEFORE, "4h")
        self.assertIn("max_seconds", str(raised.exception))

    def test_a_lease_at_the_ceiling_is_allowed(self) -> None:
        """The boundary in the direction that matters: a ceiling that refused
        its own value would make the configured maximum unusable."""
        config = {**example_config(),
                  "lease": {**example_config()["lease"], "max_seconds": 14400}}
        self.assertEqual(14400,
                         lifecycle.lease_for(config, BEFORE, "4h")["seconds"])

    def test_an_expiry_that_has_not_passed_has_not_expired(self) -> None:
        self.assertFalse(lifecycle.has_expired(EXPIRY, BEFORE))
        self.assertTrue(lifecycle.has_expired(EXPIRY, AFTER))

    def test_the_instant_of_expiry_counts_as_expired(self) -> None:
        self.assertTrue(lifecycle.has_expired(EXPIRY, EXPIRY))

    def test_no_recorded_expiry_is_never_treated_as_expired(self) -> None:
        """Reaping on missing evidence is the same mistake as passing a guard on
        missing evidence, and here it deletes a machine."""
        self.assertFalse(lifecycle.has_expired(None, AFTER))
        self.assertFalse(lifecycle.has_expired("", AFTER))


class ConfigTest(unittest.TestCase):

    def test_a_config_with_no_lease_block_is_refused(self) -> None:
        """Required, not optional. An optional lease is 'the operator will
        remember', which is the thing this unit exists to replace."""
        config = {key: value for key, value in example_config().items()
                  if key != "lease"}
        with TemporaryTree(config=config) as tree:
            with self.assertRaises(lifecycle.ConfigError) as raised:
                lifecycle.load_config(tree.config_path)
        self.assertIn("lease", str(raised.exception))

    def test_a_namespace_that_would_move_a_branch_is_refused_at_load(self) -> None:
        """Preservation must never surprise a human by writing a ref they read."""
        for namespace in ("refs/heads/", "refs/tags/", "refs/remotes/",
                          "main", "refs/heads/lease/"):
            with self.subTest(namespace):
                config = {**example_config(),
                          "lease": {**example_config()["lease"],
                                    "ref_namespace": namespace}}
                with TemporaryTree(config=config) as tree:
                    with self.assertRaises(lifecycle.ConfigError):
                        lifecycle.load_config(tree.config_path)

    def test_the_shipped_example_declares_a_lease(self) -> None:
        config = example_config()
        self.assertIn("lease", config)
        self.assertTrue(config["lease"]["ref_namespace"].startswith("refs/"))


# ── The expiry travels inside the plan ────────────────────────────────────────

class PlanTest(unittest.TestCase):

    def test_the_expiry_is_inside_the_hash(self) -> None:
        """Not configured beside it. A plan whose expiry could change without
        changing its hash would be approved for one lifetime and applied with
        another."""
        with TemporaryTree() as tree:
            state = lifecycle.empty_state(lifecycle.digest(tree.config))
            short = lifecycle.plan_up(tree.config, state, FakeProvider(),
                                      "run-001", planned_at=BEFORE, lease="1h")
            long = lifecycle.plan_up(tree.config, state, FakeProvider(),
                                     "run-001", planned_at=BEFORE, lease="4h")
        self.assertNotEqual(short["plan_hash"], long["plan_hash"])
        lifecycle.verify_plan_hash(short)
        self.assertEqual(EXPIRY, long["lease"]["expires_at"])

    def test_the_same_inputs_produce_the_same_plan(self) -> None:
        """`planned_at` is an input precisely so this stays true."""
        with TemporaryTree() as tree:
            state = lifecycle.empty_state(lifecycle.digest(tree.config))
            first = lifecycle.plan_up(tree.config, state, FakeProvider(),
                                      "run-001", planned_at=BEFORE, lease="4h")
            second = lifecycle.plan_up(tree.config, state, FakeProvider(),
                                       "run-001", planned_at=BEFORE, lease="4h")
        self.assertEqual(first["plan_hash"], second["plan_hash"])

    def test_there_is_no_way_to_ask_for_no_expiry(self) -> None:
        with TemporaryTree() as tree:
            state = lifecycle.empty_state(lifecycle.digest(tree.config))
            for lease in ("0h", "0s"):
                with self.subTest(lease):
                    with self.assertRaises(lifecycle.LeaseError):
                        lifecycle.plan_up(tree.config, state, FakeProvider(),
                                          "run-001", planned_at=BEFORE,
                                          lease=lease)

    def test_state_records_the_expiry_the_plan_carried(self) -> None:
        """Copied, never recomputed. A second computation is a second chance to
        disagree with what was approved."""
        import test_provision
        with test_provision.ProvisionFixture() as fixture:
            state = fixture.apply()
            self.assertEqual(fixture.plan["lease"]["expires_at"],
                             state["primary"]["expires_at"])
            self.assertEqual(state["primary"]["expires_at"],
                             fixture.saved()["primary"]["expires_at"])

    def test_a_plan_whose_lease_already_expired_is_refused_at_apply(self) -> None:
        """The workflow `hybrid-approve` exists to enable makes this reachable.

        Plan at 09:00 with a 30m lease, a human reviews and approves, an agent
        applies at 11:00. The lease clock started at plan time, so state would
        record an expiry two hours in the past -- and the next reaper tick
        destroys the host the operator has just paid to create, plausibly while
        they are still fetching its console fingerprint.
        """
        import test_provision
        with test_provision.ProvisionFixture() as fixture:
            expires_at = fixture.plan["lease"]["expires_at"]
            with self.assertRaises(lifecycle.LeaseError) as raised:
                fixture.apply(applied_at="2027-01-01T00:00:00Z")
            self.assertIn(expires_at, str(raised.exception))
            # Refused before the mutation, not after: nothing was created and
            # nothing was journalled.
            self.assertEqual("ABSENT", fixture.saved()["primary"]["phase"]
                             if fixture.state_path.exists() else "ABSENT")

    def test_a_plan_applied_within_its_lease_is_allowed(self) -> None:
        """The boundary in the direction that matters -- a check that refused
        everything would pass the test above and break the system."""
        import test_provision
        with test_provision.ProvisionFixture() as fixture:
            state = fixture.apply(applied_at=fixture.plan["lease"]["expires_at"]
                                  .replace("T13", "T12"))
            self.assertEqual("TRUST_PENDING", state["primary"]["phase"])

    def test_the_expiry_is_recorded_before_the_provider_is_called(self) -> None:
        """A machine that exists must always have a readable expiry, including
        one whose creation then failed halfway."""
        source = inspect.getsource(provision.apply_up)
        recorded = source.index("expires_at=plan")
        created = source.index("mutator.create_server")
        self.assertLess(recorded, created)


# ── Is it due? ────────────────────────────────────────────────────────────────

class StatusTest(unittest.TestCase):

    def test_an_unexpired_host_is_not_due(self) -> None:
        with ReapFixture() as fixture:
            verdict = reaper.status(fixture.tree.config, fixture.state, now=BEFORE)
        self.assertEqual("waiting", verdict["action"])

    def test_an_expired_host_is_due(self) -> None:
        with ReapFixture() as fixture:
            verdict = reaper.status(fixture.tree.config, fixture.state, now=AFTER)
        self.assertEqual("reap", verdict["action"])

    def test_a_host_with_no_recorded_expiry_is_never_due(self) -> None:
        with ReapFixture(expires_at=None) as fixture:
            verdict = reaper.status(fixture.tree.config, fixture.state, now=AFTER)
        self.assertEqual("no recorded expiry; refusing to guess", verdict["action"])

    def test_a_destroyed_host_is_nothing_to_reap(self) -> None:
        for phase in ("ABSENT", "ABSENT_VERIFIED"):
            with self.subTest(phase):
                with ReapFixture(phase=phase) as fixture:
                    verdict = reaper.status(fixture.tree.config, fixture.state,
                                            now=AFTER)
                self.assertEqual("nothing to reap", verdict["action"])


# ── Rung 1: the ordinary teardown ─────────────────────────────────────────────

class ReapTest(unittest.TestCase):

    def test_an_expired_host_is_destroyed(self) -> None:
        with ReapFixture() as fixture:
            mutator = FakeMutator()
            outcome = fixture.reap(mutator=mutator)
            self.assertEqual("destroyed", outcome["outcome"])
            self.assertEqual("PASS", outcome["receipt"]["verdict"])
            self.assertIn(("delete_server", str(SERVER_ID)), mutator.calls)
            self.assertEqual("ABSENT_VERIFIED",
                             fixture.saved()["primary"]["phase"])

    def test_an_unexpired_host_is_left_alone(self) -> None:
        """The single most important negative. A reaper that destroys early is
        worse than no reaper: at least a forgotten host still has the work on
        it."""
        with ReapFixture() as fixture:
            mutator = FakeMutator()
            outcome = fixture.reap(now=BEFORE, mutator=mutator)
            self.assertEqual("skipped", outcome["outcome"])
            self.assertEqual([], mutator.calls)
            self.assertEqual("READY", fixture.saved()["primary"]["phase"])

    def test_a_host_with_no_expiry_is_left_alone(self) -> None:
        with ReapFixture(expires_at=None) as fixture:
            mutator = FakeMutator()
            outcome = fixture.reap(mutator=mutator)
        self.assertEqual("skipped", outcome["outcome"])
        self.assertEqual([], mutator.calls)

    def test_a_second_pass_produces_no_second_deletion(self) -> None:
        """launchd will run this every five minutes forever."""
        with ReapFixture() as fixture:
            fixture.reap()
            fixture.state = fixture.saved()
            mutator = FakeMutator()
            outcome = fixture.reap(mutator=mutator)
        self.assertEqual("skipped", outcome["outcome"])
        self.assertEqual([], mutator.calls)

    def test_the_receipt_names_the_reaper_and_the_expiry(self) -> None:
        with ReapFixture() as fixture:
            receipt = fixture.reap()["receipt"]
        authority = receipt["authority"]
        self.assertEqual("approval", authority["kind"])
        self.assertEqual(reaper.REAPER_IDENTITY, authority["approved_by"])
        self.assertIn(EXPIRY, authority["reason"])

    def test_the_approval_it_used_is_left_on_disk(self) -> None:
        """An unattended deletion should leave behind the document that
        authorized it."""
        with ReapFixture() as fixture:
            fixture.reap()
            written = list(fixture.tree.root.glob("reap-*.approval.json"))
            self.assertEqual(1, len(written), written)
            approval = json.loads(written[0].read_text())
        self.assertEqual(reaper.REAPER_IDENTITY, approval["approved_by"])


# ── Rung 2: preserve, then destroy ────────────────────────────────────────────

class PreservationTest(unittest.TestCase):

    def test_a_host_holding_work_is_preserved_and_then_destroyed(self) -> None:
        with ReapFixture() as fixture:
            calls: list = []
            # The guard's answer is derived from whether preservation actually
            # ran, not scripted to flip on the second call. An `iter([True,
            # False])` would report the work preserved even if the reaper never
            # pushed anything -- a fake that answers regardless of the input
            # under test, which is the shape five of this project's defects
            # had, and it is the property under test here.
            probes = FakeProbes()
            probes.uncommitted_or_unpushed = lambda alias, workspace: not calls
            outcome = fixture.reap(
                probes=probes,
                preserver=reaper.Preserver(
                    preserve_runner("PRESERVE-OK abc1234\n", calls=calls)))
        self.assertEqual("preserved_then_destroyed", outcome["outcome"])
        self.assertEqual("abc1234", outcome["preserved"]["commit"])
        self.assertEqual("refs/lease/run-001", outcome["preserved"]["ref"])
        self.assertEqual(1, len(calls))

    def test_a_failed_preservation_leaves_the_host_running(self) -> None:
        """Rung 3, and the reason the ladder exists.

        $0.017/hour is cheaper than destroyed work. A reaper that deleted the
        host here would be the only outcome worse than one that never ran.
        """
        with ReapFixture() as fixture:
            mutator = FakeMutator()
            probes = FakeProbes(dirty=True)
            with self.assertRaises(lifecycle.LeaseError) as raised:
                fixture.reap(probes=probes, mutator=mutator,
                             provider=fixture.still_there(),
                             preserver=reaper.Preserver(
                                 preserve_runner(returncode=1, stderr="no agent")))
            self.assertEqual([], mutator.calls)
            self.assertEqual("READY", fixture.saved()["primary"]["phase"])
            self.assertIn("still billing", str(raised.exception))

    def test_work_that_survives_preservation_still_stops_the_teardown(self) -> None:
        """Preserving is not the same as having preserved. If the guard still
        refuses after the push, the answer is not to push harder."""
        with ReapFixture() as fixture:
            mutator = FakeMutator()
            with self.assertRaises(lifecycle.LeaseError) as raised:
                fixture.reap(probes=FakeProbes(dirty=True), mutator=mutator,
                             provider=fixture.still_there())
            self.assertEqual([], mutator.calls)
            self.assertEqual("READY", fixture.saved()["primary"]["phase"])
            self.assertIn("still billing", str(raised.exception))
            # The cause survives, so the escalation still says which guard
            # refused rather than only that something did.
            self.assertIsInstance(raised.exception.__cause__,
                                  teardown.TeardownError)

    def test_a_guard_that_could_not_run_is_never_preserved_around(self) -> None:
        """An unreachable host is escalated, not climbed.

        `--work-attested` exists for a human who has looked at the machine. The
        reaper has looked at nothing, and a preservation push to a host that
        answers nothing would fail anyway -- but the point is that it must not
        even be attempted, because the next guard along is not the work guard.
        """
        with ReapFixture() as fixture:
            calls: list = []
            mutator = FakeMutator()
            with self.assertRaises(lifecycle.LeaseError) as raised:
                fixture.reap(probes=FakeProbes(unreachable=True), mutator=mutator,
                             preserver=reaper.Preserver(
                                 preserve_runner(calls=calls)))
            self.assertIsInstance(raised.exception.__cause__,
                                  teardown.GuardNotVerified)
        self.assertEqual([], calls, "the reaper tried to preserve an unreachable host")
        self.assertEqual([], mutator.calls)

    def test_a_live_session_is_escalated_rather_than_preserved_around(self) -> None:
        with ReapFixture() as fixture:
            calls: list = []
            with self.assertRaises(lifecycle.LeaseError) as raised:
                fixture.reap(probes=FakeProbes(sessions=True),
                             preserver=reaper.Preserver(preserve_runner(calls=calls)))
            self.assertEqual("G4_no_active_session",
                             raised.exception.__cause__.guard)
        self.assertEqual([], calls)


class PreserverTest(unittest.TestCase):
    """The preservation script itself, not a stand-in for it."""

    def test_uncommitted_changes_are_committed_before_the_push(self) -> None:
        """`git push HEAD` alone would preserve the commits and silently drop
        every uncommitted change -- half of what the guard refused over, and the
        half whose loss the guard would then stop complaining about."""
        script = reaper.Preserver.script("/w", "refs/lease/run-001")
        self.assertLess(script.index("git add -A"), script.index("git push"))
        self.assertIn("commit", script)

    def test_the_push_names_the_run_scoped_ref_and_no_branch(self) -> None:
        script = reaper.Preserver.script("/w", "refs/lease/run-001")
        push = next(line for line in script.splitlines()
                    if line.startswith("git push"))
        self.assertIn("HEAD:refs/lease/run-001", push)
        self.assertNotIn("refs/heads", push)

    def test_a_workspace_path_with_a_space_survives_the_shell(self) -> None:
        script = reaper.Preserver.script("/opt/work space", "refs/lease/r-1")
        self.assertIn("cd '/opt/work space'", script)

    def test_a_missing_workspace_is_a_failure_not_a_success(self) -> None:
        preserver = reaper.Preserver(preserve_runner(returncode=90))
        with self.assertRaises(reaper.PreservationError):
            preserver.preserve("host", "/w", "refs/lease/r-1")

    def test_an_unreachable_host_is_a_failure(self) -> None:
        for error in (OSError("network down"),
                      subprocess.TimeoutExpired(cmd="ssh", timeout=10)):
            with self.subTest(type(error).__name__):
                preserver = reaper.Preserver(preserve_runner(raises=error))
                with self.assertRaises(reaper.PreservationError):
                    preserver.preserve("host", "/w", "refs/lease/r-1")

    def test_success_without_a_commit_is_a_failure(self) -> None:
        """A script that exits 0 having done nothing must not read as "the work
        is safe". Absent evidence is not success, here as everywhere else."""
        preserver = reaper.Preserver(preserve_runner("done\n"))
        with self.assertRaises(reaper.PreservationError):
            preserver.preserve("host", "/w", "refs/lease/r-1")

    def test_the_agent_is_forwarded_and_nothing_prompts(self) -> None:
        calls: list = []
        reaper.Preserver(preserve_runner("PRESERVE-OK a\n", calls=calls)
                         ).preserve("host", "/w", "refs/lease/r-1")
        argv = calls[0][0]
        self.assertIn("-A", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)

    def test_a_ref_needs_a_run_id_to_be_found_under(self) -> None:
        with self.assertRaises(lifecycle.LeaseError):
            reaper.preservation_ref(example_config(), "")


# ── Continuous preservation (unit U7) ─────────────────────────────────────────

class RealGitTest(unittest.TestCase):
    """The preservation script and the work guard, run against real git.

    Everything else in this file drives fakes. These two things cannot be
    tested that way and mean anything: the guard is a git query and the
    preservation script is a shell script, and a fake answers whatever it was
    told to. Both defects this class exists for survived a full fake-based
    suite and appeared the first time the commands ran.

    No network: `origin` is a bare repository on disk.
    """

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        root = Path(self._temporary.name)
        self.origin = root / "origin.git"
        self.work = root / "work"
        self.git("init", "-q", "--bare", str(self.origin), cwd=root)
        self.git("clone", "-q", str(self.origin), str(self.work), cwd=root)
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        (self.work / "a.txt").write_text("a\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "first")
        self.git("push", "-q", "origin", "HEAD:refs/heads/main")
        self.git("fetch", "-q", "origin")
        # Exactly what rehydration leaves behind: a DETACHED HEAD at the pinned
        # commit. Every commit an agent makes on this host is on no branch.
        self.git("checkout", "-q", "--detach", "HEAD")

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def git(self, *argv: str, cwd: Path | None = None) -> str:
        result = subprocess.run(["git", *argv], cwd=str(cwd or self.work),
                                capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode,
                         f"git {' '.join(argv)}: {result.stderr}")
        return result.stdout

    def guard_sees_work(self) -> bool:
        """The teardown work guard's real query, run for real."""
        probes = teardown.Probes(runner=lambda argv: subprocess.run(
            ["bash", "-c", argv[-1]], cwd=str(self.work), capture_output=True,
            text=True, check=False))
        return probes.uncommitted_or_unpushed("unused", str(self.work))

    def preserve(self, ref: str = "refs/lease/run-001"):
        script = reaper.Preserver.script(str(self.work), ref)
        return subprocess.run(["bash", "-c", script], cwd=str(self.work),
                              capture_output=True, text=True, check=False)

    def test_a_commit_on_a_detached_head_is_seen_as_work(self) -> None:
        """The defect this class was written for.

        `git log --branches --not --remotes` reports nothing for a detached
        HEAD, because a detached HEAD is not a branch. The guard called such a
        host clean, and `down` -- manual or scheduled -- would have destroyed a
        commit that existed nowhere else.
        """
        self.assertFalse(self.guard_sees_work())
        (self.work / "b.txt").write_text("b\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "work on a detached head")
        self.assertEqual("", self.git("status", "--porcelain"),
                         "the worktree is clean; only the commit is at risk")
        self.assertTrue(self.guard_sees_work())

    def test_uncommitted_changes_are_still_seen_as_work(self) -> None:
        """The half that already worked, kept so the fix cannot trade one for
        the other."""
        (self.work / "c.txt").write_text("c\n")
        self.assertTrue(self.guard_sees_work())

    def test_preservation_makes_the_guard_pass_and_really_pushes(self) -> None:
        """Both halves, because either one alone would be a lie.

        A guard that passes without the work reaching origin is the worst
        outcome available here: teardown would proceed and the work would be
        gone. So the remote is inspected directly, not inferred from the
        guard's silence.
        """
        (self.work / "b.txt").write_text("b\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "committed work")
        (self.work / "c.txt").write_text("c\n")
        self.assertTrue(self.guard_sees_work())

        result = self.preserve()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("PRESERVE-OK", result.stdout)

        self.assertFalse(self.guard_sees_work())
        remote = self.git("log", "--oneline", "refs/lease/run-001",
                          cwd=self.origin)
        self.assertIn("committed work", remote)
        blob = self.git("show", "refs/lease/run-001:c.txt", cwd=self.origin)
        self.assertEqual("c\n", blob)

    def test_a_failed_push_never_marks_the_work_preserved(self) -> None:
        """`set -eu` is load-bearing, not hygiene.

        If the push fails and the tracking ref is written anyway, the guard
        goes quiet about work that exists in exactly one place -- which is the
        single most dangerous state this system can reach.
        """
        (self.work / "b.txt").write_text("b\n")
        self.git("remote", "set-url", "origin", str(self.work / "nowhere.git"))
        result = self.preserve()
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(self.guard_sees_work())

    def test_preserving_twice_moves_the_ref_rather_than_conflicting(self) -> None:
        """launchd runs this every few minutes for the life of the host."""
        for index in range(3):
            (self.work / f"f{index}.txt").write_text(f"{index}\n")
            self.assertEqual(0, self.preserve().returncode)
            self.assertFalse(self.guard_sees_work())
        self.assertIn("f2.txt",
                      self.git("ls-tree", "--name-only", "refs/lease/run-001",
                               cwd=self.origin))


class ContinuousPreservationTest(unittest.TestCase):
    """The scheduled pass that makes expiry boring."""

    def test_a_host_holding_work_is_preserved_before_anything_expires(self) -> None:
        with ReapFixture() as fixture:
            calls: list = []
            outcome = reaper.tick(
                fixture.tree.config, fixture.state, now=BEFORE, recorded_at=BEFORE,
                state_path=fixture.state_path,
                provider=FakeProvider(surfaces=live_surfaces()),
                mutator=FakeMutator(), tailscale=FakeTailscale(),
                probes=FakeProbes(dirty=True),
                preserver=reaper.Preserver(
                    preserve_runner("PRESERVE-OK abc1234\n", calls=calls)))
            self.assertEqual("waiting", outcome["action"])
            self.assertEqual("PASS", outcome["preservation"]["status"])
            self.assertEqual(1, len(calls))

    def test_an_idle_host_accrues_no_commit(self) -> None:
        """Every tick would otherwise leave an empty commit behind, forever."""
        with ReapFixture() as fixture:
            calls: list = []
            result = reaper.preserve_now(
                fixture.tree.config, fixture.state, probes=FakeProbes(dirty=False),
                preserver=reaper.Preserver(preserve_runner(calls=calls)))
        self.assertEqual("nothing to preserve", result["detail"])
        self.assertEqual([], calls)

    def test_a_host_that_cannot_carry_work_is_skipped(self) -> None:
        with ReapFixture(phase="TRUST_PENDING") as fixture:
            calls: list = []
            result = reaper.preserve_now(
                fixture.tree.config, fixture.state, probes=FakeProbes(dirty=True),
                preserver=reaper.Preserver(preserve_runner(calls=calls)))
        self.assertEqual("SKIPPED", result["status"])
        self.assertEqual([], calls)

    def test_a_failed_push_is_reported_rather_than_swallowed(self) -> None:
        """And it is not fatal either: an unreachable host must not stop the
        tick from reaping some other time. The work guard is what protects the
        work, and it will still refuse."""
        with ReapFixture() as fixture:
            result = reaper.preserve_now(
                fixture.tree.config, fixture.state, probes=FakeProbes(dirty=True),
                preserver=reaper.Preserver(
                    preserve_runner(returncode=1, stderr="no agent")))
        self.assertEqual("NOT_VERIFIED", result["status"])
        self.assertIn("no agent", result["detail"])

    def test_an_unreachable_host_is_not_verified_rather_than_preserved(self) -> None:
        with ReapFixture() as fixture:
            result = reaper.preserve_now(
                fixture.tree.config, fixture.state,
                probes=FakeProbes(unreachable=True),
                preserver=reaper.Preserver(preserve_runner()))
        self.assertEqual("NOT_VERIFIED", result["status"])

    def test_preservation_never_stops_a_reaping(self) -> None:
        """An expired host whose preservation failed must still be offered to
        the ladder, which has its own answer for work it cannot preserve."""
        with ReapFixture() as fixture:
            outcome = reaper.tick(
                fixture.tree.config, fixture.state, now=AFTER, recorded_at=AFTER,
                state_path=fixture.state_path,
                provider=FakeProvider(surfaces=live_surfaces(
                    server=False, primary_ip=False)),
                mutator=FakeMutator(), tailscale=FakeTailscale(),
                probes=FakeProbes(dirty=False),
                preserver=reaper.Preserver(preserve_runner(returncode=1)))
            self.assertEqual("destroyed", outcome["outcome"])

    def test_preservation_runs_before_the_reaping_decision(self) -> None:
        """Otherwise the common case -- an expired host holding a few minutes
        of work -- climbs the escalation ladder every single time, and the
        ladder is meant to be the exception."""
        body = ast.parse(textwrap.dedent(inspect.getsource(reaper.tick))).body[0]
        statements = [ast.unparse(node) for node in body.body
                      if not (isinstance(node, ast.Expr)
                              and isinstance(node.value, ast.Constant))]
        self.assertIn("preserve_now", statements[0])

    def test_the_tracking_ref_records_the_ref_that_was_pushed(self) -> None:
        self.assertEqual("refs/remotes/origin/lease/run-001",
                         reaper.tracking_ref("refs/lease/run-001"))


# ── Credentials, escalation, and the launchd job ──────────────────────────────

class CredentialTest(unittest.TestCase):
    """The finding that made the whole unit a silent no-op.

    `hybrid-reap` used to depend on a recipe that refuses when HCLOUD_TOKEN and
    TAILSCALE_API_TOKEN are absent from the environment. launchd's login shell
    exports neither, so the job exited 2 before the reaper ran, wrote no
    escalation record, and the host billed forever while the operator believed
    a lease was being enforced.
    """

    @staticmethod
    def op_runner(secret: str = "s3cret", returncode: int = 0,
                  calls: list | None = None, raises: Exception | None = None):
        def runner(argv):
            if calls is not None:
                calls.append(argv)
            if raises is not None:
                raise raises
            return subprocess.CompletedProcess(argv, returncode, secret, "denied")
        return runner

    def test_an_absent_credential_is_fetched_from_its_reference(self) -> None:
        calls: list = []
        environment: dict = {}
        fetched = reaper.ensure_credentials(example_config(), environment,
                                            self.op_runner(calls=calls))
        self.assertEqual(["HCLOUD_TOKEN", "TAILSCALE_API_TOKEN"], fetched)
        self.assertEqual("s3cret", environment["HCLOUD_TOKEN"])
        self.assertEqual(2, len(calls))
        configured = [example_config()["credentials"][key]
                      for _, key in reaper.CREDENTIALS]
        self.assertEqual(configured, calls)

    def test_an_exported_credential_is_left_alone(self) -> None:
        """An interactive run must behave exactly as it did and never run a
        secret command, or the operator's own token silently stops being the
        one in use."""
        calls: list = []
        environment = {"HCLOUD_TOKEN": "mine", "TAILSCALE_API_TOKEN": "also-mine"}
        self.assertEqual([], reaper.ensure_credentials(
            example_config(), environment, self.op_runner(calls=calls)))
        self.assertEqual([], calls)
        self.assertEqual("mine", environment["HCLOUD_TOKEN"])

    def test_a_credential_that_cannot_be_resolved_escalates(self) -> None:
        """LeaseError, not a plain failure: exit 3 and a durable record, so it
        is distinguishable from "there was nothing to do"."""
        for description, runner in (
                ("op refused", self.op_runner(returncode=1)),
                ("op absent", self.op_runner(raises=FileNotFoundError())),
                ("op timed out", self.op_runner(
                    raises=subprocess.TimeoutExpired(cmd="op", timeout=1))),
                ("empty secret", self.op_runner(secret="  "))):
            with self.subTest(description):
                with self.assertRaises(lifecycle.LeaseError):
                    reaper.ensure_credentials(example_config(), {}, runner)

    def test_a_partial_resolution_exports_nothing(self) -> None:
        """Both credentials, or neither.

        Exporting each secret as it arrived meant a second reference that
        failed left the first token sitting in the environment of a process
        that was about to go and do something else with it.
        """
        calls: list[str] = []

        def runner(command, **_):
            calls.append(command[-1])
            if len(calls) > 1:
                raise FileNotFoundError("op")
            return subprocess.CompletedProcess(command, 0, "s3cret", "")

        environment: dict[str, str] = {}
        with self.assertRaises(lifecycle.LeaseError):
            reaper.ensure_credentials(example_config(), environment, runner)
        self.assertEqual(2, len(calls), "the second reference was never tried")
        self.assertEqual({}, environment)

    def test_the_reference_is_named_but_the_secret_never_is(self) -> None:
        """A pointer is debuggable; a value is a leak."""
        with self.assertRaises(lifecycle.LeaseError) as raised:
            reaper.ensure_credentials(example_config(), {},
                                      self.op_runner(returncode=1))
        message = str(raised.exception)
        self.assertIn(
            " ".join(example_config()["credentials"]["hcloud_token_command"]),
            message)
        self.assertNotIn("s3cret", message)

    def test_checking_credentials_does_not_keep_them(self) -> None:
        """Proving the path works must not be a way to hold a credential for
        longer than the check."""
        with ReapFixture() as fixture:
            before = dict(os.environ)
            code = reaper.main(["--config", str(fixture.tree.config_path),
                                "--state", str(fixture.state_path),
                                "--now", AFTER, "--check-credentials"])
        self.assertIn(code, (0, 3))
        self.assertEqual(before.get("HCLOUD_TOKEN"),
                         os.environ.get("HCLOUD_TOKEN"))


class EscalationTest(unittest.TestCase):

    def run_reaper(self, fixture, *, now: str = AFTER, **environment) -> tuple[int, Path]:
        escalation = reaper.escalation_path_for(fixture.state_path)
        previous = {key: os.environ.get(key) for key in environment}
        os.environ.update(environment)
        try:
            code = reaper.main(["--config", str(fixture.tree.config_path),
                                "--state", str(fixture.state_path),
                                "--now", now])
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        return code, escalation

    def test_main_turns_a_pre_teardown_refusal_into_exit_3_and_a_record(self) -> None:
        """The whole composition, not just the raise.

        A retained-resource collision refuses inside `plan_down`, before any
        provider is touched, so this runs end to end through `main` with no
        network at all. It used to exit 2 in silence -- every five minutes,
        forever, while the host billed -- which is indistinguishable from a
        transient hiccup and was the point of the escalation path.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            code, escalation = self.run_reaper(
                fixture, HCLOUD_TOKEN="exported", TAILSCALE_API_TOKEN="exported")
            self.assertEqual(3, code)
            self.assertTrue(escalation.exists(), "no durable record was left")
            recorded = json.loads(escalation.read_text())
            self.assertIn("retained list", recorded["reason"])
            # Whichever disposition the provider read yields -- there is no
            # hcloud in the test environment, so it is UNKNOWN -- the record
            # must state one of them rather than assert a fate it never saw.
            self.assertTrue(
                any(phrase in recorded["reason"]
                    for phrase in reaper._DISPOSITIONS.values()),
                recorded["reason"])
            self.assertEqual("READY", fixture.saved()["primary"]["phase"])

    def test_every_refusal_that_leaves_the_host_running_escalates(self) -> None:
        """Not only a failed preservation, and not only failures inside `down`.

        An unreachable host, a drifted id, a live session and a second `down`
        that still refuses all leave an expired host billing. They used to
        leave through the ordinary error path -- exit 2, no record, nothing to
        distinguish them from a transient hiccup.

        The first version of this test asserted "every refusal" while supplying
        only refusals raised inside `destroy()`. Both cases below raise
        *before* it -- one from planning, one from writing the self-approval --
        and both escaped the guard entirely: exit 2, or an uncaught traceback
        and exit 1. A test whose inputs cannot reach the failure it names is
        the same defect as the code it is meant to be watching.
        """
        for description, probes in (
                ("unreachable", FakeProbes(unreachable=True)),
                ("live session", FakeProbes(sessions=True))):
            with self.subTest(description):
                with ReapFixture() as fixture:
                    with self.assertRaises(lifecycle.LeaseError) as raised:
                        fixture.reap(probes=probes,
                                     provider=fixture.still_there())
                    self.assertIn("still billing", str(raised.exception))

    def test_a_refusal_raised_before_the_teardown_starts_still_escalates(self) -> None:
        """The operator retained the very host whose lease has expired.

        `plan_down` refuses on the retained list before any teardown begins.
        That leaves an expired host running just as thoroughly as a live
        session does, so it must escalate rather than exit 2 in silence.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            with self.assertRaises(lifecycle.LeaseError) as raised:
                fixture.reap(provider=fixture.still_there())
            self.assertIn("still billing", str(raised.exception))
            self.assertIn("retained list", str(raised.exception))

    @unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
    def test_an_os_error_minting_the_approval_still_escalates(self) -> None:
        """Not a `LifecycleError`, and that used to be enough to escape.

        The guard caught `LifecycleError` alone, so a plain `OSError` -- an
        unwritable state directory, a full disk -- reached `main`, which
        catches neither: traceback, exit 1, no escalation, host still billing.
        The invariant is about the host, not about which module was unlucky.
        """
        with ReapFixture() as fixture:
            unwritable = fixture.tree.root / "read-only"
            unwritable.mkdir()
            unwritable.chmod(0o500)
            try:
                with self.assertRaises(lifecycle.LeaseError) as raised:
                    fixture.reap(approval_dir=unwritable,
                                 provider=fixture.still_there())
            finally:
                unwritable.chmod(0o700)
            self.assertIn("still billing", str(raised.exception))
            self.assertIn("PermissionError", str(raised.exception))

    def unwritable_escalation(self, fixture) -> Path:
        """Drive a real escalation onto the fallback path and return it."""
        fallback = reaper.fallback_escalation_path(fixture.state_path)
        fallback.unlink(missing_ok=True)
        fixture.state_path.parent.chmod(0o500)
        try:
            code, _ = self.run_reaper(fixture, HCLOUD_TOKEN="exported",
                                      TAILSCALE_API_TOKEN="exported")
        finally:
            fixture.state_path.parent.chmod(0o700)
        self.assertEqual(3, code)
        self.assertTrue(fallback.exists())
        return fallback

    @unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
    def test_a_record_on_the_fallback_path_is_still_a_standing_record(self) -> None:
        """The fallback was added to the writer alone.

        Nothing read it and nothing retracted it, so the exit-0 hole it existed
        to close reopened directly onto it: a host stranded while the state
        directory was unwritable, then a state file that drifted, and the next
        tick reported "nothing to reap" and exited 0 with the host still
        billing. One function owns where records live for exactly this reason.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            fallback = self.unwritable_escalation(fixture)
            try:
                fixture.state_path.unlink()
                absent = state_in("ABSENT", config=fixture.tree.config)
                with self.assertRaises(lifecycle.LeaseError) as raised:
                    reaper.reap(fixture.tree.config, absent, now=AFTER,
                                recorded_at=AFTER, state_path=fixture.state_path,
                                provider=fixture.still_there(),
                                mutator=FakeMutator(), tailscale=FakeTailscale(),
                                probes=FakeProbes(),
                                preserver=reaper.Preserver(preserve_runner()))
                self.assertIn("retained list", str(raised.exception))
            finally:
                fallback.unlink(missing_ok=True)

    @unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
    def test_a_record_on_the_fallback_path_is_retracted_when_resolved(self) -> None:
        """Otherwise it is permanent: nothing in the codebase would remove it,
        and it would outlive its cause forever in the system temp directory."""
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            fallback = self.unwritable_escalation(fixture)
            try:
                resolved = state_in("ABSENT_VERIFIED", config=fixture.tree.config,
                                    expires_at=EXPIRY)
                outcome = reaper.reap(
                    fixture.tree.config, resolved, now=AFTER, recorded_at=AFTER,
                    state_path=fixture.state_path, provider=fixture.still_there(),
                    mutator=FakeMutator(), tailscale=FakeTailscale(),
                    probes=FakeProbes(),
                    preserver=reaper.Preserver(preserve_runner()))
                self.assertTrue(outcome["cleared_escalation"])
                self.assertFalse(fallback.exists(), "the record is permanent")
            finally:
                fallback.unlink(missing_ok=True)

    def test_a_repeated_escalation_does_not_grow_without_bound(self) -> None:
        """On a five-minute timer, nesting each run's message inside the next
        added a couple of hundred bytes per tick, forever -- and overwrote the
        moment the host was first stranded with the moment it was last checked.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            escalation = reaper.escalation_path_for(fixture.state_path)
            lengths = []
            # Distinct timestamps, so "the moment it was first stranded" and
            # "the moment it was last checked" are actually distinguishable.
            for minute in range(4):
                self.run_reaper(fixture, now=f"2026-08-11T13:0{minute}:01Z",
                                HCLOUD_TOKEN="exported",
                                TAILSCALE_API_TOKEN="exported")
                fixture.state_path.unlink(missing_ok=True)
                lengths.append(len(escalation.read_text()))
            record = json.loads(escalation.read_text())
            self.assertEqual(lengths[1], lengths[-1], f"the record grows: {lengths}")
            self.assertIn("retained list", record["original_reason"])
            self.assertEqual("2026-08-11T13:00:01Z", record["first_escalated_at"])
            self.assertEqual("2026-08-11T13:03:01Z", record["escalated_at"])

    @unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
    def test_the_record_survives_an_unwritable_state_directory(self) -> None:
        """The condition that strands a host is often the one that loses the
        record of it.

        The escalation lives beside the state file, so an unwritable or full
        state directory takes both. `main` swallowed that `OSError` and
        returned exit 3 with nothing on disk to read -- and under launchd
        nobody sees the exit code either.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            fallback = reaper.fallback_escalation_path(fixture.state_path)
            fallback.unlink(missing_ok=True)
            fixture.state_path.parent.chmod(0o500)
            try:
                code, escalation = self.run_reaper(
                    fixture, HCLOUD_TOKEN="exported",
                    TAILSCALE_API_TOKEN="exported")
            finally:
                fixture.state_path.parent.chmod(0o700)
            self.assertEqual(3, code)
            self.assertFalse(escalation.exists(), "the fixture was writable")
            self.assertTrue(fallback.exists(), "the record was lost entirely")
            self.assertIn("retained list",
                          json.loads(fallback.read_text())["reason"])
            fallback.unlink()

    def test_exactly_one_record_survives_a_write(self) -> None:
        """Two records, disagreeing, is worse than one in the wrong place.

        A run that fell back leaves a record in the temp directory. When the
        state directory becomes writable again the next run records there --
        and without this, the older file stays behind, describing a different
        moment, with nothing to say which one is current.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            fallback = reaper.fallback_escalation_path(fixture.state_path)
            reaper.write_escalation(fallback, {"escalated_at": BEFORE,
                                               "reason": "an older episode"})
            try:
                code, escalation = self.run_reaper(
                    fixture, HCLOUD_TOKEN="exported",
                    TAILSCALE_API_TOKEN="exported")
                self.assertEqual(3, code)
                self.assertTrue(escalation.exists())
                self.assertFalse(fallback.exists(), "two records were left")
                # The older episode is not discarded, it is carried forward.
                self.assertEqual("an older episode",
                                 json.loads(escalation.read_text())["original_reason"])
            finally:
                fallback.unlink(missing_ok=True)

    def test_an_unreadable_record_is_not_mistaken_for_no_record(self) -> None:
        """A corrupt file still means something went wrong here.

        Reading it as "there is no record" would let a truncated write -- the
        very thing a full disk produces -- look like a resolved problem.
        """
        with ReapFixture() as fixture:
            escalation = reaper.escalation_path_for(fixture.state_path)
            escalation.write_text("{ this is not json")
            self.assertEqual({}, reaper.read_escalation(fixture.state_path))
            fixture.state_path.unlink()
            absent = state_in("ABSENT", config=fixture.tree.config)
            with self.assertRaises(lifecycle.LeaseError) as raised:
                reaper.reap(fixture.tree.config, absent, now=AFTER,
                            recorded_at=AFTER, state_path=fixture.state_path,
                            provider=fixture.still_there(),
                            mutator=FakeMutator(), tailscale=FakeTailscale(),
                            probes=FakeProbes(),
                            preserver=reaper.Preserver(preserve_runner()))
            self.assertIn("(unreadable)", str(raised.exception))

    @unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
    def test_a_failed_record_write_is_reported_rather_than_swallowed(self) -> None:
        """Falling back is not silent.

        An operator reading stderr has to be able to tell "recorded where you
        expect" from "recorded somewhere else because the usual place is
        broken" -- the second is itself a problem worth knowing about.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            fallback = reaper.fallback_escalation_path(fixture.state_path)
            fallback.unlink(missing_ok=True)
            stderr = io.StringIO()
            fixture.state_path.parent.chmod(0o500)
            try:
                with contextlib.redirect_stderr(stderr):
                    self.run_reaper(fixture, HCLOUD_TOKEN="exported",
                                    TAILSCALE_API_TOKEN="exported")
            finally:
                fixture.state_path.parent.chmod(0o700)
                fallback.unlink(missing_ok=True)
        printed = stderr.getvalue()
        self.assertIn("could not record the escalation at", printed)
        self.assertIn(str(reaper.escalation_path_for(fixture.state_path)), printed)

    @unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
    def test_a_record_that_cannot_be_swept_up_still_exits_3(self) -> None:
        """The cleanup that tidies away the losing location may itself fail.

        A record already sitting beside the state file, in a directory that has
        since become unwritable: the write falls to the fallback, and the sweep
        that removes the stale one cannot unlink it. Left unguarded, that
        `PermissionError` escapes the escalation handler entirely -- traceback,
        exit 1, and under launchd that is the same silence the whole path
        exists to prevent. The escalation is what matters; failing to tidy is
        not a reason to lose it.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            fallback = reaper.fallback_escalation_path(fixture.state_path)
            fallback.unlink(missing_ok=True)
            stale = reaper.escalation_path_for(fixture.state_path)
            stale.write_text('{"reason": "an earlier tick"}\n')
            fixture.state_path.parent.chmod(0o500)
            try:
                code, _ = self.run_reaper(fixture, HCLOUD_TOKEN="exported",
                                          TAILSCALE_API_TOKEN="exported")
                self.assertEqual(3, code)
                self.assertTrue(fallback.exists(),
                                "the escalation was lost to a failed cleanup")
            finally:
                fixture.state_path.parent.chmod(0o700)
                fallback.unlink(missing_ok=True)

    def test_the_fallback_location_does_not_move_with_the_environment(self) -> None:
        """launchd and an operator's shell must agree on where to look.

        `tempfile.gettempdir()` reads `$TMPDIR`, and those two environments
        disagree about it: launchd exports none, resolving `/tmp`, while an
        interactive shell resolves `/var/folders/.../T`. The reaper runs under
        launchd, so a record it wrote would be invisible to the shell and to the
        next manual reap -- `standing_escalation` returns None, the lost-state
        guard never fires, and the tick exits 0 with the host still billing.
        That is the hole this location exists to close, reopened through the
        environment rather than the path.
        """
        with ReapFixture() as fixture:
            previous = os.environ.get("TMPDIR")
            seen = set()
            try:
                for value in ("/tmp", "/var/folders/zz/T", None):
                    if value is None:
                        os.environ.pop("TMPDIR", None)
                    else:
                        os.environ["TMPDIR"] = value
                    seen.add(reaper.fallback_escalation_path(fixture.state_path))
            finally:
                if previous is None:
                    os.environ.pop("TMPDIR", None)
                else:
                    os.environ["TMPDIR"] = previous
            self.assertEqual(1, len(seen), f"the location moved: {seen}")
            location = seen.pop()
            if Path(tempfile.gettempdir()) in Path.home().parents:
                # A HOME beneath the temp directory is not a configuration this
                # property can be asserted against: every path under it is also
                # under the temp directory. Say so rather than fail, because a
                # confusing failure here reads as a defect in the reaper.
                self.skipTest("HOME lies beneath the temp directory")
            self.assertNotIn(Path(tempfile.gettempdir()), location.parents)

    @unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
    def test_a_failed_sweep_is_not_reported_as_a_failed_recording(self) -> None:
        """Two different facts must not share one message.

        The sweep that removes the losing record used to sit inside the write's
        own `try`, so an unlink it could not perform was reported as "could not
        record the escalation at <the path just written to>" -- the opposite of
        what happened, to whoever reads that line at 3am -- and skipped the
        `break`, leaving the loop to write a second record elsewhere.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            fallback = reaper.fallback_escalation_path(fixture.state_path)
            fallback.unlink(missing_ok=True)
            stale = reaper.escalation_path_for(fixture.state_path)
            stale.write_text('{"reason": "an earlier tick"}\n')
            stderr = io.StringIO()
            fixture.state_path.parent.chmod(0o500)
            try:
                with contextlib.redirect_stderr(stderr):
                    code, _ = self.run_reaper(fixture, HCLOUD_TOKEN="exported",
                                              TAILSCALE_API_TOKEN="exported")
            finally:
                fixture.state_path.parent.chmod(0o700)
                fallback.unlink(missing_ok=True)
        printed = stderr.getvalue()
        self.assertEqual(3, code)
        self.assertIn(f"escalation recorded at {fallback}", printed)
        self.assertNotIn(f"could not record the escalation at {fallback}",
                         printed)
        self.assertIn(f"could not remove the stale escalation at {stale}",
                      printed)

    @unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
    def test_a_retraction_that_cannot_finish_says_so(self) -> None:
        """Retracting one location must not abandon the others.

        Unlinking the record beside the state file needs a writable directory
        -- the same directory whose unwritability put a record on the fallback
        in the first place. Stopping at that failure leaves the fallback
        standing forever, which is the permanent wrong record the retraction
        exists to prevent, and reporting success would state a fact nobody
        observed.
        """
        with ReapFixture() as fixture:
            beside = reaper.escalation_path_for(fixture.state_path)
            fallback = reaper.fallback_escalation_path(fixture.state_path)
            beside.write_text('{"reason": "beside"}\n')
            fallback.write_text('{"reason": "fallback"}\n')
            stderr = io.StringIO()
            fixture.state_path.parent.chmod(0o500)
            try:
                with contextlib.redirect_stderr(stderr):
                    cleared = reaper.clear_escalation(fixture.state_path)
            finally:
                fixture.state_path.parent.chmod(0o700)
                fallback.unlink(missing_ok=True)
                beside.unlink(missing_ok=True)
        self.assertFalse(cleared, "an unretracted record was reported cleared")
        self.assertIn("could not retract the escalation at", stderr.getvalue())

    def test_a_retraction_reaches_past_a_location_it_could_not_remove(self) -> None:
        """The fallback is swept even when the first location refuses."""
        with ReapFixture() as fixture:
            fallback = reaper.fallback_escalation_path(fixture.state_path)
            fallback.write_text('{"reason": "fallback"}\n')
            try:
                self.assertTrue(reaper.clear_escalation(fixture.state_path))
                self.assertFalse(fallback.exists())
                self.assertIsNone(
                    reaper.standing_escalation(fixture.state_path))
            finally:
                fallback.unlink(missing_ok=True)

    def test_an_unreadable_record_does_not_reset_the_history(self) -> None:
        """The reader refuses to mistake corrupt for absent; so must the writer.

        A truncated record -- what a full disk produces -- was read as `{}` and
        then treated exactly like no record at all, stamping the current tick
        as `first_escalated_at` and adopting its own message as the original
        cause. That silently rewrites how long a host has been stranded and why,
        which is the one thing the record is read for.
        """
        config = {**example_config(),
                  "retained_resources": [retained_entry(SERVER_ID)]}
        with ReapFixture(config=config) as fixture:
            escalation = reaper.escalation_path_for(fixture.state_path)
            escalation.write_text("{ truncated")
            code, _ = self.run_reaper(fixture, now=AFTER,
                                      HCLOUD_TOKEN="exported",
                                      TAILSCALE_API_TOKEN="exported")
            self.assertEqual(3, code)
            recorded = json.loads(escalation.read_text())
            self.assertEqual(reaper.LOST_HISTORY,
                             recorded["first_escalated_at"])
            self.assertEqual(reaper.LOST_HISTORY, recorded["original_reason"])
            self.assertEqual(AFTER, recorded["escalated_at"])

    def test_a_record_is_written_whole_or_not_at_all(self) -> None:
        """Two overlapping ticks must not expose a half-written record.

        A five-minute timer can start a tick before the last one finished, and
        a reader arriving mid-write sees truncated JSON -- which every consumer
        is obliged to treat as unreadable, losing the history it holds. The
        replacement is atomic, so the record is either the old one or the new.
        """
        with ReapFixture() as fixture:
            target = reaper.escalation_path_for(fixture.state_path)
            target.write_text('{"reason": "the first"}\n')
            before = target.stat().st_ino
            reaper.write_escalation(target, {"reason": "the second"})
            self.assertNotEqual(before, target.stat().st_ino,
                                "the record was written in place")
            self.assertEqual("the second",
                             json.loads(target.read_text())["reason"])
            leftovers = [entry.name for entry in target.parent.iterdir()
                         if entry.name.startswith(f".{target.name}")]
            self.assertEqual([], leftovers, "a scratch file was left behind")

    def test_a_write_that_fails_at_the_last_step_leaves_no_scratch(self) -> None:
        """The caller falls to the next location; the litter would stay forever.

        Reached by a target that cannot be replaced at all. The write itself
        succeeds, so the failure lands after the scratch file exists.
        """
        with ReapFixture() as fixture:
            target = reaper.escalation_path_for(fixture.state_path)
            target.mkdir()
            with self.assertRaises(OSError):
                reaper.write_escalation(target, {"reason": "no"})
            leftovers = [entry.name for entry in target.parent.iterdir()
                         if entry.name.startswith(f".{target.name}")]
            target.rmdir()
        self.assertEqual([], leftovers, "a scratch file was left behind")

    @unittest.skipIf(os.geteuid() == 0, "root ignores the mode bits")
    def test_an_unreadable_config_is_named_rather_than_traced(self) -> None:
        """Exit 2 with the reason, not a traceback and exit 1.

        Deliberately NOT an escalation: failing to read the config establishes
        nothing at all about any host, so a record claiming one is stranded
        would be an invention.
        """
        with ReapFixture() as fixture:
            fixture.tree.config_path.chmod(0o000)
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stderr(stderr):
                    code = reaper.main(["--config", str(fixture.tree.config_path),
                                        "--state", str(fixture.state_path),
                                        "--now", AFTER])
            finally:
                fixture.tree.config_path.chmod(0o600)
            self.assertEqual(2, code)
            self.assertIn("PermissionError", stderr.getvalue())
            self.assertIsNone(reaper.standing_escalation(fixture.state_path))

    def test_a_destroyed_host_is_never_recorded_as_still_billing(self) -> None:
        """The regression the blanket `except Exception` introduced.

        `apply_down` deletes the resources and only then writes state and takes
        its lock, so an OSError there lands *after* the host is gone. The first
        version asserted "left RUNNING and is still billing" for every failure,
        which turned that into a durable record claiming a destroyed host was
        burning money -- the same lie the retraction path exists to prevent,
        inverted and permanent. It still escalates, because the state file no
        longer describes reality and a human has to reconcile it; what it must
        not do is invent which of the two happened.
        """
        class BreaksTheDiskAfterDeleting(FakeMutator):
            """The disk fills, or the volume remounts read-only, between the
            provider deleting the host and the state file recording it.

            `apply_down` takes its lock before the deletions, so the directory
            has to become unwritable partway through rather than beforehand --
            otherwise the failure lands before anything has been destroyed and
            proves the opposite of what this test is about.
            """

            def __init__(self, directory: Path) -> None:
                super().__init__()
                self._directory = directory

            def delete_primary_ip(self, identifier):
                result = super().delete_primary_ip(identifier)
                self._directory.chmod(0o500)
                return result

        with ReapFixture() as fixture:
            mutator = BreaksTheDiskAfterDeleting(fixture.state_path.parent)
            try:
                with self.assertRaises(lifecycle.LeaseError) as raised:
                    fixture.reap(mutator=mutator,
                                 approval_dir=Path(tempfile.gettempdir()))
            finally:
                fixture.state_path.parent.chmod(0o700)
        message = str(raised.exception)
        self.assertIn(("delete_server", "900001"), mutator.calls,
                      f"the fixture never reached the deletions: {mutator.calls}")
        self.assertIn("no longer reports the server", message)
        self.assertNotIn("left RUNNING", message)

    def test_an_unconfirmable_disposition_says_so_rather_than_guessing(self) -> None:
        """A provider that cannot be read is not evidence of survival, and not
        evidence of destruction either.

        Two ways to be unreadable, and both must reach the same answer: the
        call itself failing, and a surface that came back NOT_VERIFIED. The
        second is the one that looks like data and is not.
        """
        class Raises(FakeProvider):
            def inventory(self):
                raise lifecycle.LifecycleError("the provider is unreachable")

        unreadable = live_surfaces()
        unreadable["servers"] = {"status": "NOT_VERIFIED", "items": []}

        for description, provider in (
                ("the read fails", Raises(surfaces=live_surfaces())),
                ("the surface is NOT_VERIFIED", FakeProvider(surfaces=unreadable))):
            with self.subTest(description):
                with ReapFixture() as fixture:
                    with self.assertRaises(lifecycle.LeaseError) as raised:
                        fixture.reap(probes=FakeProbes(sessions=True),
                                     provider=provider)
                    self.assertIn("could NOT be confirmed", str(raised.exception))

    def test_a_lost_state_file_never_erases_a_standing_escalation(self) -> None:
        """`load_state` synthesises an ABSENT record when the file is missing,
        so a drifted `--state` path read as "nothing to reap" -- and the
        blanket retraction deleted the record and exited 0. The host is
        untouched and still billing, and nothing on disk would have said so.
        """
        with ReapFixture() as fixture:
            stale = reaper.escalation_path_for(fixture.state_path)
            reaper.write_escalation(stale, {"escalated_at": BEFORE,
                                            "reason": "the original cause"})
            fixture.state_path.unlink()
            absent = state_in("ABSENT", config=fixture.tree.config)
            with self.assertRaises(lifecycle.LeaseError) as raised:
                reaper.reap(fixture.tree.config, absent, now=AFTER,
                            recorded_at=AFTER, state_path=fixture.state_path,
                            provider=fixture.still_there(),
                            mutator=FakeMutator(), tailscale=FakeTailscale(),
                            probes=FakeProbes(),
                            preserver=reaper.Preserver(preserve_runner()))
            self.assertTrue(stale.exists(), "the record was erased")
            # The replacement record must carry the original cause forward:
            # `main` rewrites the file wholesale.
            self.assertIn("the original cause", str(raised.exception))

    def test_an_escalation_is_retracted_when_the_host_is_gone_by_other_means(self) -> None:
        """The reaper is not the only thing that can destroy a host.

        Retracting only after a reap the reaper itself completed meant an
        operator who tore the host down by hand left a file insisting it was
        still burning money -- dated, permanent, and exactly the "lie with a
        date" the retraction exists to prevent.
        """
        for description, phase, expires_at in (
                ("destroyed by hand", "ABSENT_VERIFIED", EXPIRY),
                ("re-leased", "TRUSTED", "2026-08-11T23:00:00Z")):
            with self.subTest(description):
                with ReapFixture(phase=phase, expires_at=expires_at) as fixture:
                    stale = reaper.escalation_path_for(fixture.state_path)
                    reaper.write_escalation(stale, {"escalated_at": BEFORE,
                                                    "reason": "an older problem"})
                    outcome = fixture.reap()
                    self.assertEqual("skipped", outcome["outcome"])
                    self.assertTrue(outcome["cleared_escalation"])
                    self.assertFalse(stale.exists())

    def test_a_host_with_no_recorded_expiry_keeps_its_escalation(self) -> None:
        """Refusing to guess is not the same as the problem being resolved."""
        with ReapFixture(expires_at=None) as fixture:
            stale = reaper.escalation_path_for(fixture.state_path)
            reaper.write_escalation(stale, {"escalated_at": BEFORE,
                                            "reason": "an older problem"})
            outcome = fixture.reap()
            self.assertEqual("skipped", outcome["outcome"])
            self.assertFalse(outcome["cleared_escalation"])
            self.assertTrue(stale.exists())

    def test_a_successful_reap_retracts_an_earlier_escalation(self) -> None:
        """A file saying a host is billing that outlives the host is worse than
        no file: the next reader either acts on nothing or learns to skim.

        Driven through a real successful reap rather than through `main`, which
        would need a provider. The clearing lives beside the outcome that
        justifies it for exactly this reason -- put it in `main` and no test
        that reaches success can see it.
        """
        with ReapFixture() as fixture:
            stale = reaper.escalation_path_for(fixture.state_path)
            reaper.write_escalation(stale, {"escalated_at": BEFORE,
                                            "reason": "an older problem"})
            self.assertTrue(stale.exists())
            outcome = fixture.reap()
            self.assertEqual("destroyed", outcome["outcome"])
            self.assertTrue(outcome["cleared_escalation"])
            self.assertFalse(stale.exists())

    def test_a_reap_with_nothing_to_retract_says_so(self) -> None:
        """The negative, so the field cannot become a constant."""
        with ReapFixture() as fixture:
            self.assertFalse(fixture.reap()["cleared_escalation"])

    def test_a_refused_reap_leaves_the_escalation_standing(self) -> None:
        with ReapFixture() as fixture:
            stale = reaper.escalation_path_for(fixture.state_path)
            reaper.write_escalation(stale, {"reason": "still true"})
            with self.assertRaises(lifecycle.LeaseError):
                fixture.reap(probes=FakeProbes(unreachable=True))
            self.assertTrue(stale.exists())

    def test_a_reaper_that_cannot_get_credentials_escalates_end_to_end(self) -> None:
        """Through `main`, with the environment genuinely empty.

        The escalation machinery being correct is not the same as `main`
        reaching it. Before this, the launchd job exited 2 on a missing token
        with no record at all -- the failure was upstream of everything that
        knew how to report one.
        """
        missing = ["cinderwell-no-such-secret-tool", "read", "nothing"]
        unresolvable = {**example_config(),
                        "credentials": {
                            "hcloud_token_command": missing,
                            "tailscale_api_token_command": missing}}
        with ReapFixture(config=unresolvable) as fixture:
            code, escalation = self.run_reaper(
                fixture, HCLOUD_TOKEN="", TAILSCALE_API_TOKEN="")
            self.assertEqual(3, code)
            self.assertTrue(escalation.exists())
            self.assertIn("cinderwell-no-such-secret-tool", escalation.read_text())

    def test_clearing_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lease-escalation.json"
            self.assertFalse(reaper.clear_escalation(path))
            reaper.write_escalation(path, {"reason": "x"})
            self.assertTrue(reaper.clear_escalation(path))
            self.assertFalse(reaper.clear_escalation(path))


class PlistTest(unittest.TestCase):

    def _paths(self, directory: str):
        root = Path(directory)
        binary = root / "bin" / "cinderwell"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        config = root / "cfg" / "config.json"
        state = root / "state" / "host.json"
        config.parent.mkdir(parents=True, exist_ok=True)
        state.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("{}")
        state.write_text("{}")
        return binary, state, config

    def test_it_renders_the_binary_interval_and_machine_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary, state, config = self._paths(directory)
            rendered = reaper.render_plist(binary, state, config, 600)
            self.assertIn("<integer>600</integer>", rendered)
            self.assertIn(str(binary), rendered)
            self.assertIn(str(config), rendered)
            self.assertIn(str(state), rendered)
            log_path = str(state.parent / "reaper.log")
            self.assertIn(f"<string>{log_path}</string>", rendered)
            self.assertEqual(2, rendered.count(f"<string>{log_path}</string>"))
            self.assertNotIn("{{", rendered)
            self.assertNotIn(str(REPOSITORY_ROOT_PRIMARY), rendered)
            parsed = plistlib.loads(rendered.encode())
            self.assertEqual(str(state.parent / "reaper.log"),
                             parsed["StandardOutPath"])

    def test_a_path_that_would_break_shell_quoting_survives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            awkward = root / "a&b|c"
            binary = awkward / "cinderwell"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\n")
            binary.chmod(0o755)
            config = awkward / "config.json"
            state = awkward / "host.json"
            config.write_text("{}")
            state.write_text("{}")
            rendered = reaper.render_plist(binary, state, config, 300)
            self.assertIn("a&amp;b|c", rendered)
            parsed = plistlib.loads(rendered.encode())
            outs = parsed["StandardOutPath"]
            errs = parsed["StandardErrorPath"]
            self.assertEqual(outs, errs)
            self.assertTrue(outs.endswith("reaper.log"))
            self.assertIn("a&b|c", outs)  # plistlib unescapes
            prog = parsed["ProgramArguments"]
            self.assertEqual("/bin/bash", prog[0])

    def test_a_relative_binary_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, state, config = self._paths(directory)
            with self.assertRaises(lifecycle.LeaseError):
                reaper.render_plist(Path("relative/factory"), state, config, 300)

    def test_a_busy_loop_interval_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary, state, config = self._paths(directory)
            with self.assertRaises(lifecycle.LeaseError):
                reaper.render_plist(binary, state, config, 30)

    def test_a_refused_render_leaves_no_escalation_record(self) -> None:
        """Rendering a plist establishes nothing about any host."""
        with ReapFixture() as fixture:
            escalation = reaper.escalation_path_for(fixture.state_path)
            code = reaper.main(["--config", str(fixture.tree.config_path),
                                "--state", str(fixture.state_path),
                                "--now", AFTER, "--interval", "30",
                                "--render-plist",
                                "--factory-bin", "/usr/bin/factory"])
            self.assertEqual(2, code)
            self.assertFalse(escalation.exists())

    def test_the_linked_worktree_helper_answers_for_this_checkout(self) -> None:
        """is_linked_worktree remains for diagnostics; render no longer uses it.

        Asserted as "returns a bool without raising" rather than a fixed
        answer, because whether the suite runs from the primary checkout, a
        linked worktree, or an extracted archive is the caller's business.
        """
        self.assertIsInstance(reaper.is_linked_worktree(REPOSITORY_ROOT), bool)



# ── The reaper gets no private path ───────────────────────────────────────────

class NoPrivatePathTest(unittest.TestCase):

    def test_the_reaper_never_attests_to_anything(self) -> None:
        """Structural, because this is the tempting fix.

        The reaper will meet unreachable hosts, and `--work-attested` is sitting
        right there and would make the error go away. It is an operator's
        written statement that they looked; the reaper has looked at nothing,
        and a machine cannot attest on a human's behalf.
        """
        code = source_without_prose("reaper.py")
        for node in ast.walk(ast.parse(code)):
            if isinstance(node, ast.keyword):
                self.assertNotEqual("work_attested", node.arg)
        self.assertNotIn("work_attested", code)

    def test_destruction_goes_through_the_ordinary_teardown(self) -> None:
        """Asserted on the call, not the outcome.

        A reaper that deleted the server itself would produce the same
        destroyed host and none of the guards.
        """
        called: list = []
        original = teardown.apply_down

        def recording(*args, **kwargs):
            called.append(kwargs)
            return original(*args, **kwargs)

        with ReapFixture() as fixture:
            teardown.apply_down = recording
            try:
                fixture.reap()
            finally:
                teardown.apply_down = original
        self.assertEqual(1, len(called))
        self.assertNotIn("work_attested", called[0])

    def test_the_reaper_issues_no_provider_command_of_its_own(self) -> None:
        """It has no Mutator of its own and builds no hcloud argv. Deletion is
        `teardown`'s, by exact recorded id, or it does not happen."""
        code = source_without_prose("reaper.py")
        # `'hcloud'` quoted is the CLI's own name as a literal, which is what
        # building an argv would look like. `config['hcloud_context']` is not
        # that -- it is the ordinary Mutator being handed its context.
        for forbidden in ("delete_server", "delete_primary_ip", "'hcloud'"):
            self.assertNotIn(forbidden, code)


# ── Command line and the launchd job ──────────────────────────────────────────

class CommandLineTest(unittest.TestCase):

    def test_check_reports_without_changing_anything(self) -> None:
        with ReapFixture() as fixture:
            before = fixture.state_path.read_text()
            code = reaper.main(["--config", str(fixture.tree.config_path),
                                "--state", str(fixture.state_path),
                                "--now", AFTER, "--check"])
            self.assertEqual(0, code)
            self.assertEqual(before, fixture.state_path.read_text())

    def test_now_is_an_input_rather_than_a_side_effect(self) -> None:
        parameter = inspect.signature(reaper.reap).parameters["now"]
        self.assertIs(inspect.Parameter.empty, parameter.default)
        self.assertNotIn("utcnow", inspect.getsource(reaper))

    def test_an_escalation_is_recorded_where_a_human_will_find_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            written = reaper.write_escalation(
                Path(directory) / "lease-escalation.json",
                {"escalated_at": AFTER, "reason": "could not push"})
            self.assertIn("could not push", written.read_text())

    def test_the_launchd_job_survives_sleep_without_a_checkout(self) -> None:
        """StartInterval rather than StartCalendarInterval, so a closed laptop
        delays enforcement rather than cancelling it. Logs and program stay on
        machine paths — no repository root placeholder remains."""
        template = (SCHEMA_DIR /
                    "com.cinderwell.reaper.plist.tmpl").read_text()
        packaged = (REPOSITORY_ROOT / "cinderwell" / "resources" /
                    "com.cinderwell.reaper.plist.tmpl").read_text()
        self.assertEqual(template, packaged)
        self.assertIn("<key>StartInterval</key>", template)
        self.assertNotIn("<key>StartCalendarInterval</key>", template)
        for placeholder in ("{{PROGRAM}}", "{{INTERVAL_SECONDS}}", "{{LOG_PATH}}"):
            self.assertIn(placeholder, template)
        self.assertNotIn("{{REPOSITORY_ROOT}}", template)
        self.assertNotIn("reaper.log", template)


if __name__ == "__main__":
    unittest.main()
