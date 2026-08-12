"""Tests for fail-closed teardown (unit S5).

The property under test throughout is that a guard which cannot be evaluated
stops the teardown. Most of these tests therefore assert a refusal *and* that
zero mutations were attempted, because a refusal that still deleted something
is not a refusal.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from cinderwell import lifecycle  # noqa: E402
from cinderwell import provision  # noqa: E402
from cinderwell import teardown  # noqa: E402
from test_lifecycle import (FakeProvider, TemporaryTree,  # noqa: E402
                            SENTINEL_FIREWALL_ID, SENTINEL_FIREWALL_NAME,
                            authority_for, example_config)
from test_provision import FakeMutator, FakeTailscale  # noqa: E402

SERVER_ID = 900001
SERVER_NAME = "cinderwell-run-001"
PRIMARY_IP_ID = 900002


def state_in(phase: str, *, generation: int = 4, config: dict | None = None,
             **primary) -> dict:
    """A state record positioned at a chosen phase."""
    record = {"phase": phase, "run_id": "run-001", "server_id": SERVER_ID,
              "server_name": SERVER_NAME, "primary_ipv4_id": PRIMARY_IP_ID,
              "tailscale_hostname": SERVER_NAME, "tailscale_key_id": "key-abc123",
              "alias": "cinderwell"}
    record.update(primary)
    record = {key: value for key, value in record.items() if value is not None}
    return {"schema_version": 1, "generation": generation,
            "config_digest": lifecycle.digest(config or example_config()),
            "primary": record}


def retained_entry(identifier: int = SERVER_ID) -> dict:
    """A retention entry in exactly the shape the config schema permits."""
    return {"id": identifier, "kind": "server", "purpose": "in use",
            "owner": "operator", "max_monthly": 10.0,
            "review_by": "2026-12-31"}


def live_surfaces(*, server: bool = True, primary_ip: bool = True,
                  server_name: str = SERVER_NAME) -> dict:
    return {
        "servers": ([{"id": SERVER_ID, "name": server_name}] if server else []),
        "volumes": [],
        "primary_ips": ([{"id": PRIMARY_IP_ID, "name": "ip"}] if primary_ip else []),
        "floating_ips": [],
        "firewalls": [{"id": SENTINEL_FIREWALL_ID, "name": SENTINEL_FIREWALL_NAME}],
        "ssh_keys": [], "snapshots": [],
    }


def probe_runner(stdout="", returncode=0, stderr="", raises=None):
    """Drive the real Probes through its runner seam, not around it."""
    def runner(argv):
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
    return runner


class RealProbeTest(unittest.TestCase):
    """The probes themselves, not a stand-in for them.

    `FakeProbes` overrides `uncommitted_or_unpushed` wholesale, so every test
    that exercises the work guard exercises the *call site* and never the logic
    that decides the answer. A mutation making that method return False
    unconditionally survived the entire suite -- and that method is the guard
    against destroying a host holding work that exists nowhere else.
    """

    def test_a_clean_workspace_reports_no_work(self) -> None:
        probes = teardown.Probes(probe_runner("\n---\n"))
        self.assertFalse(probes.uncommitted_or_unpushed("host", "/w"))

    def test_uncommitted_changes_are_work(self) -> None:
        probes = teardown.Probes(probe_runner(" M app.py\n?? new.py\n---\n"))
        self.assertTrue(probes.uncommitted_or_unpushed("host", "/w"))

    def test_unpushed_commits_are_work(self) -> None:
        """The half that is easiest to forget: a committed-but-unpushed change
        is clean by `git status` and still exists nowhere else."""
        probes = teardown.Probes(probe_runner("\n---\nabc1234 fix the thing\n"))
        self.assertTrue(probes.uncommitted_or_unpushed("host", "/w"))

    def test_both_kinds_at_once_are_work(self) -> None:
        probes = teardown.Probes(probe_runner(" M app.py\n---\nabc1234 wip\n"))
        self.assertTrue(probes.uncommitted_or_unpushed("host", "/w"))

    def test_a_missing_workspace_is_not_verified_rather_than_clean(self) -> None:
        probes = teardown.Probes(probe_runner(returncode=90))
        with self.assertRaises(teardown.GuardNotVerified) as raised:
            probes.uncommitted_or_unpushed("host", "/w")
        self.assertIn("not found", str(raised.exception))

    def test_a_failed_inspection_is_not_verified_rather_than_clean(self) -> None:
        probes = teardown.Probes(probe_runner(returncode=1, stderr="boom"))
        with self.assertRaises(teardown.GuardNotVerified):
            probes.uncommitted_or_unpushed("host", "/w")

    def test_an_unreachable_host_is_not_verified_rather_than_clean(self) -> None:
        """The case where destroying the host is most likely to lose
        something."""
        for error in (OSError("network down"),
                      subprocess.TimeoutExpired(cmd="ssh", timeout=10)):
            with self.subTest(error=type(error).__name__):
                probes = teardown.Probes(probe_runner(raises=error))
                with self.assertRaises(teardown.GuardNotVerified):
                    probes.uncommitted_or_unpushed("host", "/w")

    def test_any_external_session_is_active(self) -> None:
        """The non-PTY check's own SSH connection is not in utmp."""
        self.assertFalse(
            teardown.Probes(probe_runner("0\n")).has_active_sessions("host"))
        self.assertTrue(
            teardown.Probes(probe_runner("1\n")).has_active_sessions("host"))

    def test_an_unreadable_session_count_is_not_verified(self) -> None:
        probes = teardown.Probes(probe_runner("not a number\n"))
        with self.assertRaises(teardown.GuardNotVerified):
            probes.has_active_sessions("host")

    def test_a_failed_session_check_is_not_verified_rather_than_empty(self) -> None:
        probes = teardown.Probes(probe_runner(returncode=255))
        with self.assertRaises(teardown.GuardNotVerified):
            probes.has_active_sessions("host")


class FakeProbes(teardown.Probes):
    """Scripted answers about the host, including 'I do not know'."""

    def __init__(self, *, dirty: bool | Exception = False,
                 sessions: bool | Exception = False,
                 workspaces: list | Exception | None = None,
                 delete_fails: bool = False,
                 unreachable: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        # An unreachable host is the case the attestation exists for: the guard
        # cannot run at all, which is a different thing from running and saying
        # no.
        if unreachable:
            dirty = teardown.GuardNotVerified("cannot inspect git state: unreachable")
            sessions = teardown.GuardNotVerified("cannot check sessions: unreachable")
        self._dirty = dirty
        self._sessions = sessions
        self._workspaces = workspaces if workspaces is not None else []
        self._delete_fails = delete_fails
        super().__init__(runner=self._unusable)

    @staticmethod
    def _unusable(argv):
        raise AssertionError(f"no test may run a real command: {argv}")

    @staticmethod
    def _answer(value):
        if isinstance(value, Exception):
            raise value
        return value

    def uncommitted_or_unpushed(self, alias, workspace):
        self.calls.append(("uncommitted_or_unpushed", alias, workspace))
        return self._answer(self._dirty)

    def has_active_sessions(self, alias):
        self.calls.append(("has_active_sessions", alias))
        return self._answer(self._sessions)

    def devpod_workspaces(self):
        self.calls.append(("devpod_workspaces",))
        return self._answer(self._workspaces)

    def devpod_stop_and_delete(self, workspace):
        self.calls.append(("devpod_stop_and_delete", workspace))
        if self._delete_fails:
            raise teardown.TeardownError("devpod delete failed")


class TeardownFixture:
    """A config, a state file on disk, and a matching plan."""

    def __init__(self, phase: str = "TRUST_PENDING", **state_kwargs):
        self.tree = TemporaryTree()
        self.work = Path(tempfile.mkdtemp())
        self.state_path = self.work / "state.json"
        self.state = state_in(phase, config=self.tree.config, **state_kwargs)
        provision.save_state(self.state_path, self.state)
        self.plan = teardown.plan_down(self.tree.config, self.state)

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.tree.__exit__()

    def apply(self, *, provider=None, mutator=None, tailscale=None, probes=None,
              plan=None, config=None, state=None, work_attested=None,
              authority=None):
        return teardown.apply_down(
            config or self.tree.config, state or self.state, plan or self.plan,
            state_path=self.state_path,
            provider=provider or FakeProvider(surfaces=live_surfaces(
                server=False, primary_ip=False)),
            mutator=mutator or FakeMutator(),
            tailscale=tailscale or FakeTailscale(),
            probes=probes or FakeProbes(),
            recorded_at="2026-08-10T00:00:00Z",
            work_attested=work_attested,
            authority=authority or authority_for(plan or self.plan))

    def saved(self) -> dict:
        return json.loads(self.state_path.read_text())


# ── Planning ──────────────────────────────────────────────────────────────────

class PlanTest(unittest.TestCase):

    def test_absent_phases_have_nothing_to_destroy(self) -> None:
        for phase in ("ABSENT", "ABSENT_VERIFIED"):
            with self.assertRaises(teardown.TeardownError) as caught:
                teardown.plan_down(example_config(), state_in(phase))
            self.assertIn("nothing to destroy", str(caught.exception))

    def test_pre_creation_phases_are_sent_to_abort_up(self) -> None:
        """A host that was never created is cheaper and safer to abandon."""
        for phase in ("PLANNED", "PROVISIONING"):
            with self.assertRaises(teardown.TeardownError) as caught:
                teardown.plan_down(example_config(), state_in(phase))
            self.assertIn("abort-up", str(caught.exception))

    def test_the_plan_names_only_recorded_ids(self) -> None:
        plan = teardown.plan_down(example_config(), state_in("READY"))
        identifiers = {(target["kind"], str(target.get("id") or
                                            target.get("hostname")))
                       for target in plan["targets"]}
        self.assertEqual({("tailscale_device", SERVER_NAME),
                          ("tailscale_key", "key-abc123"),
                          ("server", str(SERVER_ID)),
                          ("primary_ip", str(PRIMARY_IP_ID))}, identifiers)

    def test_nothing_unrecorded_is_ever_targeted(self) -> None:
        state = state_in("READY", primary_ipv4_id=None, tailscale_key_id=None)
        kinds = {target["kind"]
                 for target in teardown.plan_down(example_config(), state)["targets"]}
        self.assertEqual({"tailscale_device", "server"}, kinds)

    def test_the_plan_hash_is_stable_and_input_sensitive(self) -> None:
        config, state = example_config(), state_in("READY")
        self.assertEqual(teardown.plan_down(config, state)["plan_hash"],
                         teardown.plan_down(config, state)["plan_hash"])
        moved = teardown.plan_down(config, state_in("READY", generation=5))
        self.assertNotEqual(teardown.plan_down(config, state)["plan_hash"],
                            moved["plan_hash"])

    def test_a_hand_edited_plan_cannot_be_applied(self) -> None:
        plan = teardown.plan_down(example_config(), state_in("READY"))
        plan["targets"].append({"kind": "server", "id": 111111})
        with self.assertRaises(lifecycle.PlanError):
            lifecycle.verify_plan_hash(plan)

    def test_a_retained_resource_is_never_planned_for_deletion(self) -> None:
        """The retention list and the state file disagreeing is not resolvable
        by guessing which one is right."""
        config = {**example_config(), "retained_resources": [retained_entry()]}
        # The entry must be exactly what the shipped schema permits, or this
        # test would pass against a guard that never matches anything.
        lifecycle.validate(config, lifecycle.load_schema("config.schema.json"))
        with self.assertRaises(teardown.TeardownError) as caught:
            teardown.plan_down(config, state_in("READY"))
        self.assertIn("retained", str(caught.exception))

    def test_an_unrelated_retained_resource_does_not_block_teardown(self) -> None:
        config = {**example_config(),
                  "retained_resources": [retained_entry(identifier=424242)]}
        teardown.plan_down(config, state_in("READY"))

    def test_planning_needs_no_provider_at_all(self) -> None:
        """Structural: plan_down's signature admits nothing that could mutate."""
        import inspect
        parameters = set(inspect.signature(teardown.plan_down).parameters)
        self.assertEqual({"config", "state"}, parameters)


# ── Guards ────────────────────────────────────────────────────────────────────

class GuardTest(unittest.TestCase):

    def _guards(self, phase="TRUST_PENDING", *, provider=None, probes=None,
                config=None, **state_kwargs):
        config = config or example_config()
        state = state_in(phase, config=config, **state_kwargs)
        plan = teardown.plan_down(config, state)
        return teardown.evaluate_guards(
            config, state, plan,
            provider=provider or FakeProvider(surfaces=live_surfaces()),
            probes=probes or FakeProbes())

    def test_an_unreadable_server_surface_stops_the_teardown(self) -> None:
        surfaces = live_surfaces()
        surfaces["servers"] = RuntimeError("api down")
        with self.assertRaises(teardown.GuardNotVerified):
            self._guards(provider=FakeProvider(surfaces=surfaces))

    def test_a_reused_id_now_naming_something_else_is_refused(self) -> None:
        """Provider IDs can be reused. Deleting by an ID whose name no longer
        matches would destroy a resource this run never created."""
        with self.assertRaises(teardown.TeardownError) as caught:
            self._guards(provider=FakeProvider(
                surfaces=live_surfaces(server_name="somebody-elses-server")))
        self.assertIn("did not create", str(caught.exception))

    def test_an_already_absent_server_is_accepted_not_treated_as_drift(self) -> None:
        results = self._guards(provider=FakeProvider(
            surfaces=live_surfaces(server=False)))
        drift = next(r for r in results if r["id"] == "G2_drift")
        self.assertEqual("PASS", drift["status"])
        self.assertIn("already absent", drift["detail"])

    def test_the_work_guard_is_vacuous_before_rehydrate_and_says_so(self) -> None:
        """TRUST_PENDING and TRUSTED never created the factory workspace
        (rehydrate is what does, and rehydrate advances to READY)."""
        for phase in ("TRUST_PENDING", "TRUSTED"):
            with self.subTest(phase=phase):
                results = self._guards(phase)
                work = next(r for r in results if r["id"] == "G3_work_preserved")
                self.assertEqual("PASS", work["status"])
                self.assertIn("vacuous", work["detail"])
                self.assertIn("never reached READY", work["detail"])

    def test_the_work_guard_actually_runs_once_the_host_may_carry_work(self) -> None:
        probes = FakeProbes()
        self._guards("READY", probes=probes)
        self.assertIn(("uncommitted_or_unpushed", "cinderwell",
                       example_config()["workspace"]["path"]), probes.calls)

    def test_unpushed_work_stops_the_teardown(self) -> None:
        with self.assertRaises(teardown.TeardownError) as caught:
            self._guards("READY", probes=FakeProbes(dirty=True))
        self.assertIn("uncommitted or unpushed", str(caught.exception))

    def test_an_unreachable_host_is_not_verified_rather_than_clean(self) -> None:
        """The case where destroying the host is most likely to lose work is
        exactly the case where the host cannot be asked."""
        probes = FakeProbes(dirty=teardown.GuardNotVerified("host unreachable"))
        with self.assertRaises(teardown.GuardNotVerified):
            self._guards("READY", probes=probes)

    def test_a_trusted_host_with_no_alias_recorded_is_refused(self) -> None:
        config = {**example_config()}
        config["ssh"] = {**config["ssh"], "alias": ""}
        with self.assertRaises(teardown.GuardNotVerified):
            self._guards("READY", config=config, alias=None)

    def test_an_ambiguous_phase_refuses_rather_than_guesses(self) -> None:
        """FAILED does not say whether the host ever carried work."""
        for phase in ("FAILED", "DESTROYING"):
            with self.assertRaises(teardown.GuardNotVerified) as caught:
                self._guards(phase)
            self.assertIn("does not establish", str(caught.exception))

    def test_an_active_session_stops_the_teardown(self) -> None:
        with self.assertRaises(teardown.TeardownError) as caught:
            self._guards("READY", probes=FakeProbes(sessions=True))
        self.assertIn("active session", str(caught.exception))

    def test_an_unverifiable_session_check_stops_the_teardown(self) -> None:
        probes = FakeProbes(sessions=teardown.GuardNotVerified("no answer"))
        with self.assertRaises(teardown.GuardNotVerified):
            self._guards("READY", probes=probes)

    def test_a_wrong_project_credential_stops_the_teardown(self) -> None:
        provider = FakeProvider(surfaces=live_surfaces(),
                                described_firewall={"id": SENTINEL_FIREWALL_ID,
                                                    "name": "wrong-project"})
        with self.assertRaises(lifecycle.SurfaceUnavailable):
            self._guards(provider=provider)

    def test_evaluating_guards_mutates_nothing(self) -> None:
        provider = FakeProvider(surfaces=live_surfaces())
        self._guards(provider=provider)
        provider.assert_read_only(self)


# ── Lock ──────────────────────────────────────────────────────────────────────

class LockTest(unittest.TestCase):

    def setUp(self) -> None:
        self.path = Path(tempfile.mkdtemp()) / "state.json"

    def test_a_lock_held_by_a_live_process_is_refused(self) -> None:
        lock = teardown.Lock(self.path)
        lock.path.write_text(str(os.getppid()))
        with self.assertRaises(teardown.TeardownError):
            lock.acquire()

    def test_a_stale_lock_from_a_dead_process_does_not_wedge_the_lifecycle(self) -> None:
        lock = teardown.Lock(self.path)
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        lock.path.write_text(str(dead.pid))
        lock.acquire()
        self.assertEqual(str(os.getpid()), lock.path.read_text())

    def test_a_corrupt_lock_is_not_treated_as_held(self) -> None:
        lock = teardown.Lock(self.path)
        lock.path.parent.mkdir(parents=True, exist_ok=True)
        lock.path.write_text("not-a-pid")
        lock.acquire()

    def test_release_only_removes_this_process_lock(self) -> None:
        lock = teardown.Lock(self.path)
        lock.path.parent.mkdir(parents=True, exist_ok=True)
        lock.path.write_text("999999999")
        lock.release()
        self.assertTrue(lock.path.exists())


# ── Apply: refusals ───────────────────────────────────────────────────────────

class ApplyRefusalTest(unittest.TestCase):

    def test_a_stale_generation_refuses_before_any_mutation(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            moved = {**fixture.state, "generation": fixture.state["generation"] + 1}
            mutator, tailscale = FakeMutator(), FakeTailscale()
            with self.assertRaises(teardown.TeardownError):
                fixture.apply(state=moved, mutator=mutator, tailscale=tailscale)
            self.assertEqual([], mutator.calls)
            self.assertEqual([], tailscale.calls)

    def test_a_changed_configuration_refuses_before_any_mutation(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            changed = {**fixture.tree.config, "location": "fsn1"}
            mutator = FakeMutator()
            with self.assertRaises(teardown.TeardownError):
                fixture.apply(config=changed, mutator=mutator)
            self.assertEqual([], mutator.calls)

    def test_a_tampered_plan_refuses_before_any_mutation(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            tampered = {**fixture.plan,
                        "targets": [{"kind": "server", "id": 1}]}
            mutator = FakeMutator()
            with self.assertRaises(lifecycle.PlanError):
                fixture.apply(plan=tampered, mutator=mutator)
            self.assertEqual([], mutator.calls)

    def test_a_held_lock_refuses_before_any_mutation(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            teardown.Lock(fixture.state_path).path.write_text(str(os.getppid()))
            mutator = FakeMutator()
            with self.assertRaises(teardown.TeardownError):
                fixture.apply(mutator=mutator)
            self.assertEqual([], mutator.calls)

    def test_a_failing_guard_refuses_before_any_mutation(self) -> None:
        with TeardownFixture("READY") as fixture:
            mutator, tailscale = FakeMutator(), FakeTailscale()
            with self.assertRaises(teardown.TeardownError):
                fixture.apply(mutator=mutator, tailscale=tailscale,
                              probes=FakeProbes(dirty=True),
                              provider=FakeProvider(surfaces=live_surfaces()))
            self.assertEqual([], mutator.calls)
            self.assertEqual([], tailscale.calls)

    def test_the_lock_is_released_even_when_teardown_refuses(self) -> None:
        with TeardownFixture("READY") as fixture:
            with self.assertRaises(teardown.TeardownError):
                fixture.apply(probes=FakeProbes(dirty=True),
                              provider=FakeProvider(surfaces=live_surfaces()))
            self.assertFalse(teardown.Lock(fixture.state_path).path.exists())


# ── Apply: the happy path ─────────────────────────────────────────────────────

class ApplySuccessTest(unittest.TestCase):

    def test_a_clean_teardown_reaches_absent_verified(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            receipt = fixture.apply()
            self.assertEqual("PASS", receipt["verdict"])
            self.assertEqual("down", receipt["operation"])
            self.assertEqual("ABSENT_VERIFIED", fixture.saved()["primary"]["phase"])

    def test_the_receipt_validates_against_the_committed_schema(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            lifecycle.validate(fixture.apply(),
                               lifecycle.load_schema("receipt.schema.json"))

    def test_the_receipt_records_who_authorized_the_destruction(self) -> None:
        """A receipt that omits this cannot answer "who destroyed it".

        The plan hash says *what* was destroyed and the verdict says whether it
        was proven; neither says on whose authority. Once an unattended run can
        reach this path, that is the question a reader will have.
        """
        with TeardownFixture("TRUST_PENDING") as fixture:
            approval = {"schema_version": 1,
                        "plan_hash": fixture.plan["plan_hash"],
                        "operation": "down", "approved_by": "the-agent",
                        "approved_at": "2026-08-11T09:00:00Z",
                        "reason": "lease expired"}
            path = fixture.state_path.parent / "approval.json"
            path.write_text(json.dumps(approval))
            receipt = fixture.apply(authority=lifecycle.authorize(
                fixture.plan, approval_path=path, terminal_present=False))
            lifecycle.validate(receipt,
                               lifecycle.load_schema("receipt.schema.json"))
            self.assertEqual("approval", receipt["authority"]["kind"])
            self.assertEqual("the-agent", receipt["authority"]["approved_by"])
            self.assertEqual("lease expired", receipt["authority"]["reason"])

    def test_deletion_is_by_exact_id_with_no_selector_or_glob(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            mutator = FakeMutator()
            fixture.apply(mutator=mutator)
            self.assertIn(("delete_server", str(SERVER_ID)), mutator.calls)
            for call in mutator.calls:
                for part in call:
                    self.assertNotIn("--selector", part)
                    self.assertNotIn("*", part)

    def test_the_state_passes_through_destroying_before_absent(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            phases = []
            original = provision.record

            def spy(path, state, **updates):
                if "phase" in updates:
                    phases.append(updates["phase"])
                return original(path, state, **updates)

            provision.record = spy
            try:
                fixture.apply()
            finally:
                provision.record = original
            self.assertEqual(["DESTROYING", "ABSENT_VERIFIED"], phases)

    def test_a_workspace_is_stopped_and_deleted_without_force(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            name = fixture.tree.config["devpod"]["workspace_name"]
            probes = FakeProbes(workspaces=[name])
            fixture.apply(probes=probes)
            self.assertIn(("devpod_stop_and_delete", name), probes.calls)

    def test_a_missing_workspace_is_not_an_error(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            probes = FakeProbes(workspaces=[])
            receipt = fixture.apply(probes=probes)
            self.assertEqual("PASS", receipt["verdict"])
            self.assertNotIn(("devpod_stop_and_delete",
                              fixture.tree.config["devpod"]["workspace_name"]),
                             probes.calls)

    def test_an_already_deleted_primary_ip_is_not_deleted_again(self) -> None:
        """With ipv4_auto_delete the address goes with the server, so a second
        delete would fail on a resource that is already correctly gone."""
        with TeardownFixture("TRUST_PENDING") as fixture:
            mutator = FakeMutator()
            mutator.describe_primary_ip = lambda _id: None
            fixture.apply(mutator=mutator)
            self.assertNotIn(("delete_primary_ip", str(PRIMARY_IP_ID)), mutator.calls)


# ── Apply: proving absence ────────────────────────────────────────────────────

class AbsenceTest(unittest.TestCase):

    def test_a_surviving_server_is_a_failure_not_a_success(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            provider = _StagedProvider(before=live_surfaces(),
                                       after=live_surfaces())
            with self.assertRaises(teardown.TeardownError):
                fixture.apply(provider=provider)
            self.assertEqual("FAILED", fixture.saved()["primary"]["phase"])

    def test_an_unreadable_surface_after_deletion_is_not_verified(self) -> None:
        """A delete call that returned 0 is not evidence the resource is gone."""
        with TeardownFixture("TRUST_PENDING") as fixture:
            blind = dict(live_surfaces(server=False, primary_ip=False))
            blind["servers"] = RuntimeError("api down")
            provider = _StagedProvider(before=live_surfaces(), after=blind)
            with self.assertRaises(teardown.TeardownError) as caught:
                fixture.apply(provider=provider)
            self.assertIn("NOT_VERIFIED", str(caught.exception))
            # The phase matters more than the exception, and this assertion is
            # what was missing. The raise happens *after* state is written, so
            # dropping NOT_VERIFIED from the phase decision left the exception
            # intact while recording ABSENT_VERIFIED -- a durable claim that
            # absence was proven by a read that never succeeded. A later
            # `up --plan` proceeds happily from that state.
            self.assertEqual("FAILED", fixture.saved()["primary"]["phase"])

    def test_a_preview_only_trusted_host_tears_down_without_attestation(self) -> None:
        """cinderwell-hns: TRUSTED never rehydrated, so G3 is vacuous. A
        preview-only host must not force --work-attested for a workspace that
        the phase already proves was never created."""
        with TeardownFixture("TRUSTED") as fixture:
            # Even with an "unreachable" probe, G3 does not consult SSH at
            # TRUSTED -- the phase is the evidence.
            receipt = fixture.apply(probes=FakeProbes(unreachable=True))
            self.assertEqual("PASS", receipt["verdict"])
            guard = next(r for r in receipt["results"]
                         if r["id"] == "G3_work_preserved")
            self.assertEqual("PASS", guard["status"])
            self.assertIn("vacuous", guard["detail"])
            self.assertEqual("ABSENT_VERIFIED",
                             fixture.saved()["primary"]["phase"])

    def test_an_unreachable_ready_host_can_be_destroyed_on_a_written_attestation(self) -> None:
        """The deadlock this resolves is real and was hit three times live.

        A READY host that has become unreachable cannot be destroyed by `down`
        -- the work guards are mandatory at that phase and need SSH -- nor by
        `abort-up`, which does not accept READY. A billable machine with no
        route out is a worse outcome than a recorded human decision.
        """
        with TeardownFixture("READY") as fixture:
            probes = FakeProbes(unreachable=True)
            receipt = fixture.apply(probes=probes,
                                    work_attested="host unreachable since 02:10; "
                                                  "workspace was a clean clone")
            self.assertEqual("NOT_VERIFIED", receipt["verdict"])
            guard = next(r for r in receipt["results"]
                         if r["id"] == "G3_work_preserved")
            self.assertEqual("NOT_VERIFIED", guard["status"])
            self.assertIn("clean clone", guard["detail"])
            self.assertEqual("ABSENT_VERIFIED",
                             fixture.saved()["primary"]["phase"])

    def test_without_an_attestation_an_unreachable_ready_host_still_refuses(self) -> None:
        with TeardownFixture("READY") as fixture:
            with self.assertRaises(teardown.GuardNotVerified):
                fixture.apply(probes=FakeProbes(unreachable=True))

    def test_an_attestation_never_overrides_a_guard_that_ran_and_refused(self) -> None:
        """The distinction the whole design rests on. "I could not check" is
        attestable. "I checked and the host holds unpushed work" is not, and no
        wording in an attestation may turn it into permission."""
        with TeardownFixture("READY") as fixture:
            with self.assertRaises(teardown.TeardownError) as raised:
                fixture.apply(probes=FakeProbes(dirty=True),
                              work_attested="I really do want this gone")
            self.assertIn("uncommitted or unpushed", str(raised.exception))
            self.assertNotEqual("ABSENT_VERIFIED",
                                fixture.saved()["primary"]["phase"])

    def test_absence_that_could_not_be_read_is_never_recorded_as_proven(self) -> None:
        """ABSENT_VERIFIED means "absence proven by a fresh read". It is the one
        phase a new server may be planned from, so writing it on the strength of
        a read that failed is the most expensive lie this module could tell.

        Stated as its own test rather than left to the verdict check, because
        those two guards do different jobs: one decides what is written to disk,
        the other decides whether to raise. Relying on the second to cover the
        first means a later edit to the verdict logic silently removes this.
        """
        with TeardownFixture("TRUST_PENDING") as fixture:
            blind = dict(live_surfaces(server=False, primary_ip=False))
            blind["servers"] = RuntimeError("api down")
            with self.assertRaises(teardown.TeardownError):
                fixture.apply(provider=_StagedProvider(before=live_surfaces(),
                                                       after=blind))
            saved = fixture.saved()["primary"]["phase"]
            self.assertNotEqual("ABSENT_VERIFIED", saved)
            self.assertEqual("FAILED", saved)

    def test_a_tailscale_outage_still_deletes_the_billable_server(self) -> None:
        with TeardownFixture("TRUST_PENDING") as fixture:
            mutator = FakeMutator()
            tailscale = FakeTailscale(fail_on="delete_key")
            with self.assertRaises(teardown.TeardownError):
                fixture.apply(mutator=mutator, tailscale=tailscale)
            self.assertIn(("delete_server", str(SERVER_ID)), mutator.calls)
            self.assertEqual("FAILED", fixture.saved()["primary"]["phase"])


class _StagedProvider(FakeProvider):
    """Reports one set of surfaces before deletion and another afterwards."""

    def __init__(self, *, before: dict, after: dict) -> None:
        self._stages = [before, after]
        super().__init__(surfaces=before)

    def inventory(self) -> dict:
        self._surfaces = self._stages.pop(0) if self._stages else self._surfaces
        return super().inventory()


# ── Command line ──────────────────────────────────────────────────────────────

class CommandLineTest(unittest.TestCase):

    def test_apply_requires_an_explicit_timestamp(self) -> None:
        """A receipt whose time is generated inside the run cannot be
        re-derived; it must be an input like the run id."""
        import inspect
        signature = inspect.signature(teardown.apply_down)
        self.assertIn("recorded_at", signature.parameters)
        self.assertIs(inspect.Parameter.empty,
                      signature.parameters["recorded_at"].default)

    def test_there_is_no_force_flag_anywhere(self) -> None:
        source = (REPOSITORY_ROOT / "cinderwell" / "teardown.py").read_text()
        code = "\n".join(line for line in source.splitlines()
                         if not line.strip().startswith("#"))
        self.assertNotIn('"--force"', code)
        self.assertNotIn("'--force'", code)
        self.assertIn("--force-delete=false", code)


if __name__ == "__main__":
    unittest.main()
