#!/usr/bin/env python3
"""Tests for authority as an artifact (unit U2).

The property under test is that **no plan is applied without something that
names it**. Before this unit the mutating scripts applied a plan for anyone who
could repeat its hash, and the hash is printed on screen; the only thing
standing between an agent and a live provider call was a `read < /dev/tty` in
the justfile, which is not a security property at all -- it is a proxy for "a
human is present".

So the tests below come in two layers, and both matter:

* `authorize` decides *whether* there is authority, at the edge, where
  terminal-ness is knowable.
* `assert_authorized` decides whether the authority that arrived belongs to the
  plan about to be applied, at the mutation. A guard that exists only at the
  entry point is a guard the next entry point silently does without.

Standard library only, matching the rest of this suite.
"""

from __future__ import annotations

import ast
import inspect
import json
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

from cinderwell import approve  # noqa: E402
from cinderwell import lifecycle  # noqa: E402
from cinderwell import provision  # noqa: E402
from cinderwell import teardown  # noqa: E402
APPROVED_AT = "2026-08-11T09:00:00Z"
APPROVED_BY = "operator"


def plan(operation: str = "down", **extra) -> dict:
    """A minimal but genuinely hash-bound plan.

    Built through `digest` rather than with a literal hash, so a change to the
    canonical serialization moves these fixtures with it instead of leaving them
    silently approving nothing.
    """
    body = {"operation": operation, "schema_version": 1, "run_id": "run-001",
            **extra}
    return {**body, "plan_hash": lifecycle.digest(body)}


def approval_for(subject: dict, **overrides) -> dict:
    approval = {"schema_version": 1, "plan_hash": subject["plan_hash"],
                "operation": subject["operation"], "approved_by": APPROVED_BY,
                "approved_at": APPROVED_AT}
    approval.update(overrides)
    return {key: value for key, value in approval.items() if value is not None}


def first_statement(function) -> str:
    """The first executable statement of a function, docstring excluded.

    Parsed rather than pattern-matched on lines: a multi-line signature and a
    multi-line docstring both look like statements to a line filter, and the
    first attempt at this test asserted against a fragment of `apply_up`'s
    parameter list.
    """
    body = ast.parse(textwrap.dedent(inspect.getsource(function))).body[0].body
    if (isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    return ast.unparse(body[0])


def code_without_docstrings(function) -> str:
    """Source with docstrings removed, for tests that assert on the code.

    A structural assertion that reads the docstring too will fail the moment
    the docstring explains what the code deliberately does not do -- which is
    exactly the kind of comment this project writes.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Module)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                node.body = body[1:]
    return ast.unparse(tree)


class Written:
    """A scratch directory holding a plan and, usually, an approval."""

    def __init__(self, approval: dict | None = None, raw: str | None = None):
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.path = self.root / "approval.json"
        if raw is not None:
            self.path.write_text(raw)
        elif approval is not None:
            self.path.write_text(json.dumps(approval))

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self._temporary.cleanup()


# ── The contract itself ───────────────────────────────────────────────────────

class SchemaTest(unittest.TestCase):
    """The authority shape is written down three times. Prove it is one shape.

    `approval.schema.json` is the source of truth; the state and receipt
    schemas carry copies because the small validator here supports only local
    `$ref`. Three copies of a contract is three chances for it to drift, and
    drift here would mean a record that state accepts and a receipt rejects --
    discovered at teardown, on a live host. The list lives in one place for the
    same reason: a copy added later and checked nowhere is the drift this test
    exists to catch.
    """

    COPIES = ("state.schema.json", "receipt.schema.json")

    @staticmethod
    def fragment(name: str) -> dict:
        return json.loads((SCHEMA_DIR / name
                           ).read_text())["definitions"]["authority"]

    def test_all_copies_of_the_authority_shape_are_identical(self) -> None:
        canonical = self.fragment("approval.schema.json")
        for name in self.COPIES:
            with self.subTest(schema=name):
                self.assertEqual(lifecycle.canonical_json(canonical),
                                 lifecycle.canonical_json(self.fragment(name)))

    def test_the_copies_are_actually_wired_up(self) -> None:
        """Identical definitions prove nothing if nothing points at them.

        Replacing both `$ref`s with `{"type": "object"}` left the whole suite
        green, because `assert_authorized` reads the definition directly. But
        the schemas are the durable contract and the code is not: after that
        change `save_state` and `build_receipt` would have written
        `{"kind": "assumed", ...}` -- the exact record another test here
        exists to reject -- into state and into a receipt.
        """
        reference = {"$ref": "#/definitions/authority"}
        state = json.loads((SCHEMA_DIR /
                            "state.schema.json").read_text())
        receipt = json.loads((SCHEMA_DIR /
                              "receipt.schema.json").read_text())
        self.assertEqual(
            reference,
            {"$ref": state["definitions"]["host_record"]["properties"]
                     ["authority"]["$ref"]})
        self.assertEqual(reference, receipt["properties"]["authority"])

    def test_each_schema_rejects_an_invented_authority(self) -> None:
        """The property the wiring exists for, asserted through the validator.

        Stronger than comparing `$ref` strings: this fails for a schema that
        points at the right definition and for one that does not, so it cannot
        be satisfied by pointing somewhere plausible.
        """
        invented = {"kind": "assumed", "operation": "down",
                    "plan_hash": "0" * 64}
        for name, instance in (
                ("state.schema.json",
                 {"schema_version": 1, "generation": 1,
                  "config_digest": "0" * 64,
                  "primary": {"phase": "TRUSTED", "authority": invented}}),
                ("receipt.schema.json",
                 {"schema_version": 1, "run_id": "run-001",
                  "recorded_at": APPROVED_AT, "operation": "down",
                  "results": [{"id": "G1", "status": "PASS"}],
                  "verdict": "PASS", "authority": invented})):
            with self.subTest(schema=name):
                with self.assertRaises(lifecycle.SchemaError):
                    lifecycle.validate(instance, lifecycle.load_schema(name))

    def test_the_operations_an_approval_may_name_are_the_ones_that_exist(self) -> None:
        """An approval for an operation no plan produces would be unusable, and
        a plan whose operation no approval may name would be unapprovable."""
        schema = json.loads((SCHEMA_DIR /
                             "approval.schema.json").read_text())
        self.assertEqual(
            {"up", "abort-up", "down"},
            set(schema["definitions"]["operation"]["enum"]))

    def test_the_authority_copies_name_the_same_operations(self) -> None:
        """The enum appears twice in each schema: once for what an approval may
        say, and once inside the authority record it produces. They are
        deliberately the same list, because an operation an approval may name
        and an authority record may not carry is one that can be approved and
        never applied.
        """
        schema = json.loads((SCHEMA_DIR /
                             "approval.schema.json").read_text())
        self.assertEqual(
            set(schema["definitions"]["operation"]["enum"]),
            set(schema["definitions"]["authority"]["properties"]
                ["operation"]["enum"]))


# ── authorize ───────────────────────────────────────────────────────────────────────────

class AuthorizeTest(unittest.TestCase):

    def test_an_approval_naming_this_plan_authorizes_it(self) -> None:
        subject = plan()
        with Written(approval_for(subject)) as written:
            authority = lifecycle.authorize(subject, approval_path=written.path,
                                            terminal_present=False)
        self.assertEqual("approval", authority["kind"])
        self.assertEqual(subject["plan_hash"], authority["plan_hash"])
        self.assertEqual(APPROVED_BY, authority["approved_by"])

    def test_an_approval_for_a_different_plan_is_refused_by_name(self) -> None:
        """The central property. An approval is bound to the bytes it saw.

        Asserted on the message as well as the refusal, because a refusal for
        some other reason -- a malformed file, a missing field -- would pass a
        bare assertRaises while leaving this guard untested.
        """
        subject, other = plan(), plan(run_id="run-002")
        self.assertNotEqual(subject["plan_hash"], other["plan_hash"])
        with Written(approval_for(other)) as written:
            with self.assertRaises(lifecycle.ApprovalError) as raised:
                lifecycle.authorize(subject, approval_path=written.path,
                                    terminal_present=False)
        self.assertIn(other["plan_hash"], str(raised.exception))
        self.assertIn(subject["plan_hash"], str(raised.exception))

    def test_an_approval_for_another_operation_is_refused(self) -> None:
        subject = plan("down")
        with Written(approval_for(subject, operation="up")) as written:
            with self.assertRaises(lifecycle.ApprovalError) as raised:
                lifecycle.authorize(subject, approval_path=written.path,
                                    terminal_present=False)
        self.assertIn("'up'", str(raised.exception))

    def test_a_schema_invalid_approval_is_refused(self) -> None:
        subject = plan()
        for description, approval in (
                ("no approver", approval_for(subject, approved_by=None)),
                ("empty approver", approval_for(subject, approved_by="")),
                ("unknown operation", approval_for(subject, operation="destroy")),
                ("truncated hash", approval_for(subject, plan_hash="abc123")),
                ("unknown field", approval_for(subject, force=True)),
                ("wrong version", approval_for(subject, schema_version=2))):
            with self.subTest(description):
                with Written(approval) as written:
                    with self.assertRaises(lifecycle.ApprovalError):
                        lifecycle.authorize(subject, approval_path=written.path,
                                            terminal_present=False)

    def test_a_malformed_approval_is_refused(self) -> None:
        with Written(raw="{not json") as written:
            with self.assertRaises(lifecycle.ApprovalError):
                lifecycle.authorize(plan(), approval_path=written.path,
                                    terminal_present=False)

    def test_a_missing_approval_file_is_refused_rather_than_ignored(self) -> None:
        """Silently falling through to the terminal check would mean a typo in
        the path quietly turned an unattended run into a prompt -- or, with a
        terminal present, into an approval nobody made."""
        with Written() as written:
            with self.assertRaises(lifecycle.ApprovalError):
                lifecycle.authorize(plan(), approval_path=written.path,
                                    terminal_present=True)

    def test_a_terminal_authorizes_when_no_approval_is_supplied(self) -> None:
        subject = plan()
        authority = lifecycle.authorize(subject, approval_path=None,
                                        terminal_present=True)
        self.assertEqual("terminal", authority["kind"])
        self.assertEqual(subject["plan_hash"], authority["plan_hash"])
        self.assertNotIn("approved_by", authority)

    def test_neither_a_terminal_nor_an_approval_refuses(self) -> None:
        """The mutation this whole unit exists to prevent.

        Delete the final `raise` in `authorize` and this is the test that goes
        red; without it, an unattended run with no approval would mutate a live
        provider on the strength of a hash printed on screen.
        """
        with self.assertRaises(lifecycle.ApprovalError) as raised:
            lifecycle.authorize(plan(), approval_path=None,
                                terminal_present=False)
        self.assertIn("cinderwell approve", str(raised.exception))

    def test_a_hand_edited_plan_cannot_be_authorized_at_all(self) -> None:
        """Not even at a terminal. The hash is the plan's identity, so a plan
        whose body no longer matches its hash has no identity to approve."""
        tampered = {**plan(), "run_id": "run-999"}
        with self.assertRaises(lifecycle.PlanError):
            lifecycle.authorize(tampered, approval_path=None,
                                terminal_present=True)


# ── assert_authorized ─────────────────────────────────────────────────────────

class AssertAuthorizedTest(unittest.TestCase):
    """The inner seam: what arrives at the mutation must name what is mutating."""

    def test_an_authority_for_another_plan_is_refused(self) -> None:
        subject, other = plan(), plan(run_id="run-002")
        stolen = lifecycle.authorize(other, approval_path=None,
                                     terminal_present=True)
        with self.assertRaises(lifecycle.ApprovalError):
            lifecycle.assert_authorized(subject, stolen)

    def test_an_authority_for_another_operation_is_refused(self) -> None:
        subject = plan("down")
        authority = lifecycle.authorize(subject, approval_path=None,
                                        terminal_present=True)
        with self.assertRaises(lifecycle.ApprovalError):
            lifecycle.assert_authorized(plan("up"), {**authority,
                                                     "plan_hash": plan("up")["plan_hash"]})

    def test_an_invented_authority_record_is_refused(self) -> None:
        subject = plan()
        for description, authority in (
                ("not a mapping", "yes"),
                ("nothing at all", None),
                ("no kind", {"plan_hash": subject["plan_hash"],
                             "operation": "down"}),
                ("invented kind", {"kind": "assumed",
                                   "plan_hash": subject["plan_hash"],
                                   "operation": "down"})):
            with self.subTest(description):
                with self.assertRaises(lifecycle.ApprovalError):
                    lifecycle.assert_authorized(subject, authority)

    def test_every_apply_path_requires_an_authority(self) -> None:
        """Structural, and deliberately so.

        A behavioural test proves the three paths that exist today check it. This
        proves the *next* one cannot be written without it -- which is the
        failure mode, since `apply_abort` and `apply_down` were themselves added
        one at a time to a module that already had guards.
        """
        for function in (provision.apply_up, provision.apply_abort,
                         teardown.apply_down):
            with self.subTest(function=function.__name__):
                parameter = inspect.signature(function).parameters.get("authority")
                self.assertIsNotNone(
                    parameter, f"{function.__name__} takes no authority")
                self.assertIs(inspect.Parameter.empty, parameter.default,
                              f"{function.__name__} makes authority optional")
                self.assertIs(inspect.Parameter.KEYWORD_ONLY, parameter.kind,
                              f"{function.__name__} accepts authority "
                              f"positionally, where a caller can pass the "
                              f"wrong thing without noticing")

    def test_every_apply_path_checks_it_before_anything_else(self) -> None:
        """The check must precede the provider calls, not follow them.

        `apply_up` records intent to state and mints a Tailscale key before it
        reaches the provider; an authority check placed after that would refuse
        a run that had already burned a credential.
        """
        for module, name in ((provision, "apply_up"), (provision, "apply_abort"),
                             (teardown, "apply_down")):
            with self.subTest(function=name):
                self.assertEqual("lifecycle.assert_authorized(plan, authority)",
                                 first_statement(getattr(module, name)),
                                 f"{name} does something before checking "
                                 f"authority")


# ── The terminal probe ────────────────────────────────────────────────────────

class TerminalTest(unittest.TestCase):

    def test_an_unopenable_device_means_no_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(lifecycle.has_controlling_terminal(
                str(Path(directory) / "not-a-device")))

    def test_it_asks_dev_tty_and_not_stdin(self) -> None:
        """The interactive confirm reads from `/dev/tty`. Asking stdin instead would
        answer a different question the moment a recipe redirected it."""
        self.assertIn("/dev/tty", inspect.signature(
            lifecycle.has_controlling_terminal).parameters["path"].default)
        self.assertNotIn("isatty",
                         code_without_docstrings(lifecycle.has_controlling_terminal))

    def test_an_openable_file_means_a_terminal_is_reachable(self) -> None:
        """The positive branch, so the function is not merely proven to say no.

        A version that returned False unconditionally would satisfy every other
        test here and would make the human path unreachable.
        """
        with tempfile.TemporaryDirectory() as directory:
            openable = Path(directory) / "stand-in"
            openable.write_text("")
            self.assertTrue(lifecycle.has_controlling_terminal(str(openable)))


# ── approve.py ────────────────────────────────────────────────────────────────

class ApproveTest(unittest.TestCase):

    def test_an_approval_it_writes_authorizes_its_plan(self) -> None:
        """The round trip. The two halves of this unit are written separately
        and could disagree about the shape they exchange."""
        subject = plan("up")
        built = approve.build_approval(subject, approved_by=APPROVED_BY,
                                       approved_at=APPROVED_AT, reason="ci")
        with Written(built) as written:
            authority = lifecycle.authorize(subject, approval_path=written.path,
                                            terminal_present=False)
        self.assertEqual("approval", authority["kind"])
        self.assertEqual("ci", authority["reason"])

    def test_a_plan_that_fails_its_own_hash_cannot_be_approved(self) -> None:
        """Refused at approval time, not merely at apply time.

        A tampered plan would be refused later either way -- but an approval for
        it would sit on disk looking legitimate until someone tried to use it.
        """
        with self.assertRaises(lifecycle.PlanError):
            approve.build_approval({**plan(), "run_id": "run-999"},
                                   approved_by=APPROVED_BY,
                                   approved_at=APPROVED_AT)

    def test_it_refuses_a_plan_with_no_operation(self) -> None:
        body = {"schema_version": 1, "run_id": "run-001"}
        with self.assertRaises(lifecycle.ApprovalError):
            approve.build_approval({**body, "plan_hash": lifecycle.digest(body)},
                                   approved_by=APPROVED_BY,
                                   approved_at=APPROVED_AT)

    def test_the_written_file_is_not_world_writable(self) -> None:
        """An approval any process can rewrite authorizes whatever it was last
        edited to say."""
        with tempfile.TemporaryDirectory() as directory:
            target = approve.write_approval(Path(directory) / "a.json",
                                            approval_for(plan()))
            self.assertEqual(0o600, target.stat().st_mode & 0o777)

    def test_the_command_line_writes_beside_the_plan_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            subject = plan("abort-up")
            plan_path = Path(directory) / "abort-up-plan.json"
            plan_path.write_text(json.dumps(subject))
            code = approve.main(["--plan-file", str(plan_path),
                                 "--approved-by", APPROVED_BY,
                                 "--approved-at", APPROVED_AT])
            self.assertEqual(0, code)
            written = Path(directory) / "abort-up-plan.approval.json"
            self.assertEqual(subject["plan_hash"],
                             json.loads(written.read_text())["plan_hash"])

    def test_the_command_line_refuses_a_tampered_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "plan.json"
            plan_path.write_text(json.dumps({**plan(), "run_id": "run-999"}))
            self.assertEqual(2, approve.main(
                ["--plan-file", str(plan_path), "--approved-by", APPROVED_BY,
                 "--approved-at", APPROVED_AT]))

    def test_it_creates_nothing_and_reads_no_credential(self) -> None:
        """Structural. Approving is a local decision about bytes on disk; a
        provider call in this module would make reviewing a plan a billable
        act."""
        source = (REPOSITORY_ROOT / "cinderwell" / "approve.py").read_text()
        for forbidden in ("hcloud", "HCLOUD_TOKEN", "TAILSCALE_API_TOKEN",
                          "subprocess"):
            self.assertNotIn(forbidden, source)


# ── End to end, with no terminal at all ───────────────────────────────────────

class UnattendedTest(unittest.TestCase):
    """The acceptance shape for R1, at the level this unit can reach.

    A real end-to-end run needs a provider. What is provable here is the part
    that used to be impossible: reaching the mutation with stdin closed, no
    controlling terminal, and nobody to type -- and being refused when nothing
    authorizes the plan.
    """

    def run_detached(self, *arguments: str) -> subprocess.CompletedProcess:
        """Run with stdin closed and no controlling terminal.

        `start_new_session=True` detaches the child from the terminal, so
        `/dev/tty` genuinely cannot be opened -- rather than being mocked into
        saying so, which would prove only that the mock works.
        """
        return subprocess.run(
            [sys.executable, *arguments], cwd=REPOSITORY_ROOT,
            capture_output=True, text=True, check=False,
            stdin=subprocess.DEVNULL, start_new_session=True)

    def test_without_a_terminal_the_probe_reports_no_terminal(self) -> None:
        result = self.run_detached(
            "-c", "import sys; sys.path.insert(0, '.'); "
                  "from cinderwell import lifecycle; print(lifecycle.has_controlling_terminal())")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("False", result.stdout.strip())

    def test_a_detached_teardown_with_no_approval_refuses_before_any_provider_call(self) -> None:
        """The refusal must arrive before the credential check, not after.

        `teardown.py` reads config, then state, then authorizes, then talks to
        Hetzner. If authority were checked last, an unattended run with no
        approval would still have made provider calls before being told no.
        """
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "down-plan.json"
            subject = plan("down")
            plan_path.write_text(json.dumps(subject))
            result = self.run_detached(
                "-m", "cinderwell", "teardown",
                "--config", str(EXAMPLE_CONFIG),
                "--state", str(Path(directory) / "state.json"),
                "down", "--apply", subject["plan_hash"],
                "--plan-file", str(plan_path),
                "--recorded-at", APPROVED_AT)
        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("no controlling terminal", result.stderr)

    def test_an_approval_gets_a_detached_run_past_the_gate_and_no_further(self) -> None:
        """Both halves of R1 in one comparison, which is the only honest way.

        A test that only proves the refusal cannot tell "the gate works" from
        "nothing works". A test that only proves the approval path proceeds
        cannot tell "authority was established" from "authority was skipped".
        So: the same detached invocation twice, differing only in `--approval`,
        and the two must fail for *different* reasons -- authority first, and
        then whatever the next real check happens to be.

        The second failure being a plain `TeardownError` rather than a success
        is the point: an approval opens exactly one gate and weakens nothing
        behind it.
        """
        with tempfile.TemporaryDirectory() as directory:
            subject = plan("down")
            plan_path = Path(directory) / "down-plan.json"
            plan_path.write_text(json.dumps(subject))
            approval_path = approve.write_approval(
                Path(directory) / "down.approval.json", approval_for(subject))

            arguments = ["-m", "cinderwell", "teardown",
                         "--config", str(EXAMPLE_CONFIG),
                         "--state", str(Path(directory) / "state.json"),
                         "down", "--apply", subject["plan_hash"],
                         "--plan-file", str(plan_path),
                         "--recorded-at", APPROVED_AT]
            refused = self.run_detached(*arguments)
            allowed = self.run_detached(*arguments, "--approval",
                                        str(approval_path))

        self.assertIn("ApprovalError", refused.stderr)
        self.assertNotIn("ApprovalError", allowed.stderr)
        self.assertIn("TeardownError", allowed.stderr)

    def test_the_environment_cannot_smuggle_authority_in(self) -> None:
        """There is no APPROVED-style environment escape hatch.

        Structural, because the tempting fix for an agent that cannot get an
        approval onto disk is an environment variable -- and an environment
        variable is exactly the thing a plan hash was chosen over.
        """
        for name in ("lifecycle.py", "provision.py", "teardown.py",
                     "approve.py", "reaper.py"):
            source = (REPOSITORY_ROOT / "cinderwell" / name).read_text()
            code = "\n".join(line for line in source.splitlines()
                             if not line.strip().startswith("#"))
            for smuggled in ("APPROV", "AUTHORIZ", "AUTHORITY"):
                for reference in (f'environ.get("{smuggled}',
                                  f"environ.get('{smuggled}",
                                  f'environ["{smuggled}'):
                    self.assertNotIn(reference, code.upper().replace(
                        "OS.ENVIRON", "environ"), f"{name} reads {smuggled}")


if __name__ == "__main__":
    unittest.main()
