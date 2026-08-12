"""Tests for the read-only ephemeral-server lifecycle planner (unit S2).

Every provider surface is faked. No test in this file may touch a real provider,
and the FakeProvider records every command it is asked to run so the read-only
property is asserted rather than assumed.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPOSITORY_ROOT / "cinderwell" / "resources"
EXAMPLE_CONFIG = REPOSITORY_ROOT / "examples" / "config.example.json"
sys.path.insert(0, str(REPOSITORY_ROOT))

from cinderwell import lifecycle  # noqa: E402
# Any hcloud verb that could change provider state. If a planning path ever
# emits one of these, the read-only guarantee is broken and the test fails.
MUTATING_VERBS = {"create", "delete", "remove", "update", "attach", "detach",
                  "rebuild", "reset", "poweroff", "poweron", "reboot", "enable",
                  "disable", "add-", "change-", "set-"}


def example_config() -> dict:
    return json.loads((REPOSITORY_ROOT / "examples" /
                       "config.example.json").read_text())


# The sentinel that binds a credential to one project. Read from the committed
# example so the fakes cannot drift away from the shipped contract.
SENTINEL_FIREWALL_ID: int = example_config()["firewall_id"]
SENTINEL_FIREWALL_NAME: str = example_config()["firewall_name"]


# The instant every fixture plan is measured from. An input rather than now(),
# so a plan built in a test has the same hash tomorrow.
PLANNED_AT = "2026-08-11T09:00:00Z"


def _unreachable_runner(argv: tuple[str, ...]) -> subprocess.CompletedProcess:
    """A runner that must never be called. Refusal has to precede any read."""
    raise AssertionError(f"no command should have run: {' '.join(argv)}")


# The real receipt, byte-identical to the object committed at
# refs/recovery/wks-95/factory-baseline:docs/proofs/v1/<run>.json (blob
# 9ef50e9432f3297f2675b1ce100d3ff765c228ae). Kept as a fixture so the gate is
def pricing(currency: str = "USD", hourly: str = "0.0160000000",
            monthly: str = "8.9900000000", location: str = "hel1") -> dict:
    return {
        "currency": currency,
        "primary_ips": [{"type": "ipv4", "prices": [
            {"location": location,
             "price_hourly": {"net": "0.0010000000"},
             "price_monthly": {"net": "0.6000000000"}}]}],
    }


def server_type_prices(location: str = "hel1", hourly: str = "0.0160000000",
                       monthly: str = "8.9900000000") -> dict:
    return {"name": "cx33", "prices": [
        {"location": location,
         "price_hourly": {"net": hourly},
         "price_monthly": {"net": monthly}}]}


class FakeProvider(lifecycle.Provider):
    """A Provider whose every read is scripted and recorded."""

    def __init__(self, *, surfaces: dict | None = None,
                 server_type: dict | None = None,
                 price_book: dict | None = None,
                 context: str | None = "example-context",
                 active_context: str | None = None,
                 described_firewall: Any = None,
                 assertion: dict | None = None) -> None:
        self.commands: list[tuple[str, ...]] = []
        self._surfaces = surfaces if surfaces is not None else {
            "servers": [], "volumes": [], "primary_ips": [], "floating_ips": [],
            "firewalls": [{"id": SENTINEL_FIREWALL_ID, "name": SENTINEL_FIREWALL_NAME}],
            "ssh_keys": [], "snapshots": [],
        }
        self._server_type = server_type if server_type is not None else server_type_prices()
        self._price_book = price_book if price_book is not None else pricing()
        self._active_context = active_context if active_context is not None else (
            context or "")
        self._described_firewall = (described_firewall if described_firewall is not None
                                    else {"id": SENTINEL_FIREWALL_ID,
                                          "name": SENTINEL_FIREWALL_NAME})
        super().__init__(context, runner=self._run,
                         pricing_reader=lambda: self._price_book,
                         project_assertion=(assertion if assertion is not None
                                            else lifecycle.project_assertion(
                                                example_config())))

    def _run(self, argv: tuple[str, ...]) -> subprocess.CompletedProcess:
        self.commands.append(argv)
        joined = " ".join(argv)
        if argv[:2] == ("hcloud", "context"):
            return subprocess.CompletedProcess(argv, 0, self._active_context, "")
        if "describe" in argv and "firewall" in argv:
            if isinstance(self._described_firewall, Exception):
                return subprocess.CompletedProcess(
                    argv, 1, "", str(self._described_firewall))
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(self._described_firewall), "")
        for name, command in lifecycle.INVENTORY_SURFACES:
            if all(part in argv for part in command):
                payload = self._surfaces.get(name)
                if isinstance(payload, Exception):
                    return subprocess.CompletedProcess(argv, 1, "", str(payload))
                return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        if "server-type" in argv:
            return subprocess.CompletedProcess(argv, 0, json.dumps(self._server_type), "")
        raise AssertionError(f"unscripted command: {joined}")

    def assert_read_only(self, test: unittest.TestCase) -> None:
        for command in self.commands:
            for part in command:
                test.assertFalse(
                    any(part.startswith(verb) or part == verb.rstrip("-")
                        for verb in MUTATING_VERBS),
                    f"planning issued a mutating command: {' '.join(command)}")


class TemporaryTree:
    """A scratch directory holding a config."""

    def __init__(self, config: dict | None = None):
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        merged = config if config is not None else example_config()
        self.config_path = self.root / "config.json"
        self.config_path.write_text(json.dumps(merged))
        self.config = merged

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self._temporary.cleanup()


def authority_for(plan: dict) -> dict:
    """The authority a plan would carry when applied at an operator's terminal.

    Built by the real `authorize` rather than hand-written, so every test that
    applies a plan drives the function that decides whether it may be applied.
    A literal dict here would let `authorize` rot untested while three hundred
    tests kept passing -- the fake-that-answers-regardless shape that five of
    this project's defects had.
    """
    return lifecycle.authorize(plan, approval_path=None, terminal_present=True)


# ── Canonical hashing ─────────────────────────────────────────────────────────

class CanonicalHashingTest(unittest.TestCase):

    def test_key_order_does_not_change_the_digest(self) -> None:
        self.assertEqual(lifecycle.digest({"a": 1, "b": {"c": 2, "d": 3}}),
                         lifecycle.digest({"b": {"d": 3, "c": 2}, "a": 1}))

    def test_any_value_change_changes_the_digest(self) -> None:
        base = {"server": {"type": "cx33", "image_id": 1}}
        for mutation in ({"server": {"type": "cx43", "image_id": 1}},
                         {"server": {"type": "cx33", "image_id": 2}},
                         {"server": {"type": "cx33", "image_id": 1, "extra": None}}):
            self.assertNotEqual(lifecycle.digest(base), lifecycle.digest(mutation))

    def test_plan_hash_verifies_and_rejects_edits(self) -> None:
        with TemporaryTree() as tree:
            provider = FakeProvider()
            plan = lifecycle.plan_up(tree.config, lifecycle.empty_state(
                lifecycle.digest(tree.config)), provider, "run-001",
                planned_at=PLANNED_AT)
            lifecycle.verify_plan_hash(plan)
            plan["server"]["type"] = "cx43"
            with self.assertRaises(lifecycle.PlanError):
                lifecycle.verify_plan_hash(plan)


# ── Redaction ─────────────────────────────────────────────────────────────────

class RedactionTest(unittest.TestCase):

    def test_secret_shaped_values_are_redacted(self) -> None:
        for secret in ("tskey-auth-abc123DEF456",
                       "Bearer abcdefghijklmnop",
                       "a" * 48):
            self.assertIn("[REDACTED]", lifecycle.redact(f"prefix {secret} suffix"))

    def test_a_secret_fetching_command_survives_redaction(self) -> None:
        """A pointer is not a secret. Redacting the command that fetches a
        token would leave an operator unable to debug a wrong path."""
        command = "your-secret-tool read tailscale/oauth-client-secret"
        self.assertEqual(command, lifecycle.redact(command))


# ── Configuration ─────────────────────────────────────────────────────────────

class ConfigurationTest(unittest.TestCase):

    def _write(self, config: dict) -> Path:
        directory = Path(tempfile.mkdtemp())
        path = directory / "config.json"
        path.write_text(json.dumps(config))
        return path

    def test_the_committed_example_validates(self) -> None:
        config = lifecycle.load_config(
            EXAMPLE_CONFIG)
        self.assertEqual(1, config["schema_version"])

    def test_mutable_image_name_is_rejected(self) -> None:
        for name in ("latest", "ubuntu-24.04"):
            config = {**example_config(), "image_id": name}
            with self.assertRaises(lifecycle.ConfigError):
                lifecycle.load_config(self._write(config))

    def test_unknown_key_is_rejected(self) -> None:
        config = {**example_config(), "surprise": True}
        with self.assertRaises(lifecycle.ConfigError):
            lifecycle.load_config(self._write(config))

    def test_literal_credential_is_rejected_but_a_command_is_accepted(self) -> None:
        config = example_config()
        config["tailscale"] = {
            **config["tailscale"],
            "oauth_client_secret_command": ["echo", "tskey-auth-abc123DEF456xyz"]}
        with self.assertRaises(lifecycle.ConfigError):
            lifecycle.load_config(self._write(config))
        lifecycle.load_config(self._write(example_config()))

    def test_key_expiry_above_ten_minutes_is_rejected(self) -> None:
        config = example_config()
        config["tailscale"] = {**config["tailscale"], "key_expiry_seconds": 3600}
        with self.assertRaises(lifecycle.ConfigError):
            lifecycle.load_config(self._write(config))

    def test_zero_spend_ceiling_is_rejected(self) -> None:
        config = example_config()
        config["spend_envelope"] = {**config["spend_envelope"], "max_hourly": 0}
        with self.assertRaises(lifecycle.ConfigError):
            lifecycle.load_config(self._write(config))

    def test_missing_file_and_malformed_json_are_typed(self) -> None:
        with self.assertRaises(lifecycle.ConfigError):
            lifecycle.load_config(Path("/nonexistent/config.json"))
        directory = Path(tempfile.mkdtemp())
        broken = directory / "config.json"
        broken.write_text("{not json")
        with self.assertRaises(lifecycle.ConfigError):
            lifecycle.load_config(broken)


# ── State ─────────────────────────────────────────────────────────────────────

class StateTest(unittest.TestCase):

    def test_absent_state_is_synthesized_when_no_file_exists(self) -> None:
        state = lifecycle.load_state(Path("/nonexistent/state.json"), "a" * 64)
        self.assertEqual("ABSENT", state["primary"]["phase"])
        self.assertEqual(0, state["generation"])

    def test_state_from_a_different_config_is_refused(self) -> None:
        directory = Path(tempfile.mkdtemp())
        path = directory / "state.json"
        path.write_text(json.dumps(lifecycle.empty_state("b" * 64)))
        with self.assertRaises(lifecycle.StateError):
            lifecycle.load_state(path, "a" * 64)

    def test_corrupt_state_is_refused(self) -> None:
        directory = Path(tempfile.mkdtemp())
        path = directory / "state.json"
        path.write_text("{broken")
        with self.assertRaises(lifecycle.StateError):
            lifecycle.load_state(path, "a" * 64)

    def test_unknown_phase_is_refused(self) -> None:
        directory = Path(tempfile.mkdtemp())
        path = directory / "state.json"
        state = lifecycle.empty_state("a" * 64)
        state["primary"]["phase"] = "MOSTLY_GONE"
        path.write_text(json.dumps(state))
        with self.assertRaises(lifecycle.StateError):
            lifecycle.load_state(path, "a" * 64)

    def test_generation_must_advance(self) -> None:
        previous = {**lifecycle.empty_state("a" * 64), "generation": 5}
        for generation in (5, 4, 0):
            candidate = {**previous, "generation": generation}
            with self.assertRaises(lifecycle.StateError):
                lifecycle.assert_generation_advances(previous, candidate)
        lifecycle.assert_generation_advances(previous, {**previous, "generation": 6})


# ── Inventory ─────────────────────────────────────────────────────────────────

class InventoryTest(unittest.TestCase):

    def test_every_surface_is_read(self) -> None:
        provider = FakeProvider()
        surfaces = provider.inventory()
        self.assertEqual({name for name, _ in lifecycle.INVENTORY_SURFACES},
                         set(surfaces))
        self.assertTrue(all(result["status"] == "PASS" for result in surfaces.values()))
        provider.assert_read_only(self)

    def test_a_failed_surface_is_not_verified_not_empty_success(self) -> None:
        provider = FakeProvider(surfaces={
            "servers": [], "volumes": RuntimeError("api down"), "primary_ips": [],
            "floating_ips": [], "firewalls": [], "ssh_keys": [], "snapshots": []})
        surfaces = provider.inventory()
        self.assertEqual("NOT_VERIFIED", surfaces["volumes"]["status"])
        self.assertNotIn("count", surfaces["volumes"])
        self.assertEqual("PASS", surfaces["servers"]["status"])

    def test_malformed_output_is_not_verified(self) -> None:
        provider = FakeProvider()

        def broken(argv):
            provider.commands.append(argv)
            return subprocess.CompletedProcess(argv, 0, "<html>not json</html>", "")

        provider._runner = broken
        surfaces = provider.inventory()
        self.assertTrue(all(result["status"] == "NOT_VERIFIED"
                            for result in surfaces.values()))

    def test_non_array_output_is_not_verified(self) -> None:
        provider = FakeProvider(surfaces={
            name: ({"unexpected": "object"} if name == "servers" else [])
            for name, _ in lifecycle.INVENTORY_SURFACES})
        self.assertEqual("NOT_VERIFIED", provider.inventory()["servers"]["status"])

    def test_summaries_carry_identity_only(self) -> None:
        provider = FakeProvider(surfaces={
            "servers": [{"id": 1, "name": "a", "labels": {},
                         "public_net": {"ipv4": {"ip": "203.0.113.9"}}}],
            "volumes": [], "primary_ips": [], "floating_ips": [],
            "firewalls": [], "ssh_keys": [], "snapshots": []})
        item = provider.inventory()["servers"]["items"][0]
        self.assertEqual({"id", "name", "labels"}, set(item))


# ── Account identity ──────────────────────────────────────────────────────────

class AccountVerificationTest(unittest.TestCase):

    def test_wrong_active_context_is_refused(self) -> None:
        provider = FakeProvider(context="example-context", active_context="production")
        with self.assertRaises(lifecycle.SurfaceUnavailable):
            provider.verify_account()

    def test_matching_context_passes(self) -> None:
        FakeProvider().verify_account()

    def test_ambient_token_fallback_does_not_count_as_verification(self) -> None:
        """Observed live: `hcloud --context missing server list` exits 0.

        The CLI only warns on stderr and then falls back to whatever HCLOUD_TOKEN
        is in the environment. A caller that trusted the exit code would plan --
        and later create -- against an unintended account. `hcloud context active`
        returns empty in that situation, so an empty active context must be
        treated as unverified rather than as agreement.
        """
        provider = FakeProvider(context="example-context", active_context="")
        with self.assertRaises(lifecycle.SurfaceUnavailable):
            provider.verify_account()

    def test_a_null_context_never_passes_an_empty_context_name(self) -> None:
        """`--context ''` selects a context named the empty string, not 'none'."""
        provider = FakeProvider(context=None)
        with mock.patch.dict(os.environ, {"HCLOUD_TOKEN": "x"}, clear=False):
            provider.verify_account()
        self.assertTrue(provider.commands)
        for command in provider.commands:
            self.assertNotIn("--context", command)

    def test_a_null_context_without_a_token_is_refused(self) -> None:
        provider = FakeProvider(context=None)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(lifecycle.SurfaceUnavailable):
                provider.verify_account()

    def test_the_project_assertion_is_what_actually_proves_identity(self) -> None:
        """A matching context label with the wrong project must still refuse.

        This is the whole point of the assertion. A context name is a local
        label an operator chose; it is not evidence about which Hetzner project
        the token can reach.
        """
        provider = FakeProvider(
            described_firewall={"id": SENTINEL_FIREWALL_ID,
                                "name": "somebody-elses-firewall"})
        with self.assertRaises(lifecycle.SurfaceUnavailable):
            provider.verify_account()

    def test_an_undescribable_sentinel_is_refused(self) -> None:
        provider = FakeProvider(described_firewall=RuntimeError("not found"))
        with self.assertRaises(lifecycle.SurfaceUnavailable):
            provider.verify_account()

    def test_a_provider_without_an_assertion_refuses_rather_than_skips(self) -> None:
        provider = lifecycle.Provider("example-context", runner=_unreachable_runner)
        with self.assertRaises(lifecycle.ConfigError):
            provider.verify_account()

    def test_provider_for_always_carries_the_assertion(self) -> None:
        provider = lifecycle.provider_for(example_config())
        self.assertEqual({"firewall_id": SENTINEL_FIREWALL_ID,
                          "firewall_name": SENTINEL_FIREWALL_NAME},
                         provider.project_assertion)

    def test_verifying_the_account_mutates_nothing(self) -> None:
        provider = FakeProvider()
        provider.verify_account()
        provider.assert_read_only(self)


# ── Pricing ───────────────────────────────────────────────────────────────────

class PricingTest(unittest.TestCase):

    def test_spend_sums_server_and_primary_ip(self) -> None:
        spend = lifecycle.compute_spend(example_config(), FakeProvider())
        self.assertEqual("USD", spend["currency"])
        self.assertAlmostEqual(0.017, spend["hourly"], places=6)
        self.assertAlmostEqual(9.59, spend["monthly"], places=6)
        self.assertTrue(spend["within_envelope"])

    def test_currency_mismatch_is_refused(self) -> None:
        with self.assertRaises(lifecycle.PlanError):
            lifecycle.compute_spend(example_config(),
                                    FakeProvider(price_book=pricing(currency="EUR")))

    def test_unpriced_location_is_refused(self) -> None:
        with self.assertRaises(lifecycle.SurfaceUnavailable):
            lifecycle.compute_spend(
                example_config(),
                FakeProvider(server_type=server_type_prices(location="ash")))

    def test_unpriced_primary_ip_is_refused(self) -> None:
        book = pricing()
        book["primary_ips"] = []
        with self.assertRaises(lifecycle.SurfaceUnavailable):
            lifecycle.compute_spend(example_config(), FakeProvider(price_book=book))

    def test_missing_price_field_is_refused(self) -> None:
        broken = {"name": "cx33", "prices": [{"location": "hel1"}]}
        with self.assertRaises(lifecycle.SurfaceUnavailable):
            lifecycle.compute_spend(example_config(), FakeProvider(server_type=broken))

    def test_ipv4_is_not_priced_when_disabled(self) -> None:
        config = example_config()
        config["public_net"] = {**config["public_net"], "enable_ipv4": False}
        spend = lifecycle.compute_spend(config, FakeProvider())
        self.assertEqual(1, len(spend["lines"]))


# ── v1 advancement gate ───────────────────────────────────────────────────────


# ── Planning ──────────────────────────────────────────────────────────────────

class PlanTest(unittest.TestCase):

    def _plan(self, provider: FakeProvider, tree: TemporaryTree,
              run_id: str = "run-001") -> dict:
        state = lifecycle.empty_state(lifecycle.digest(tree.config))
        return lifecycle.plan_up(tree.config, state, provider, run_id,
                                  planned_at=PLANNED_AT)

    def test_a_clean_plan_is_produced_and_mutates_nothing(self) -> None:
        with TemporaryTree() as tree:
            provider = FakeProvider()
            plan = self._plan(provider, tree)
            self.assertEqual("up", plan["operation"])
            self.assertEqual("cinderwell-run-001", plan["server"]["name"])
            self.assertEqual(100000001, plan["server"]["image_id"])
            self.assertEqual(100000002, plan["server"]["firewall_id"])
            lifecycle.verify_plan_hash(plan)
            provider.assert_read_only(self)

    def test_planning_is_deterministic_for_identical_inputs(self) -> None:
        with TemporaryTree() as tree:
            first = self._plan(FakeProvider(), tree)
            second = self._plan(FakeProvider(), tree)
            self.assertEqual(first["plan_hash"], second["plan_hash"])

    def test_changed_inputs_change_the_plan_hash(self) -> None:
        with TemporaryTree() as tree:
            baseline = self._plan(FakeProvider(), tree)["plan_hash"]
            self.assertNotEqual(baseline, self._plan(FakeProvider(), tree,
                                                     run_id="run-002")["plan_hash"])
            drifted = FakeProvider(surfaces={
                "servers": [], "volumes": [{"id": 9, "name": "new"}],
                "primary_ips": [], "floating_ips": [],
                "firewalls": [{"id": 100000002, "name": "fw"}],
                "ssh_keys": [], "snapshots": []})
            self.assertNotEqual(baseline, self._plan(drifted, tree)["plan_hash"])

    def test_unreadable_surface_blocks_planning(self) -> None:
        with TemporaryTree() as tree:
            provider = FakeProvider(surfaces={
                "servers": [], "volumes": [], "primary_ips": [], "floating_ips": [],
                "firewalls": [{"id": 100000002, "name": "fw"}],
                "ssh_keys": RuntimeError("unavailable"), "snapshots": []})
            with self.assertRaises(lifecycle.PlanError):
                self._plan(provider, tree)

    def test_concurrency_ceiling_blocks_a_second_server(self) -> None:
        with TemporaryTree() as tree:
            provider = FakeProvider(surfaces={
                "servers": [{"id": 1, "name": "cinderwell-run-000"}],
                "volumes": [], "primary_ips": [], "floating_ips": [],
                "firewalls": [{"id": 100000002, "name": "fw"}],
                "ssh_keys": [], "snapshots": []})
            with self.assertRaises(lifecycle.PlanError):
                self._plan(provider, tree)

    def test_missing_firewall_blocks_planning(self) -> None:
        with TemporaryTree() as tree:
            provider = FakeProvider(surfaces={
                "servers": [], "volumes": [], "primary_ips": [], "floating_ips": [],
                "firewalls": [], "ssh_keys": [], "snapshots": []})
            with self.assertRaises(lifecycle.PlanError):
                self._plan(provider, tree)

    def test_over_envelope_spend_blocks_planning(self) -> None:
        with TemporaryTree() as tree:
            provider = FakeProvider(
                server_type=server_type_prices(hourly="9.0", monthly="900.0"))
            with self.assertRaises(lifecycle.PlanError):
                self._plan(provider, tree)

    def test_a_config_granting_no_ssh_key_blocks_planning(self) -> None:
        """Refused at plan time, before anything exists and bills.

        A host created without an authorized key cannot be provisioned,
        rehydrated, or torn down through its own work guards -- the first live
        run reached TRUSTED and then had to be destroyed by setting the phase by
        hand. Learning that from a plan costs nothing.
        """
        with TemporaryTree() as tree:
            tree.config["ssh"]["key_ids"] = []
            with self.assertRaises(lifecycle.PlanError) as raised:
                self._plan(FakeProvider(), tree)
            self.assertIn("ssh.key_ids", str(raised.exception))

    def test_the_plan_records_which_keys_get_access(self) -> None:
        """Who may log into the machine belongs in the hash, so it is approved
        rather than discovered."""
        with TemporaryTree() as tree:
            plan = self._plan(FakeProvider(), tree)
            self.assertEqual([100000003], plan["server"]["ssh_key_ids"])
            lifecycle.verify_plan_hash(plan)

    def test_non_absent_phase_blocks_planning(self) -> None:
        with TemporaryTree() as tree:
            state = lifecycle.empty_state(lifecycle.digest(tree.config))
            state["primary"]["phase"] = "READY"
            with self.assertRaises(lifecycle.PlanError):
                lifecycle.plan_up(tree.config, state, FakeProvider(), "run-001",
                                  planned_at=PLANNED_AT)

    def test_wrong_context_blocks_planning(self) -> None:
        with TemporaryTree() as tree:
            with self.assertRaises(lifecycle.SurfaceUnavailable):
                self._plan(FakeProvider(active_context="production"), tree)

    def test_invalid_run_id_is_refused(self) -> None:
        with TemporaryTree() as tree:
            for run_id in ("", "A", "no", "Run-001", "run_001", "x" * 80):
                with self.assertRaises(lifecycle.PlanError):
                    self._plan(FakeProvider(), tree, run_id=run_id)

    def test_plan_carries_no_secret_material(self) -> None:
        """A plan may contain digests, and nothing else that is long and opaque.

        Asserting `redact(plan) == plan` would be wrong: the redactor treats any
        long alphanumeric run as secret-shaped, and sha256 digests are exactly
        that. So check the property that actually matters — every long token in
        the plan is a digest, and no credential appears at all.
        """
        with TemporaryTree() as tree:
            plan = self._plan(FakeProvider(), tree)
            serialized = json.dumps(plan)
            self.assertNotIn("tskey-", serialized)
            self.assertNotIn("your-secret-tool", serialized)
            for token in re.findall(r"[A-Za-z0-9]{40,}", serialized):
                self.assertRegex(token, r"^[0-9a-f]{64}$",
                                 f"unexplained opaque value in plan: {token}")


# ── Receipts ──────────────────────────────────────────────────────────────────

class ReceiptTest(unittest.TestCase):

    def test_verdict_can_never_exceed_the_worst_result(self) -> None:
        cases = (
            ([{"id": "a", "status": "PASS"}], "PASS"),
            ([{"id": "a", "status": "PASS"}, {"id": "b", "status": "NOT_VERIFIED"}],
             "NOT_VERIFIED"),
            ([{"id": "a", "status": "NOT_VERIFIED"}, {"id": "b", "status": "FAIL"}],
             "FAIL"),
        )
        for results, expected in cases:
            receipt = lifecycle.build_receipt("run-001", "inventory", results,
                                              "2026-08-10T00:00:00Z")
            self.assertEqual(expected, receipt["verdict"])

    def test_receipt_shape_is_enforced(self) -> None:
        with self.assertRaises(lifecycle.SchemaError):
            lifecycle.build_receipt("Run-001", "inventory",
                                    [{"id": "a", "status": "PASS"}],
                                    "2026-08-10T00:00:00Z")


# ── Command line ──────────────────────────────────────────────────────────────

class CommandLineTest(unittest.TestCase):

    def test_there_is_no_apply_verb(self) -> None:
        """The read-only guarantee is structural, not a flag someone can flip."""
        source = (REPOSITORY_ROOT / "cinderwell" / "lifecycle.py").read_text()
        self.assertNotIn('"--apply"', source)
        self.assertNotIn("'--apply'", source)

    def test_validate_reports_the_config_digest(self) -> None:
        with TemporaryTree() as tree:
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = lifecycle.main(["--config", str(tree.config_path),
                                       "--state", str(tree.root / "state.json"),
                                       "validate"])
            self.assertEqual(0, code)
            self.assertEqual("ABSENT", json.loads(captured.getvalue())["phase"])

    def test_unknown_subcommand_exits_nonzero(self) -> None:
        with TemporaryTree() as tree:
            with self.assertRaises(SystemExit):
                lifecycle.main(["--config", str(tree.config_path), "destroy"])

    def test_bad_config_exits_two_without_traceback(self) -> None:
        directory = Path(tempfile.mkdtemp())
        path = directory / "config.json"
        path.write_text("{broken")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(2, lifecycle.main(["--config", str(path),
                                                "--state", str(directory / "state.json"),
                                                "validate"]))

    def test_state_reading_commands_use_the_machine_default_path(self) -> None:
        """Omitting --state loads $XDG_STATE_HOME/factory/host.json — proven by
        seeding READY there and asserting status reports it without --state."""
        for command in ("validate", "status"):
            with self.subTest(command=command), TemporaryTree() as tree:
                with tempfile.TemporaryDirectory() as xdg_state:
                    host = Path(xdg_state) / "cinderwell" / "host.json"
                    host.parent.mkdir(parents=True)
                    config = lifecycle.load_config(tree.config_path)
                    digest = lifecycle.digest(config)
                    primary = {"phase": "ABSENT"}
                    if command == "status":
                        primary = {
                            "phase": "READY",
                            "run_id": "run-seed",
                            "server_id": 900001,
                        }
                    host.write_text(json.dumps({
                        "schema_version": 1,
                        "generation": 1,
                        "config_digest": digest,
                        "primary": primary,
                    }))
                    env = {**os.environ, "XDG_STATE_HOME": xdg_state}
                    previous = Path.cwd()
                    clean = Path(xdg_state) / "cwd"
                    clean.mkdir()
                    try:
                        os.chdir(clean)
                        with mock.patch.dict(os.environ, env, clear=False):
                            with contextlib.redirect_stdout(io.StringIO()) as out:
                                with contextlib.redirect_stderr(io.StringIO()) as err:
                                    code = lifecycle.main([
                                        "--config", str(tree.config_path),
                                        command,
                                    ])
                    finally:
                        os.chdir(previous)
                    self.assertEqual(0, code, out.getvalue() + err.getvalue())
                    if command == "status":
                        payload = json.loads(out.getvalue())
                        self.assertEqual("READY", payload["primary"]["phase"])


    def test_planning_without_existing_state_uses_absent_at_the_named_path(self) -> None:
        """Planning against a named empty state path is ABSENT for that path —
        the danger was inventing ABSENT when no path was named at all."""
        with TemporaryTree() as tree, tempfile.TemporaryDirectory() as td:
            state = Path(td) / "host.json"
            with mock.patch.object(lifecycle, "provider_for") as provider_for:
                provider_for.return_value = FakeProvider()
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    code = lifecycle.main([
                        "--config", str(tree.config_path),
                        "--state", str(state),
                        "up", "--plan", "--run-id", "run-a",
                        "--planned-at", PLANNED_AT,
                    ])
            self.assertEqual(0, code, out.getvalue())
            plan = json.loads(out.getvalue())
            self.assertIn("plan_hash", plan)

    def test_inventory_remains_stateless(self) -> None:
        """Inventory reads the provider, not the record, so requiring a state
        file there would be ceremony rather than safety."""
        with TemporaryTree() as tree:
            provider = FakeProvider()
            with mock.patch.object(lifecycle, "provider_for", return_value=provider):
                with contextlib.redirect_stdout(io.StringIO()) as captured:
                    code = lifecycle.main(["--config", str(tree.config_path),
                                           "inventory"])
            self.assertEqual(0, code)
            self.assertIn("servers", json.loads(captured.getvalue()))


if __name__ == "__main__":
    unittest.main()
