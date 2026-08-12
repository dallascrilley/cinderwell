"""Tests for ephemeral server provisioning and fail-closed abort (unit S3).

Nothing here touches a real provider or a real Tailscale tailnet. The fakes
record every call so that ordering claims -- intent recorded before mutation,
deletion only by exact recorded ID -- are asserted rather than described.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from cinderwell import lifecycle  # noqa: E402
from cinderwell import provision  # noqa: E402
from test_lifecycle import (PLANNED_AT, FakeProvider, TemporaryTree,  # noqa: E402
                            authority_for, example_config)

KEY_SECRET = "tskey-auth-FAKE0000notarealkey0000"


def _optional_yaml():
    """Return a YAML module if one is importable, else None.

    The lifecycle itself is standard-library only, so PyYAML is not a
    dependency. Where it is present these tests use it to prove the rendered
    cloud-init is a well-formed document; where it is absent they skip loudly
    rather than quietly assert less.
    """
    try:
        import yaml
        return yaml
    except ImportError:
        return None


class FakeTailscale(provision.TailscaleClient):
    """Scripted Tailscale API. Records every call in order."""

    def __init__(self, *, capabilities: dict | None = None,
                 devices: list | None = None,
                 fail_on: str | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._capabilities = capabilities if capabilities is not None else {
            "reusable": False, "ephemeral": True, "tags": ["tag:cinderwell"]}
        self._devices = devices if devices is not None else []
        self._fail_on = fail_on
        super().__init__("example.ts.net", token_reader=lambda: "fake-token",
                         opener=self._opener)

    def _opener(self, request):
        raise AssertionError("no test may reach the real Tailscale API")

    def create_auth_key(self, tag, expiry_seconds):
        self.calls.append(("create_auth_key", tag, str(expiry_seconds)))
        if self._fail_on == "create_auth_key":
            raise lifecycle.SurfaceUnavailable("tailscale unavailable")
        granted = self._capabilities
        if granted.get("reusable") is not False:
            raise provision.ProvisionError("Tailscale returned a reusable key")
        if granted.get("ephemeral") is not True:
            raise provision.ProvisionError("Tailscale returned a non-ephemeral key")
        if tag not in (granted.get("tags") or []):
            raise provision.ProvisionError(f"Tailscale key is not scoped to {tag}")
        return "key-abc123", KEY_SECRET

    def delete_key(self, key_id):
        self.calls.append(("delete_key", key_id))
        if self._fail_on == "delete_key":
            raise lifecycle.SurfaceUnavailable("tailscale unavailable")

    def find_device(self, hostname):
        self.calls.append(("find_device", hostname))
        return next((d for d in self._devices if d == hostname), None) and "dev-1"

    def delete_device(self, device_id):
        self.calls.append(("delete_device", device_id))


class FakeMutator(provision.Mutator):
    """Records every provider mutation and can fail at a chosen point."""

    def __init__(self, *, fail_on: str | None = None,
                 server_id: int = 900001, primary_ipv4_id: int | None = 900002,
                 survives_delete: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._fail_on = fail_on
        self._server_id = server_id
        self._primary_ipv4_id = primary_ipv4_id
        self.survives_delete = survives_delete
        self.created_user_data: str | None = None
        self.created_argv: list[str] = []
        super().__init__("example-context", runner=self._unusable)

    @staticmethod
    def _unusable(argv):
        raise AssertionError(f"no test may shell out to hcloud: {argv}")

    def create_server(self, *, name, server_type, image_id, location,
                      firewall_id, labels, user_data_path, public_net,
                      ssh_key_ids):
        # Recorded, not ignored. A fake that accepted the keys and dropped them
        # would let the whole point of passing them go untested -- which is the
        # shape of defect that produced a host nothing could log into.
        self.created_ssh_key_ids = list(ssh_key_ids)
        self.calls.append(("create_server", name, str(image_id), str(firewall_id)))
        self.created_user_data = Path(user_data_path).read_text()
        self.created_argv = [name, server_type, str(image_id), location,
                             str(firewall_id)]
        if self._fail_on == "create_server":
            raise provision.ProvisionError("server create rejected")
        public: dict = {}
        if self._primary_ipv4_id is not None:
            public = {"ipv4": {"id": self._primary_ipv4_id}}
        return {"id": self._server_id, "name": name, "public_net": public}

    def delete_server(self, server_id):
        self.calls.append(("delete_server", str(server_id)))
        if self._fail_on == "delete_server":
            raise provision.ProvisionError("server delete rejected")

    def describe_primary_ip(self, primary_ip_id):
        self.calls.append(("describe_primary_ip", str(primary_ip_id)))
        return ({"id": primary_ip_id} if primary_ip_id == self._primary_ipv4_id
                else None)

    def delete_primary_ip(self, primary_ip_id):
        self.calls.append(("delete_primary_ip", str(primary_ip_id)))
        if self._fail_on == "delete_primary_ip":
            raise provision.ProvisionError("primary ip delete rejected")


def build_plan(tree: TemporaryTree, provider: FakeProvider,
               run_id: str = "run-001") -> dict:
    state = lifecycle.empty_state(lifecycle.digest(tree.config))
    return lifecycle.plan_up(tree.config, state, provider, run_id,
                             planned_at=PLANNED_AT)


class ProvisionFixture:
    """A config, a plan, and a fresh state file on disk."""

    def __init__(self, **provider_kwargs):
        self.tree = TemporaryTree()
        self.provider = FakeProvider(**provider_kwargs)
        self.plan = build_plan(self.tree, self.provider)
        self.work = Path(tempfile.mkdtemp())
        self.state_path = self.work / "state.json"
        self.state = lifecycle.empty_state(lifecycle.digest(self.tree.config))

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.tree.__exit__()

    def apply(self, mutator=None, tailscale=None, provider=None,
              applied_at: str = PLANNED_AT):
        return provision.apply_up(
            self.tree.config, self.state, self.plan,
            state_path=self.state_path, provider=provider or self.provider,
            mutator=mutator or FakeMutator(), tailscale=tailscale or FakeTailscale(),
            work_dir=self.work, authority=authority_for(self.plan),
            applied_at=applied_at)

    def saved(self) -> dict:
        return json.loads(self.state_path.read_text())


# ── State persistence ─────────────────────────────────────────────────────────

class StatePersistenceTest(unittest.TestCase):

    def test_save_is_atomic_and_leaves_no_temporary(self) -> None:
        directory = Path(tempfile.mkdtemp())
        path = directory / "state.json"
        provision.save_state(path, lifecycle.empty_state("a" * 64))
        self.assertTrue(path.exists())
        self.assertEqual([], list(directory.glob("*.tmp")))

    def test_invalid_state_is_never_written(self) -> None:
        directory = Path(tempfile.mkdtemp())
        path = directory / "state.json"
        broken = lifecycle.empty_state("a" * 64)
        broken["primary"]["phase"] = "SORT_OF_GONE"
        with self.assertRaises(lifecycle.SchemaError):
            provision.save_state(path, broken)
        self.assertFalse(path.exists())

    def test_record_advances_the_generation_every_time(self) -> None:
        directory = Path(tempfile.mkdtemp())
        path = directory / "state.json"
        state = lifecycle.empty_state("a" * 64)
        for expected in (1, 2, 3):
            state = provision.record(path, state, phase="PROVISIONING")
            self.assertEqual(expected, state["generation"])
            self.assertEqual(expected, json.loads(path.read_text())["generation"])


# ── Tailscale key capabilities ────────────────────────────────────────────────

class TailscaleKeyTest(unittest.TestCase):

    def test_reusable_key_is_refused(self) -> None:
        client = FakeTailscale(capabilities={"reusable": True, "ephemeral": True,
                                             "tags": ["tag:cinderwell"]})
        with self.assertRaises(provision.ProvisionError):
            client.create_auth_key("tag:cinderwell", 600)

    def test_non_ephemeral_key_is_refused(self) -> None:
        client = FakeTailscale(capabilities={"reusable": False, "ephemeral": False,
                                             "tags": ["tag:cinderwell"]})
        with self.assertRaises(provision.ProvisionError):
            client.create_auth_key("tag:cinderwell", 600)

    def test_wrong_tag_is_refused(self) -> None:
        client = FakeTailscale(capabilities={"reusable": False, "ephemeral": True,
                                             "tags": ["tag:something-else"]})
        with self.assertRaises(provision.ProvisionError):
            client.create_auth_key("tag:cinderwell", 600)

    def test_capabilities_are_read_back_from_the_response(self) -> None:
        """The real client must verify what it got, not what it asked for."""
        source = (REPOSITORY_ROOT / "cinderwell" / "provision.py").read_text()
        self.assertIn("granted.get(\"reusable\")", source)
        self.assertIn("granted.get(\"ephemeral\")", source)


# ── Cloud-init rendering ──────────────────────────────────────────────────────

class CloudInitTest(unittest.TestCase):

    def test_every_placeholder_is_substituted(self) -> None:
        rendered = provision.render_cloud_init(
            "run-001", "cinderwell-run-001", "tag:cinderwell", KEY_SECRET)
        self.assertNotIn("{{", rendered)
        self.assertIn("run-001", rendered)
        self.assertIn(KEY_SECRET, rendered)

    def test_unsubstituted_placeholder_is_refused(self) -> None:
        directory = Path(tempfile.mkdtemp())
        template = directory / "t.tmpl"
        template.write_text("hostname: {{HOSTNAME}}\nextra: {{UNEXPECTED}}\n")
        with self.assertRaises(provision.ProvisionError):
            provision.render_cloud_init("run-001", "h", "tag:t", KEY_SECRET,
                                        template_path=template)

    def test_template_never_enables_shell_tracing(self) -> None:
        """Check executable lines only.

        A naive substring search hits the comment that explains why tracing is
        absent, which would make this test pass for the wrong reason today and
        fail for the wrong reason if the comment were reworded.
        """
        executable = "\n".join(
            line for line in provision.TEMPLATE_PATH.read_text().splitlines()
            if not line.lstrip().startswith("#"))
        self.assertNotIn("set -x", executable)
        self.assertNotIn("set -o xtrace", executable)
        self.assertIn("set -euo pipefail", executable)

    def test_the_fingerprint_survives_the_boot_that_printed_it(self) -> None:
        """The defect this replaces made the trust channel a one-shot.

        The fingerprint went only to /dev/console. Those lines scroll past, and
        since Linux 5.9 the VT has no scrollback at all -- Shift+PageUp recovers
        nothing. On the first live run the console had already reached the login
        prompt by the time it was opened, which made the host permanently
        untrustable and fit only for destruction.

        /etc/issue is rendered by getty above every login prompt, on every tty,
        for as long as the host lives.
        """
        executable = "\n".join(
            line for line in provision.TEMPLATE_PATH.read_text().splitlines()
            if not line.lstrip().startswith("#"))
        self.assertIn("/etc/issue", executable)
        # Appended, never truncating: /etc/issue already carries the distro
        # banner, and clobbering it would be a gratuitous change to the host.
        self.assertIn(">> /etc/issue", executable)
        self.assertNotIn("> /etc/issue", executable.replace(">> /etc/issue", ""))

        issue_block = executable.split(">> /etc/issue")[0]
        for line in ("CINDERWELL-RUN-ID", "CINDERWELL-HOSTKEY", "CINDERWELL-HOSTKEY-HEX",
                     "CINDERWELL-KEY-SCRUB", "CINDERWELL-TAILSCALE"):
            with self.subTest(line=line):
                # Twice: once to the console as it boots, once where it stays.
                self.assertGreaterEqual(executable.count(line), 2)
                self.assertIn(line, issue_block)

    def test_the_fingerprint_is_also_emitted_in_an_unambiguous_encoding(self) -> None:
        """base64 collides at 80x25: l/1/I and O/0 cannot be told apart. A live
        console read produced a one-character mismatch indistinguishable from an
        attack. Hex has ten digits and six letters and none of them collide."""
        executable = "\n".join(
            line for line in provision.TEMPLATE_PATH.read_text().splitlines()
            if not line.lstrip().startswith("#"))
        self.assertIn("CINDERWELL-HOSTKEY-HEX", executable)
        self.assertIn("sha256sum", executable)
        # Both places it is emitted: the boot console and the durable banner.
        self.assertEqual(2, executable.count("CINDERWELL-HOSTKEY-HEX"))

    def test_template_does_not_pass_the_key_as_an_argument(self) -> None:
        """`--auth-key file:` keeps the secret out of argv and therefore /proc."""
        template = provision.TEMPLATE_PATH.read_text()
        self.assertIn('--auth-key "file:${KEY_FILE}"', template)
        self.assertNotIn('--auth-key "$(cat', template)

    def test_template_checks_for_residue_before_shredding(self) -> None:
        """grep -f must run while the key file still exists, or it checks nothing."""
        template = provision.TEMPLATE_PATH.read_text()
        self.assertLess(template.index("grep -qFf"), template.index("shred -u"))

    def test_rendered_template_is_well_formed_yaml(self) -> None:
        """A template that fails to parse only shows up after a real server boots."""
        yaml = _optional_yaml()
        if yaml is None:
            self.skipTest("no YAML parser available")
        rendered = provision.render_cloud_init(
            "run-001", "cinderwell-run-001", "tag:cinderwell", KEY_SECRET)
        document = yaml.safe_load(rendered)
        self.assertEqual({"hostname", "preserve_hostname", "runcmd", "write_files"},
                         set(document))
        files = {entry["path"]: entry for entry in document["write_files"]}
        key_file = files["/run/tailscale-bootstrap.key"]
        self.assertEqual("0600", key_file["permissions"])
        self.assertEqual(KEY_SECRET, key_file["content"].strip())

    def test_a_yaml_hostile_key_still_renders_correctly(self) -> None:
        """Emit the key as a JSON string so its content cannot break the document."""
        yaml = _optional_yaml()
        if yaml is None:
            self.skipTest("no YAML parser available")
        hostile = 'tskey: "auth" #comment\nnot_a_key: true'
        rendered = provision.render_cloud_init(
            "run-001", "host", "tag:cinderwell", hostile)
        document = yaml.safe_load(rendered)
        files = {entry["path"]: entry for entry in document["write_files"]}
        self.assertEqual(hostile, files["/run/tailscale-bootstrap.key"]["content"])
        self.assertNotIn("not_a_key", document)

    def test_bootstrap_script_is_valid_bash(self) -> None:
        yaml = _optional_yaml()
        if yaml is None:
            self.skipTest("no YAML parser available")
        rendered = provision.render_cloud_init(
            "run-001", "host", "tag:cinderwell", KEY_SECRET)
        document = yaml.safe_load(rendered)
        script = {entry["path"]: entry for entry in document["write_files"]
                  }["/usr/local/sbin/cinderwell-bootstrap.sh"]["content"]
        directory = Path(tempfile.mkdtemp())
        path = directory / "bootstrap.sh"
        path.write_text(script)
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True,
                                text=True)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_user_data_is_created_mode_600(self) -> None:
        directory = Path(tempfile.mkdtemp())
        path = provision.write_user_data(directory, "content")
        self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_user_data_will_not_silently_overwrite(self) -> None:
        directory = Path(tempfile.mkdtemp())
        provision.write_user_data(directory, "first")
        with self.assertRaises(FileExistsError):
            provision.write_user_data(directory, "second")


# ── Drift checks ──────────────────────────────────────────────────────────────

class MutatorArgvTest(unittest.TestCase):
    """Tests the real argv the Mutator builds.

    FakeMutator replaces create_server wholesale, so nothing else in this file
    ever looks at the flags actually sent to hcloud. That gap let
    `--primary-ipv4=auto` ship; the API rejected it live with
    "Primary IPv4 not found: auto", because that flag names an *existing*
    Primary IP and has no "auto" value.
    """

    def _argv(self, **public_net) -> list[str]:
        captured: list[tuple[str, ...]] = []

        def runner(argv):
            captured.append(argv)
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({"server": {"id": 1, "public_net": {}}}), "")

        settings = {"enable_ipv4": True, "enable_ipv6": True,
                    "ipv4_auto_delete": True, **public_net}
        with tempfile.TemporaryDirectory() as directory:
            user_data = Path(directory) / "user-data.yaml"
            user_data.write_text("#cloud-config\n")
            provision.Mutator("example-context", runner=runner).create_server(
                name="cinderwell-run-001", server_type="cx33",
                image_id=100000001, location="hel1", firewall_id=100000004,
                labels={"run-id": "run-001"}, user_data_path=user_data,
                public_net=settings, ssh_key_ids=[100000003])
        return list(captured[0])

    def test_no_flag_is_given_the_word_auto(self) -> None:
        self.assertNotIn("auto", " ".join(self._argv()))

    def test_a_public_ipv4_is_requested_by_default_not_by_naming_one(self) -> None:
        argv = self._argv()
        self.assertFalse([part for part in argv if part.startswith("--primary-ipv4")])
        self.assertFalse([part for part in argv if part.startswith("--without-ipv4")])

    def test_disabling_a_public_address_uses_the_negative_flag(self) -> None:
        argv = self._argv(enable_ipv4=False, enable_ipv6=False)
        self.assertIn("--without-ipv4=true", argv)
        self.assertIn("--without-ipv6=true", argv)

    def test_the_ssh_key_is_passed_by_id_in_the_create_request(self) -> None:
        """By ID, like the firewall and the image, so no key material reaches
        this repository -- and in the create request, so access exists from
        first boot rather than depending on cloud-init finishing."""
        argv = self._argv()
        self.assertIn("--ssh-key", argv)
        self.assertEqual("100000003", argv[argv.index("--ssh-key") + 1])

    def test_the_firewall_and_image_are_passed_by_id(self) -> None:
        argv = self._argv()
        self.assertEqual("100000004", argv[argv.index("--firewall") + 1])
        self.assertEqual("100000001", argv[argv.index("--image") + 1])

    def test_every_flag_exists_in_the_installed_hcloud(self) -> None:
        """The contract test for this class.

        Comparing against the CLI's own help is what turns "these flags look
        right" into "these flags exist". Skips loudly where hcloud is absent
        rather than asserting less.
        """
        try:
            help_text = subprocess.run(["hcloud", "server", "create", "--help"],
                                       capture_output=True, text=True, timeout=15,
                                       check=False).stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.skipTest("hcloud CLI is not installed")
        emitted = {part.split("=")[0] for part in
                   self._argv(enable_ipv4=False, enable_ipv6=False)
                   if part.startswith("--")}
        for flag in sorted(emitted):
            self.assertIn(flag, help_text, f"{flag} is not a flag hcloud accepts")


class DriftTest(unittest.TestCase):

    def test_edited_plan_is_refused(self) -> None:
        with ProvisionFixture() as fixture:
            fixture.plan["server"]["type"] = "cx43"
            with self.assertRaises(lifecycle.PlanError):
                fixture.apply()

    def test_changed_configuration_is_refused(self) -> None:
        with ProvisionFixture() as fixture:
            fixture.tree.config = {**fixture.tree.config, "location": "fsn1"}
            with self.assertRaises(lifecycle.PlanError):
                fixture.apply()

    def test_advanced_state_generation_is_refused(self) -> None:
        with ProvisionFixture() as fixture:
            fixture.state = {**fixture.state, "generation": 7}
            with self.assertRaises(lifecycle.PlanError):
                fixture.apply()

    def test_non_absent_phase_is_refused(self) -> None:
        with ProvisionFixture() as fixture:
            fixture.state["primary"]["phase"] = "READY"
            with self.assertRaises(lifecycle.PlanError):
                fixture.apply()

    def test_provider_drift_is_refused(self) -> None:
        with ProvisionFixture() as fixture:
            drifted = FakeProvider(surfaces={
                "servers": [{"id": 5, "name": "someone-elses-server"}],
                "volumes": [], "primary_ips": [], "floating_ips": [],
                "firewalls": [{"id": 100000002, "name": "fw"}],
                "ssh_keys": [], "snapshots": []})
            with self.assertRaises(lifecycle.PlanError):
                fixture.apply(provider=drifted)

    def test_context_is_reverified_at_apply_time(self) -> None:
        """The S2 finding: exit 0 from hcloud is not account verification."""
        with ProvisionFixture() as fixture:
            wrong = FakeProvider(active_context="production")
            with self.assertRaises(lifecycle.SurfaceUnavailable):
                fixture.apply(provider=wrong)

    def test_unreadable_surface_is_refused(self) -> None:
        with ProvisionFixture() as fixture:
            broken = FakeProvider(surfaces={
                "servers": [], "volumes": RuntimeError("down"), "primary_ips": [],
                "floating_ips": [], "firewalls": [{"id": 100000002, "name": "fw"}],
                "ssh_keys": [], "snapshots": []})
            with self.assertRaises(lifecycle.PlanError):
                fixture.apply(provider=broken)

    def test_no_mutation_occurs_when_a_precondition_fails(self) -> None:
        with ProvisionFixture() as fixture:
            fixture.plan["server"]["type"] = "cx43"
            mutator, tailscale = FakeMutator(), FakeTailscale()
            with self.assertRaises(lifecycle.PlanError):
                fixture.apply(mutator=mutator, tailscale=tailscale)
            self.assertEqual([], mutator.calls)
            self.assertEqual([], tailscale.calls)
            self.assertFalse(fixture.state_path.exists())


# ── Successful apply ──────────────────────────────────────────────────────────

class ApplyTest(unittest.TestCase):

    def test_apply_records_ids_and_stops_at_trust_pending(self) -> None:
        with ProvisionFixture() as fixture:
            mutator, tailscale = FakeMutator(), FakeTailscale()
            state = fixture.apply(mutator=mutator, tailscale=tailscale)
            primary = state["primary"]
            self.assertEqual("TRUST_PENDING", primary["phase"])
            self.assertEqual(900001, primary["server_id"])
            self.assertEqual(900002, primary["primary_ipv4_id"])
            self.assertEqual("key-abc123", primary["tailscale_key_id"])
            self.assertEqual("run-001", primary["run_id"])

    def test_apply_never_reaches_ready(self) -> None:
        """Trust belongs to S4. Reaching READY here would skip the host-key check."""
        with ProvisionFixture() as fixture:
            state = fixture.apply()
            self.assertNotEqual("READY", state["primary"]["phase"])

    def test_intent_is_recorded_before_the_provider_call(self) -> None:
        """A crash mid-create must leave a state file abort-up can act on."""
        with ProvisionFixture() as fixture:
            mutator = FakeMutator(fail_on="create_server")
            tailscale = FakeTailscale()
            with self.assertRaises(provision.ProvisionError):
                fixture.apply(mutator=mutator, tailscale=tailscale)
            saved = fixture.saved()
            self.assertEqual("FAILED", saved["primary"]["phase"])
            # The key ID was journaled before the server call, so the credential
            # is revocable even though creation failed.
            self.assertEqual("key-abc123", saved["primary"]["tailscale_key_id"])

    def test_stale_user_data_marks_provision_failed(self) -> None:
        with ProvisionFixture() as fixture:
            (fixture.work / "user-data.yaml").write_text("foreign\n")
            with self.assertRaises(provision.ProvisionError) as caught:
                fixture.apply()
            self.assertIn("FileExistsError", str(caught.exception))
            saved = fixture.saved()
            self.assertEqual("FAILED", saved["primary"]["phase"])
            self.assertEqual("key-abc123", saved["primary"]["tailscale_key_id"])

    def test_key_id_is_journaled_before_the_server_id(self) -> None:
        """Ordering, asserted from the journal rather than assumed.

        The key ID must reach durable state at an earlier generation than the
        server ID. Otherwise a crash between key creation and server creation
        would leave a live credential nothing knows how to revoke.
        """
        with ProvisionFixture() as fixture:
            journal: list[tuple[int, dict]] = []
            original = provision.record

            def spy(path, state, **updates):
                result = original(path, state, **updates)
                journal.append((result["generation"], dict(result["primary"])))
                return result

            provision.record = spy
            try:
                fixture.apply()
            finally:
                provision.record = original

            key_generation = next(gen for gen, primary in journal
                                  if primary.get("tailscale_key_id"))
            server_generation = next(gen for gen, primary in journal
                                     if primary.get("server_id"))
            self.assertLess(key_generation, server_generation)

    def test_firewall_is_attached_in_the_create_request(self) -> None:
        with ProvisionFixture() as fixture:
            mutator = FakeMutator()
            fixture.apply(mutator=mutator)
            self.assertIn("100000002", mutator.created_argv)
            self.assertEqual(("create_server", "cinderwell-run-001",
                              "100000001", "100000002"), mutator.calls[0])

    def test_user_data_is_deleted_after_the_provider_accepts_it(self) -> None:
        with ProvisionFixture() as fixture:
            mutator = FakeMutator()
            fixture.apply(mutator=mutator)
            self.assertIn(KEY_SECRET, mutator.created_user_data or "")
            self.assertEqual([], list(fixture.work.glob("user-data.yaml")))

    def test_user_data_is_deleted_even_when_creation_fails(self) -> None:
        with ProvisionFixture() as fixture:
            with self.assertRaises(provision.ProvisionError):
                fixture.apply(mutator=FakeMutator(fail_on="create_server"))
            self.assertEqual([], list(fixture.work.glob("user-data.yaml")))

    def test_tailscale_failure_creates_no_server(self) -> None:
        with ProvisionFixture() as fixture:
            mutator = FakeMutator()
            with self.assertRaises(lifecycle.SurfaceUnavailable):
                fixture.apply(mutator=mutator,
                              tailscale=FakeTailscale(fail_on="create_auth_key"))
            self.assertEqual([], mutator.calls)
            self.assertEqual("FAILED", fixture.saved()["primary"]["phase"])

    def test_state_never_holds_the_key_secret(self) -> None:
        with ProvisionFixture() as fixture:
            fixture.apply()
            serialized = fixture.state_path.read_text()
            self.assertNotIn(KEY_SECRET, serialized)
            self.assertNotIn("tskey-", serialized)


# ── Abort ─────────────────────────────────────────────────────────────────────

class AbortTest(unittest.TestCase):

    def _provisioned(self, fixture: ProvisionFixture) -> dict:
        return fixture.apply()

    def test_abort_plan_names_only_recorded_ids(self) -> None:
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            kinds = {target["kind"] for target in plan["targets"]}
            self.assertEqual({"tailscale_device", "tailscale_key", "server",
                              "primary_ip"}, kinds)
            for target in plan["targets"]:
                if "id" in target:
                    self.assertIn(target["id"], (900001, 900002, "key-abc123"))

    def test_abort_plan_omits_resources_that_were_never_created(self) -> None:
        with ProvisionFixture() as fixture:
            with self.assertRaises(lifecycle.SurfaceUnavailable):
                fixture.apply(tailscale=FakeTailscale(fail_on="create_auth_key"))
            plan = provision.plan_abort(fixture.saved())
            kinds = {target["kind"] for target in plan["targets"]}
            self.assertNotIn("server", kinds)
            self.assertNotIn("tailscale_key", kinds)

    def test_abort_is_refused_after_trust(self) -> None:
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            state["primary"]["phase"] = "READY"
            with self.assertRaises(provision.AbortError):
                provision.plan_abort(state)

    def test_abort_deletes_exactly_the_recorded_resources(self) -> None:
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            mutator, tailscale = FakeMutator(), FakeTailscale(
                devices=["cinderwell-run-001"])
            empty = FakeProvider()
            final = provision.apply_abort(state, plan, state_path=fixture.state_path,
                                          provider=empty, mutator=mutator,
                                          tailscale=tailscale, authority=authority_for(plan))
            self.assertEqual("ABSENT_VERIFIED", final["primary"]["phase"])
            self.assertIn(("delete_server", "900001"), mutator.calls)
            self.assertIn(("delete_primary_ip", "900002"), mutator.calls)
            self.assertIn(("delete_key", "key-abc123"), tailscale.calls)

    def test_a_primary_ip_the_provider_already_removed_is_not_leftover_work(self) -> None:
        """Reproduces the first live abort, exactly.

        Hetzner deletes a primary IP along with the server it was created for,
        so the subsequent delete returns "Primary IP not found". The first
        version counted that as work left behind and recorded FAILED -- a
        terminal phase demanding a human -- for a cleanup that had in fact
        removed everything.

        No test caught it because every fake deleted both resources
        independently, which is what the code assumed the provider would do.
        The fake here does what Hetzner actually does.
        """
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            mutator = FakeMutator(fail_on="delete_primary_ip")
            final = provision.apply_abort(state, plan,
                                          state_path=fixture.state_path,
                                          provider=FakeProvider(),
                                          mutator=mutator,
                                          tailscale=FakeTailscale(), authority=authority_for(plan))
            self.assertEqual("ABSENT_VERIFIED", final["primary"]["phase"])
            self.assertIn(("delete_primary_ip", "900002"), mutator.calls)

    def test_a_deletion_error_is_only_forgiven_when_absence_is_proven(self) -> None:
        """Evidence, not wording. The error is forgiven because a fresh read
        shows the resource gone -- never because the provider's message looked
        reassuring. A primary IP that failed to delete AND is still present is
        still leftover work."""
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            still_there = FakeProvider(surfaces={
                "servers": [], "volumes": [],
                "primary_ips": [{"id": 900002, "name": "ip"}],
                "floating_ips": [], "firewalls": [{"id": 100000002, "name": "fw"}],
                "ssh_keys": [], "snapshots": []})
            with self.assertRaises(provision.AbortError) as raised:
                provision.apply_abort(state, plan,
                                      state_path=fixture.state_path,
                                      provider=still_there,
                                      mutator=FakeMutator(fail_on="delete_primary_ip"),
                                      tailscale=FakeTailscale(), authority=authority_for(plan))
            self.assertIn("primary_ip", str(raised.exception))
            self.assertEqual("FAILED", fixture.saved()["primary"]["phase"])

    def test_a_tailscale_failure_is_never_silently_forgiven(self) -> None:
        """Tailscale resources are not in the provider inventory, so their
        absence cannot be proven by this read. An unprovable failure stays a
        failure rather than being assumed fine."""
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            with self.assertRaises(provision.AbortError) as raised:
                provision.apply_abort(state, plan,
                                      state_path=fixture.state_path,
                                      provider=FakeProvider(),
                                      mutator=FakeMutator(),
                                      tailscale=FakeTailscale(fail_on="delete_key"), authority=authority_for(plan))
            self.assertIn("tailscale_key", str(raised.exception))

    def test_a_host_is_never_created_without_a_way_in(self) -> None:
        """The first live run created a host with no authorized key at all.

        Provisioning failed on its first SSH, rehydration could not run, and the
        teardown work guards could not run either -- so the machine could not be
        destroyed by its own designed path, only by setting the phase by hand.
        A host nothing can reach is worse than no host: it bills.
        """
        with ProvisionFixture() as fixture:
            mutator = FakeMutator()
            fixture.apply(mutator=mutator)
            self.assertEqual([100000003], mutator.created_ssh_key_ids)

    def test_a_plan_with_no_ssh_keys_is_refused_before_creation(self) -> None:
        with ProvisionFixture() as fixture:
            fixture.plan["server"]["ssh_key_ids"] = []
            # Re-hash, or verify_plan_hash refuses first and this test proves
            # only that a hand-edited plan is rejected -- which is a different
            # guard, already covered elsewhere.
            body = {k: v for k, v in fixture.plan.items() if k != "plan_hash"}
            fixture.plan["plan_hash"] = lifecycle.digest(body)
            mutator = FakeMutator()
            with self.assertRaises(provision.ProvisionError) as raised:
                fixture.apply(mutator=mutator)
            self.assertIn("nothing can reach", str(raised.exception))
            self.assertNotIn("create_server",
                             [c[0] for c in mutator.calls])

    def test_abort_never_issues_a_label_or_name_wide_delete(self) -> None:
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            mutator = FakeMutator()
            provision.apply_abort(state, plan, state_path=fixture.state_path,
                                  provider=FakeProvider(), mutator=mutator,
                                  tailscale=FakeTailscale(), authority=authority_for(plan))
            for call in mutator.calls:
                for argument in call[1:]:
                    self.assertNotIn("--selector", argument)
                    self.assertNotIn("*", argument)

    def test_abort_fails_closed_when_the_server_survives(self) -> None:
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            still_there = FakeProvider(surfaces={
                "servers": [{"id": 900001, "name": "cinderwell-run-001"}],
                "volumes": [], "primary_ips": [], "floating_ips": [],
                "firewalls": [{"id": 100000002, "name": "fw"}],
                "ssh_keys": [], "snapshots": []})
            with self.assertRaises(provision.AbortError):
                provision.apply_abort(state, plan, state_path=fixture.state_path,
                                      provider=still_there, mutator=FakeMutator(),
                                      tailscale=FakeTailscale(), authority=authority_for(plan))
            self.assertEqual("FAILED", fixture.saved()["primary"]["phase"])

    def test_abort_cannot_confirm_absence_from_an_unreadable_surface(self) -> None:
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            blind = FakeProvider(surfaces={
                "servers": RuntimeError("api down"), "volumes": [],
                "primary_ips": [], "floating_ips": [],
                "firewalls": [], "ssh_keys": [], "snapshots": []})
            with self.assertRaises(provision.AbortError):
                provision.apply_abort(state, plan, state_path=fixture.state_path,
                                      provider=blind, mutator=FakeMutator(),
                                      tailscale=FakeTailscale(), authority=authority_for(plan))

    def test_tailscale_outage_still_deletes_the_billable_server(self) -> None:
        """A key that cannot be revoked must not stop the server from going away."""
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            mutator = FakeMutator()
            with self.assertRaises(provision.AbortError):
                provision.apply_abort(state, plan, state_path=fixture.state_path,
                                      provider=FakeProvider(), mutator=mutator,
                                      tailscale=FakeTailscale(fail_on="delete_key"), authority=authority_for(plan))
            self.assertIn(("delete_server", "900001"), mutator.calls)
            self.assertEqual("FAILED", fixture.saved()["primary"]["phase"])

    def test_stale_abort_plan_is_refused(self) -> None:
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            moved = provision.record(fixture.state_path, state, phase="TRUST_PENDING")
            with self.assertRaises(provision.AbortError):
                provision.apply_abort(moved, plan, state_path=fixture.state_path,
                                      provider=FakeProvider(), mutator=FakeMutator(),
                                      tailscale=FakeTailscale(), authority=authority_for(plan))

    def test_edited_abort_plan_is_refused(self) -> None:
        with ProvisionFixture() as fixture:
            state = self._provisioned(fixture)
            plan = provision.plan_abort(state)
            plan["targets"].append({"kind": "server", "id": 111111})
            with self.assertRaises(lifecycle.PlanError):
                provision.apply_abort(state, plan, state_path=fixture.state_path,
                                      provider=FakeProvider(), mutator=FakeMutator(),
                                      tailscale=FakeTailscale(), authority=authority_for(plan))


# ── Command line ──────────────────────────────────────────────────────────────

class CommandLineTest(unittest.TestCase):

    def test_apply_requires_a_matching_plan_hash(self) -> None:
        with ProvisionFixture() as fixture:
            plan_file = fixture.work / "plan.json"
            plan_file.write_text(json.dumps(fixture.plan))
            with contextlib.redirect_stderr(io.StringIO()):
                code = provision.main([
                    "--config", str(fixture.tree.config_path),
                    "--state", str(fixture.state_path), "up",
                    "--apply", "0" * 64, "--plan-file", str(plan_file),
                    "--applied-at", PLANNED_AT])
            self.assertEqual(2, code)

    def test_up_cannot_run_without_a_plan_file(self) -> None:
        with ProvisionFixture() as fixture:
            with self.assertRaises(SystemExit):
                provision.main(["--config", str(fixture.tree.config_path),
                                "--state", str(fixture.state_path), "up",
                                "--apply", "0" * 64])

    def test_lifecycle_module_remains_free_of_mutation(self) -> None:
        """S2's guarantee must survive S3: the planner still cannot create."""
        source = (REPOSITORY_ROOT / "cinderwell" / "lifecycle.py").read_text()
        for verb in ("server create", "server delete", "primary-ip delete"):
            self.assertNotIn(verb, source)


if __name__ == "__main__":
    unittest.main()
