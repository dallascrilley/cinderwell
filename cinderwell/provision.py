#!/usr/bin/env python3
"""Provisioning and fail-closed abort for Cinderwell hosts (unit S3).

This is the first module in the hybrid path that can spend money. It is kept
separate from `lifecycle.py` on purpose: the planner has no mutation verb at all
and a test asserts that stays true, so "planning cannot create anything" remains
an architectural property rather than a convention.

Two invariants govern everything here.

**Intent is recorded before the mutation, never after.** Every provider call is
preceded by a durable state write naming what is about to be created. A crash
between the write and the call leaves a resource that `abort-up` can find. The
reverse order would leak billable resources that nothing knows about.

**Deletion is by exact recorded ID.** No label sweeps, no name globs, no
"delete everything matching this prefix". An ID this process did not record is
never touched, because the blast radius of a wrong guess here is someone else's
production server.

`up --apply` stops at TRUST_PENDING. It never admits data and never reaches
READY: host-key reconciliation is S4's job, and until it happens this machine is
not trusted.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from cinderwell import lifecycle
from cinderwell import paths
from cinderwell.lifecycle import (APPROVAL_HELP, LifecycleError, PlanError,  # noqa: E402
                       StateError, SurfaceUnavailable, canonical_json, digest,
                       redact)

TAILSCALE_API = "https://api.tailscale.com/api/v2"
class _PackagedText:
    """Path-shaped handle for packaged templates (``.read_text()`` only)."""

    def __init__(self, name: str) -> None:
        self.name = name

    def read_text(self, encoding: str = "utf-8") -> str:
        return lifecycle.resource_text(self.name)

    def __fspath__(self) -> str:
        raise TypeError(
            f"packaged resource {self.name!r} has no filesystem path; "
            "use read_text()"
        )


TEMPLATE_NAME = "cloud-init.yaml.tmpl"
TEMPLATE_PATH = _PackagedText(TEMPLATE_NAME)

# Phases from which a new server may still be abandoned. Once the host is
# trusted and carrying data, abandonment is no longer a safe operation and the
# operator must go through the full teardown path in S5 instead.
ABORTABLE_PHASES = {"PLANNED", "PROVISIONING", "TRUST_PENDING", "FAILED"}


class ProvisionError(LifecycleError):
    """A mutation cannot proceed safely."""


class AbortError(LifecycleError):
    """Cleanup cannot proceed safely, or left something behind."""


# ── State persistence ─────────────────────────────────────────────────────────

def save_state(path: Path, state: dict) -> None:
    """Write state atomically, then fsync, so a crash cannot truncate it.

    A partially written state file is worse than none: it would fail schema
    validation on the next load and strand whatever was already created.
    """
    lifecycle.validate(state, lifecycle.load_schema("state.schema.json"))
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(state, indent=2, sort_keys=True))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, target)
    directory = os.open(target.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def record(path: Path, state: dict, **updates: Any) -> dict:
    """Advance the generation and persist. This is the intent journal."""
    primary = {**state["primary"], **{key: value for key, value in updates.items()
                                      if value is not None}}
    advanced = {**state, "generation": state["generation"] + 1, "primary": primary}
    save_state(path, advanced)
    return advanced


# ── Tailscale ─────────────────────────────────────────────────────────────────

class TailscaleClient:
    """Minimal Tailscale API client. Key secrets never leave this object."""

    def __init__(self, tailnet: str, token_reader: Callable[[], str] | None = None,
                 opener: Callable[[urllib.request.Request], bytes] | None = None) -> None:
        self.tailnet = tailnet
        self._token_reader = token_reader or (
            lambda: os.environ.get("TAILSCALE_API_TOKEN", ""))
        self._opener = opener or self._default_opener

    @staticmethod
    def _default_opener(request: urllib.request.Request) -> bytes:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()

    def _call(self, method: str, path: str, payload: dict | None = None) -> Any:
        token = self._token_reader()
        if not token:
            raise SurfaceUnavailable("no Tailscale API token is available")
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            f"{TAILSCALE_API}{path}", data=body, method=method,
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"})
        try:
            raw = self._opener(request)
        except urllib.error.HTTPError as error:
            raise SurfaceUnavailable(
                f"Tailscale API {method} {path} failed: HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise SurfaceUnavailable(
                f"Tailscale API unreachable: {type(error).__name__}") from error
        return json.loads(raw.decode("utf-8")) if raw else {}

    def create_auth_key(self, tag: str, expiry_seconds: int) -> tuple[str, str]:
        """Create one single-use ephemeral key and verify what came back.

        The requested capabilities are re-read from the response rather than
        assumed: a key that silently came back reusable or non-ephemeral would
        outlive this run and could enroll a machine nobody is tracking.
        """
        payload = {
            "capabilities": {"devices": {"create": {
                "reusable": False, "ephemeral": True, "preauthorized": True,
                "tags": [tag]}}},
            "expirySeconds": expiry_seconds,
        }
        response = self._call("POST", f"/tailnet/{self.tailnet}/keys", payload)
        key_id, secret = response.get("id"), response.get("key")
        if not key_id or not secret:
            raise SurfaceUnavailable("Tailscale did not return a usable key")

        granted = ((response.get("capabilities") or {}).get("devices") or {}
                   ).get("create") or {}
        if granted.get("reusable") is not False:
            raise ProvisionError("Tailscale returned a reusable key")
        if granted.get("ephemeral") is not True:
            raise ProvisionError("Tailscale returned a non-ephemeral key")
        if tag not in (granted.get("tags") or []):
            raise ProvisionError(f"Tailscale key is not scoped to {tag}")
        return str(key_id), str(secret)

    def delete_key(self, key_id: str) -> None:
        self._call("DELETE", f"/tailnet/{self.tailnet}/keys/{key_id}")

    def find_device(self, hostname: str) -> str | None:
        devices = self._call("GET", f"/tailnet/{self.tailnet}/devices")
        for device in (devices or {}).get("devices", []):
            names = {device.get("hostname"), device.get("name"),
                     (device.get("name") or "").split(".")[0]}
            if hostname in names:
                return str(device.get("id"))
        return None

    def delete_device(self, device_id: str) -> None:
        self._call("DELETE", f"/device/{device_id}")


# ── Provider mutations ────────────────────────────────────────────────────────

class Mutator:
    """The only object here that can change provider state."""

    def __init__(self, context: str | None,
                 runner: lifecycle.Runner | None = None) -> None:
        self.context = context
        self._runner = runner or lifecycle.default_runner

    def _run(self, argv: tuple[str, ...], *, expect_json: bool = True) -> Any:
        base = ("hcloud",) if self.context is None else ("hcloud", "--context",
                                                         self.context)
        command = (*base, *argv)
        if expect_json:
            command = (*command, "-o", "json")
        try:
            result = self._runner(command)
        except FileNotFoundError as error:
            raise SurfaceUnavailable("hcloud CLI is not installed") from error
        except subprocess.TimeoutExpired as error:
            raise SurfaceUnavailable(f"timed out: {' '.join(argv)}") from error
        if result.returncode != 0:
            raise ProvisionError(redact((result.stderr or "").strip()) or
                                 f"exit {result.returncode}: {' '.join(argv)}")
        if not expect_json:
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ProvisionError(f"unparseable output: {' '.join(argv)}") from error

    def create_server(self, *, name: str, server_type: str, image_id: int,
                      location: str, firewall_id: int, labels: dict[str, str],
                      user_data_path: Path, public_net: dict,
                      ssh_key_ids: list[int]) -> dict:
        """Create one server with the firewall and access keys in one request.

        Attaching the firewall afterwards would leave a window in which the
        machine is booted and publicly reachable, which is exactly the window
        this is meant to eliminate.

        The SSH keys are here for a different reason, learned the direct way: a
        host created without them cannot be logged into at all. The first live
        run reached TRUSTED and then failed to provision, because nothing in the
        design had ever granted access to the machine it creates -- and the
        teardown work guards need that access too, so the host could not even be
        destroyed by its own designed path. Passing key IDs at creation means
        access exists from first boot rather than depending on cloud-init
        finishing, and keeps key material out of both the config and the
        user-data.
        """
        if not ssh_key_ids:
            raise ProvisionError(
                "no ssh_key_ids configured; a host created without one cannot "
                "be provisioned, rehydrated, or have its work guards run at "
                "teardown, which leaves a billable machine nothing can reach")
        argv = ["server", "create", "--name", name, "--type", server_type,
                "--image", str(image_id), "--location", location,
                "--firewall", str(firewall_id),
                "--user-data-from-file", str(user_data_path),
                "--start-after-create=true"]
        for key_id in ssh_key_ids:
            argv += ["--ssh-key", str(key_id)]
        for key, value in sorted(labels.items()):
            argv += ["--label", f"{key}={value}"]
        # `--primary-ipv4` names an *existing* Primary IP to attach; there is no
        # "auto" value. Automatic assignment is the default, and the only knob
        # is the negative one. An earlier draft passed `--primary-ipv4=auto`,
        # which the API rejected with "Primary IPv4 not found: auto".
        if not public_net["enable_ipv4"]:
            argv += ["--without-ipv4=true"]
        if not public_net["enable_ipv6"]:
            argv += ["--without-ipv6=true"]
        created = self._run(tuple(argv))
        server = created.get("server") if isinstance(created, dict) else None
        server = server if isinstance(server, dict) else created
        if not isinstance(server, dict) or not server.get("id"):
            raise ProvisionError("server create returned no resource id")
        return server

    def describe_server(self, server_id: int) -> dict | None:
        try:
            return self._run(("server", "describe", str(server_id)))
        except (ProvisionError, SurfaceUnavailable):
            return None

    def delete_server(self, server_id: int) -> None:
        self._run(("server", "delete", str(server_id)), expect_json=False)

    def describe_primary_ip(self, primary_ip_id: int) -> dict | None:
        try:
            return self._run(("primary-ip", "describe", str(primary_ip_id)))
        except (ProvisionError, SurfaceUnavailable):
            return None

    def delete_primary_ip(self, primary_ip_id: int) -> None:
        self._run(("primary-ip", "delete", str(primary_ip_id)), expect_json=False)


# ── Cloud-init rendering ──────────────────────────────────────────────────────

def render_cloud_init(run_id: str, hostname: str, tag: str, key_secret: str,
                      template_path: Path | None = None) -> str:
    template = (template_path or TEMPLATE_PATH).read_text()
    # The key is emitted as a JSON string, which is also a valid YAML flow
    # scalar. A bare scalar would parse today because Tailscale keys happen to
    # be alphanumeric-and-dashes, but a key containing ':' or '#' would silently
    # produce a malformed document that only fails once a real server boots.
    rendered = (template
                .replace("{{RUN_ID}}", run_id)
                .replace("{{HOSTNAME}}", hostname)
                .replace("{{TAILSCALE_TAG}}", tag)
                .replace("{{TAILSCALE_KEY}}", json.dumps(key_secret)))
    if "{{" in rendered:
        leftover = re.findall(r"\{\{[A-Z_]+\}\}", rendered)
        raise ProvisionError(f"cloud-init template has unsubstituted "
                             f"placeholders: {sorted(set(leftover))}")
    return rendered


def write_user_data(directory: Path, content: str) -> Path:
    """Write user-data mode 0600, created that way rather than chmod'ed after."""
    path = Path(directory) / "user-data.yaml"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


# ── Drift checks ──────────────────────────────────────────────────────────────

def assert_plan_still_applies(plan: dict, config: dict, state: dict,
                              provider: lifecycle.Provider,
                              applied_at: str) -> None:
    """Refuse anything about the world that has moved since the plan was made."""
    lifecycle.verify_plan_hash(plan)

    # The lease clock starts at PLAN time, and `cinderwell approve` exists precisely
    # so a human can review a plan now and an agent apply it later. Those two
    # facts together will eventually produce a plan whose expiry has already
    # passed -- and applying it creates a host that the very next reaper tick
    # destroys, possibly while the operator is still fetching its console
    # fingerprint. Refuse here rather than spend money on a machine with no
    # life left in it.
    expires_at = (plan.get("lease") or {}).get("expires_at")
    if expires_at and lifecycle.has_expired(expires_at, applied_at):
        raise lifecycle.LeaseError(
            f"this plan's lease expired at {expires_at} and it is now "
            f"{applied_at}; the host would be created already overdue for "
            f"reaping. Re-plan rather than apply this one.")

    if plan.get("config_digest") != digest(config):
        raise PlanError("configuration changed after the plan was created")

    if state["primary"]["phase"] not in {"ABSENT", "ABSENT_VERIFIED"}:
        raise PlanError(f"primary is in phase {state['primary']['phase']}; apply "
                        f"is only valid from an absent state")

    expected_generation = plan["preconditions"]["state_generation"]
    if state["generation"] != expected_generation:
        raise PlanError(f"state generation is {state['generation']}, plan was "
                        f"built against {expected_generation}")

    # The S2 finding: `hcloud --context missing` exits 0 and silently falls back
    # to the ambient token. Verify the account again here, not only at plan time,
    # because this is the call that creates something.
    provider.verify_account()

    surfaces = provider.inventory()
    unreadable = sorted(name for name, result in surfaces.items()
                        if result["status"] != "PASS")
    if unreadable:
        raise PlanError(f"cannot apply against unread surfaces: {', '.join(unreadable)}")

    for name, expected in sorted(plan["preconditions"]["surfaces"].items()):
        observed = digest(surfaces[name]["items"])
        if observed != expected:
            raise PlanError(f"provider drift on {name} since the plan was created")

    spend = lifecycle.compute_spend(config, provider)
    if not spend["within_envelope"]:
        raise PlanError("prices moved above the spend envelope since planning")


# ── up --apply ────────────────────────────────────────────────────────────────

def apply_up(config: dict, state: dict, plan: dict, *, state_path: Path,
             provider: lifecycle.Provider, mutator: Mutator,
             tailscale: TailscaleClient, work_dir: Path,
             authority: dict, applied_at: str) -> dict:
    """Create one server, recording every resource ID before and after creation."""
    lifecycle.assert_authorized(plan, authority)
    assert_plan_still_applies(plan, config, state, provider, applied_at)

    run_id = plan["run_id"]
    server_spec = plan["server"]
    hostname = server_spec["name"]

    # The expiry is copied from the approved plan, never recomputed here. A
    # second computation is a second chance to disagree with what was approved,
    # and this project has found four defects whose shape was one fact stated
    # twice.
    state = record(state_path, state, phase="PLANNED", run_id=run_id,
                   plan_hash=plan["plan_hash"], authority=authority,
                   expires_at=plan["lease"]["expires_at"],
                   server_name=hostname,
                   image_id=server_spec["image_id"],
                   firewall_id=server_spec["firewall_id"],
                   labels=server_spec["labels"],
                   tailscale_hostname=hostname,
                   hourly_cost=plan["spend"]["hourly"],
                   monthly_cost=plan["spend"]["monthly"],
                   currency=plan["spend"]["currency"])

    user_data_path: Path | None = None
    try:
        state = record(state_path, state, phase="PROVISIONING")

        key_id, key_secret = tailscale.create_auth_key(
            config["tailscale"]["tag"], config["tailscale"]["key_expiry_seconds"])
        # Record the key ID before the key is ever used. If the next step dies,
        # abort-up still knows which credential to revoke.
        state = record(state_path, state, tailscale_key_id=key_id)

        try:
            user_data_path = write_user_data(
                work_dir, render_cloud_init(run_id, hostname,
                                            config["tailscale"]["tag"], key_secret))
        except OSError as error:
            raise ProvisionError(
                f"cannot write cloud-init user data: {type(error).__name__}"
            ) from error
        finally:
            del key_secret
        # Checked here, not only inside the Mutator, because a guard that lives
        # in the provider adapter is a guard every fake bypasses -- and the
        # fakes are what the tests exercise. The first version of this lived
        # only in Mutator.create_server and the suite sailed straight past a
        # plan with no keys at all.
        if not server_spec.get("ssh_key_ids"):
            raise ProvisionError(
                "the plan grants no ssh key; a host created without one cannot "
                "be provisioned, rehydrated, or have its teardown work guards "
                "run, which leaves a billable machine nothing can reach")

        server = mutator.create_server(
            name=hostname, server_type=server_spec["type"],
            image_id=server_spec["image_id"], location=server_spec["location"],
            firewall_id=server_spec["firewall_id"], labels=server_spec["labels"],
            user_data_path=user_data_path, public_net=server_spec["public_net"],
            ssh_key_ids=server_spec.get("ssh_key_ids", []))

        primary_ipv4 = (((server.get("public_net") or {}).get("ipv4") or {}).get("id"))
        state = record(state_path, state, server_id=int(server["id"]),
                       primary_ipv4_id=primary_ipv4)
        state = record(state_path, state, phase="TRUST_PENDING")
        return state

    except LifecycleError:
        # Preserve whatever was recorded. Do not clean up implicitly: an
        # automatic rollback here would race the operator and could delete a
        # resource whose creation actually succeeded but whose response was lost.
        record(state_path, state, phase="FAILED")
        raise
    finally:
        if user_data_path is not None and user_data_path.exists():
            user_data_path.unlink()


# ── abort-up ──────────────────────────────────────────────────────────────────

def plan_abort(state: dict) -> dict:
    """Build a hash-bound cleanup plan naming exact recorded resource IDs."""
    primary = state["primary"]
    phase = primary["phase"]
    if phase not in ABORTABLE_PHASES:
        raise AbortError(f"phase {phase} is not abortable; use the S5 teardown path")

    targets = []
    if primary.get("tailscale_hostname"):
        targets.append({"kind": "tailscale_device",
                        "hostname": primary["tailscale_hostname"]})
    if primary.get("tailscale_key_id"):
        targets.append({"kind": "tailscale_key", "id": primary["tailscale_key_id"]})
    if primary.get("server_id"):
        targets.append({"kind": "server", "id": primary["server_id"]})
    if primary.get("primary_ipv4_id"):
        targets.append({"kind": "primary_ip", "id": primary["primary_ipv4_id"]})

    body = {"operation": "abort-up", "schema_version": 1,
            "run_id": primary.get("run_id"), "from_phase": phase,
            "state_generation": state["generation"], "targets": targets}
    return {**body, "plan_hash": digest(body)}


# Surfaces a recorded resource kind can be proven absent in. A kind absent from
# this map cannot be checked, so a failed deletion of it stays a failure.
_ABORT_SURFACE = {"server": "servers", "primary_ip": "primary_ips"}


def _unresolved_failures(failed: list[tuple[dict, str]],
                         surfaces: dict) -> list[str]:
    """Drop deletion errors that a fresh read proves were already satisfied.

    Hetzner deletes a primary IP along with the server it was created for, so
    deleting it afterwards returns "Primary IP not found" -- and the first
    version of this counted that as work left behind. The result was a
    completely successful cleanup recorded as FAILED, which is terminal for
    automation and demands a human. Found on the first live abort, not by any
    test: every fake deleted both resources independently, because that is what
    the code expected the provider to do.

    `down` already got this right ("already absent" is a PASS there). The check
    here is deliberately evidence-based rather than message-based: an error is
    forgiven only when a fresh inventory read shows the resource genuinely gone,
    never because the provider's wording looked reassuring.
    """
    unresolved: list[str] = []
    for target, message in failed:
        surface = _ABORT_SURFACE.get(target["kind"])
        if surface and surfaces.get(surface, {}).get("status") == "PASS":
            present = any(item.get("id") == target.get("id")
                          for item in surfaces[surface]["items"])
            if not present:
                continue  # Absent is the outcome that was wanted.
        unresolved.append(f"{target['kind']}: {message}")
    return unresolved


def apply_abort(state: dict, plan: dict, *, state_path: Path,
                provider: lifecycle.Provider, mutator: Mutator,
                tailscale: TailscaleClient, authority: dict) -> dict:
    """Delete exactly the recorded resources, then prove they are gone."""
    lifecycle.assert_authorized(plan, authority)
    lifecycle.verify_plan_hash(plan)
    if plan.get("state_generation") != state["generation"]:
        raise AbortError(f"abort plan was built against generation "
                         f"{plan.get('state_generation')}, state is now "
                         f"{state['generation']}")
    if state["primary"]["phase"] not in ABORTABLE_PHASES:
        raise AbortError(f"phase {state['primary']['phase']} is not abortable")

    provider.verify_account()
    state = record(state_path, state, phase="DESTROYING", authority=authority)

    failed: list[tuple[dict, str]] = []
    for target in plan["targets"]:
        try:
            if target["kind"] == "tailscale_device":
                device_id = tailscale.find_device(target["hostname"])
                if device_id:
                    tailscale.delete_device(device_id)
            elif target["kind"] == "tailscale_key":
                tailscale.delete_key(target["id"])
            elif target["kind"] == "server":
                mutator.delete_server(int(target["id"]))
            elif target["kind"] == "primary_ip":
                mutator.delete_primary_ip(int(target["id"]))
        except LifecycleError as error:
            # Keep going: a Tailscale outage must not prevent deleting the
            # server, which is the resource that actually costs money.
            failed.append((target, redact(str(error))))

    surfaces = provider.inventory()
    if surfaces["servers"]["status"] != "PASS":
        raise AbortError("cannot confirm absence: the server surface is unreadable")

    server_id = state["primary"].get("server_id")
    if server_id and any(item.get("id") == server_id
                         for item in surfaces["servers"]["items"]):
        record(state_path, state, phase="FAILED")
        raise AbortError(f"server {server_id} is still present after deletion")

    failures = _unresolved_failures(failed, surfaces)
    if failures:
        record(state_path, state, phase="FAILED")
        raise AbortError("cleanup left work behind: " + "; ".join(failures))

    return record(state_path, state, phase="ABSENT_VERIFIED")


# ── Command line ──────────────────────────────────────────────────────────────

def _emit(value: Any) -> int:
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cinderwell provision",
        description="Create or abandon one Cinderwell host. Every "
                    "mutation requires the exact hash of a reviewed plan.")
    parser.add_argument("--config", type=Path, default=None,
                        help="configuration (default: XDG machine path)")
    parser.add_argument("--state", type=Path, default=None,
                        help="host state (default: XDG machine path)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    up_parser = subparsers.add_parser("up", help="create the planned server")
    up_parser.add_argument("--apply", required=True, metavar="PLAN_HASH")
    up_parser.add_argument("--plan-file", required=True, type=Path)
    up_parser.add_argument("--approval", type=Path, default=None,
                           help=APPROVAL_HELP)
    up_parser.add_argument("--applied-at", required=True,
                           help="RFC3339 instant this apply happens, judged "
                                "against the plan's lease. An input rather "
                                "than now(), like every other timestamp here")

    abort_parser = subparsers.add_parser("abort-up", help="abandon before trust")
    abort_parser.add_argument("--plan", action="store_true")
    abort_parser.add_argument("--apply", metavar="PLAN_HASH")
    abort_parser.add_argument("--plan-file", type=Path)
    abort_parser.add_argument("--approval", type=Path, default=None,
                              help=APPROVAL_HELP)

    args = parser.parse_args(argv)
    args.config = paths.resolve_config_path(args.config)
    args.state = paths.resolve_state_path(args.state)

    try:
        config = lifecycle.load_config(args.config)
        config_digest = digest(config)
        state = lifecycle.load_state(args.state, config_digest)
        provider = lifecycle.provider_for(config)
        mutator = Mutator(config["hcloud_context"])
        tailscale = TailscaleClient(config["tailscale"]["tailnet"])

        if args.command == "abort-up" and args.plan:
            return _emit(plan_abort(state))

        if args.command == "abort-up":
            if not args.plan_file or not args.apply:
                raise AbortError("abort-up --apply requires --plan-file and a hash")
            plan = json.loads(args.plan_file.read_text())
            if plan["plan_hash"] != args.apply:
                raise AbortError("supplied hash does not match the plan file")
            authority = lifecycle.authorize(
                plan, approval_path=args.approval,
                terminal_present=lifecycle.has_controlling_terminal())
            return _emit(apply_abort(state, plan, state_path=args.state,
                                     provider=provider, mutator=mutator,
                                     tailscale=tailscale, authority=authority))

        plan = json.loads(args.plan_file.read_text())
        if plan["plan_hash"] != args.apply:
            raise ProvisionError("supplied hash does not match the plan file")
        authority = lifecycle.authorize(
            plan, approval_path=args.approval,
            terminal_present=lifecycle.has_controlling_terminal())
        work_dir = Path(args.state).parent
        work_dir.mkdir(parents=True, exist_ok=True)
        return _emit(apply_up(config, state, plan, state_path=args.state,
                              provider=provider, mutator=mutator,
                              tailscale=tailscale, work_dir=work_dir,
                              authority=authority, applied_at=args.applied_at))

    except LifecycleError as error:
        print(f"{type(error).__name__}: {redact(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
