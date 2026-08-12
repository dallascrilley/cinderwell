#!/usr/bin/env python3
"""Fail-closed teardown for Cinderwell hosts (unit S5).

`abort-up` in S3 abandons a host that was never trusted. This is the other
cleanup path: it destroys a host that may have been *used*, and the difference
is entirely about what could be lost.

Three rules shape everything below.

**A guard that cannot run is not a guard that passed.** Every refusal condition
is either proven satisfied, proven vacuous, or reported `NOT_VERIFIED` — and a
`NOT_VERIFIED` guard stops the teardown. The failure mode being avoided is a
guard that silently degrades to "no evidence of a problem, therefore fine".

**Vacuous is not the same as unverified.** A host that never reached TRUSTED
never received a workspace, so "no unpushed work will be destroyed" is true by
construction rather than unchecked. That distinction is recorded in the receipt
detail so a reader can tell which one they are looking at.

**Deletion is by exact recorded ID**, inherited from S3, plus one addition: each
ID is re-described immediately before deletion and must still carry the recorded
name. Provider IDs can be reused, and an ID that now denotes something else is
somebody else's resource.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from cinderwell import lifecycle
from cinderwell import paths
from cinderwell import provision
from cinderwell.lifecycle import LifecycleError, digest, redact  # noqa: E402

# Phases a teardown may start from. ABSENT and ABSENT_VERIFIED are excluded
# because there is nothing to destroy; PLANNED and PROVISIONING belong to
# `abort-up`, which is the cheaper path for a host that never existed fully.
DOWN_PHASES = {"TRUST_PENDING", "TRUSTED", "READY", "DESTROYING", "FAILED"}

# Phases in which the host provably never received a workspace. In these the
# "no unpushed work" guard is vacuously satisfied rather than skipped.
# TRUSTED is included: rehydrate is what creates the host workspace, and
# rehydrate is what advances the phase to READY. A host that stopped at
# TRUSTED (including preview-only hosts that never rehydrate) never held
# work, so requiring the workspace path there forced operators through
# --work-attested for an absence that the phase already proves
# (cinderwell-hns).
NEVER_CARRIED_WORK = {"ABSENT", "PLANNED", "PROVISIONING", "TRUST_PENDING",
                     "TRUSTED"}

# Phases in which a workspace may exist, so the work guards are mandatory.
MAY_CARRY_WORK = {"READY"}

COMMAND_TIMEOUT_SECONDS = 30


class TeardownError(LifecycleError):
    """Teardown cannot proceed safely, or left something behind.

    `guard` names which refusal condition produced this, using the identifier
    the guard already reports in the receipt -- `G3_work_preserved` and the
    rest. It exists so a caller can branch on *which* guard refused without
    reading English, which the lease reaper must do: a host holding unpushed
    work is preserved and retried, and a host whose guards could not run at all
    is escalated to a human. Reusing the existing identifiers rather than
    inventing a parallel vocabulary is deliberate; U5 generalizes this to every
    error in the lifecycle.
    """

    def __init__(self, *args: Any, guard: str | None = None) -> None:
        super().__init__(*args)
        self.guard = guard


class GuardNotVerified(TeardownError):
    """A refusal condition could not be evaluated. Never means 'satisfied'."""


# ── Lifecycle lock ────────────────────────────────────────────────────────────

class Lock:
    """A pid-bearing lock beside the state file.

    Two teardowns racing each other is how a state journal ends up describing a
    world that never existed. The pid is checked for liveness rather than
    trusted, so a crashed run cannot wedge the lifecycle forever.
    """

    def __init__(self, state_path: Path) -> None:
        self.path = Path(state_path).with_suffix(".lock")

    def held_by_live_process(self) -> int | None:
        try:
            recorded = int(self.path.read_text().strip())
        except (FileNotFoundError, ValueError):
            return None
        if recorded == os.getpid():
            return None
        try:
            os.kill(recorded, 0)
        except ProcessLookupError:
            return None
        except PermissionError:
            # The process exists and belongs to somebody else. Existing is the
            # part that matters.
            return recorded
        return recorded

    def acquire(self) -> None:
        holder = self.held_by_live_process()
        if holder is not None:
            raise TeardownError(f"lifecycle is locked by live process {holder}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(str(os.getpid()))

    def release(self) -> None:
        try:
            if int(self.path.read_text().strip()) == os.getpid():
                self.path.unlink()
        except (FileNotFoundError, ValueError):
            pass


# ── Host probes ───────────────────────────────────────────────────────────────

class Probes:
    """Everything teardown needs to learn about the host it is about to destroy.

    Split out as an object so tests can supply answers without a network, and so
    each probe has exactly one way to say "I do not know" rather than returning
    an empty result that reads like "nothing to worry about".
    """

    def __init__(self, runner: Callable[[list[str]], subprocess.CompletedProcess]
                 | None = None) -> None:
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=COMMAND_TIMEOUT_SECONDS, check=False)

    def _ssh(self, alias: str, remote: str) -> subprocess.CompletedProcess:
        return self._runner([
            "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10", alias, remote])

    def uncommitted_or_unpushed(self, alias: str, workspace: str) -> bool:
        """True if the host holds work that exists nowhere else.

        Raises GuardNotVerified rather than returning False when the answer
        cannot be obtained: an unreachable host is the case where destroying it
        is most likely to lose something.
        """
        # `--all HEAD`, not `--branches`. Rehydration leaves the host on a
        # DETACHED HEAD -- it clones and then checks out the pinned commit --
        # so every commit an agent makes there is on no branch at all, and
        # `--branches` cannot see it. The guard reported a clean host for a
        # worktree carrying committed work that existed nowhere else, which is
        # precisely the case it exists to catch. Found by running the query
        # against a real repository rather than by reading it; a scripted fake
        # answers whatever it was told to.
        script = (f"cd {workspace} 2>/dev/null || exit 90; "
                  f"git status --porcelain; echo '---'; "
                  f"git log --all HEAD --not --remotes --oneline")
        try:
            result = self._ssh(alias, script)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GuardNotVerified(
                f"cannot inspect git state on {alias}: {type(error).__name__}"
            ) from error
        if result.returncode == 90:
            raise GuardNotVerified(f"workspace {workspace} not found on {alias}")
        if result.returncode != 0:
            raise GuardNotVerified(
                f"git inspection on {alias} failed: "
                f"{redact((result.stderr or '').strip()) or result.returncode}")
        dirty, _, unpushed = (result.stdout or "").partition("---")
        return bool(dirty.strip() or unpushed.strip())

    def has_active_sessions(self, alias: str) -> bool:
        """True if somebody is logged in right now."""
        try:
            result = self._ssh(alias, "who | wc -l")
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GuardNotVerified(
                f"cannot check sessions on {alias}: {type(error).__name__}") from error
        if result.returncode != 0:
            raise GuardNotVerified(f"session check on {alias} failed")
        try:
            # Non-PTY SSH does not create a utmp entry; any recorded session
            # is an external interactive user.
            return int((result.stdout or "0").strip()) > 0
        except ValueError as error:
            raise GuardNotVerified(f"unreadable session count from {alias}") from error

    def devpod_workspaces(self) -> list[str]:
        try:
            result = self._runner(["devpod", "list", "--output", "json"])
        except FileNotFoundError:
            return []
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GuardNotVerified(
                f"cannot list DevPod workspaces: {type(error).__name__}") from error
        if result.returncode != 0:
            raise GuardNotVerified("devpod list failed")
        try:
            listed = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as error:
            raise GuardNotVerified("devpod list output is not JSON") from error
        return [str(entry.get("id") or entry.get("name") or "")
                for entry in listed if isinstance(entry, dict)]

    def devpod_stop_and_delete(self, workspace: str) -> None:
        """Stop then delete. `--force` is never used: it can drop DevPod's own
        record of the workspace while leaving provider resources behind."""
        for argv in (["devpod", "stop", workspace],
                     ["devpod", "delete", workspace, "--force-delete=false"]):
            result = self._runner(argv)
            if result.returncode != 0:
                raise TeardownError(
                    f"{' '.join(argv[:2])} failed: "
                    f"{redact((result.stderr or '').strip()) or result.returncode}")


# ── Planning ──────────────────────────────────────────────────────────────────

def plan_down(config: dict, state: dict) -> dict:
    """Build a hash-bound teardown plan. Reads nothing and mutates nothing."""
    primary = state["primary"]
    phase = primary["phase"]
    if phase not in DOWN_PHASES:
        raise TeardownError(
            f"phase {phase} is not a teardown phase; "
            f"{'there is nothing to destroy' if phase.startswith('ABSENT') else 'use abort-up'}")

    targets: list[dict] = []
    if primary.get("tailscale_hostname"):
        targets.append({"kind": "tailscale_device",
                        "hostname": primary["tailscale_hostname"]})
    if primary.get("tailscale_key_id"):
        targets.append({"kind": "tailscale_key", "id": primary["tailscale_key_id"]})
    if primary.get("server_id"):
        targets.append({"kind": "server", "id": primary["server_id"],
                        "name": primary.get("server_name")})
    if primary.get("primary_ipv4_id"):
        targets.append({"kind": "primary_ip", "id": primary["primary_ipv4_id"]})

    # A retained resource is one the operator declared off-limits. Colliding
    # with it means the state file and the retention list disagree about who
    # owns something, and guessing is not an option. Entries are objects with a
    # typed integer `id`, so compare ids -- comparing the entries themselves
    # would silently never match and the guard would look satisfied.
    retained = {entry["id"] for entry in config.get("retained_resources", [])
                if isinstance(entry, dict) and "id" in entry}
    collisions = sorted(str(target["id"]) for target in targets
                        if isinstance(target.get("id"), int)
                        and target["id"] in retained)
    if collisions:
        raise TeardownError(f"teardown targets are on the retained list: "
                            f"{', '.join(collisions)}")

    body = {
        "operation": "down",
        "schema_version": 1,
        "run_id": primary.get("run_id"),
        "from_phase": phase,
        "state_generation": state["generation"],
        "config_digest": digest(config),
        "workspace": (config.get("devpod") or {}).get("workspace_name"),
        "alias": primary.get("alias") or (config.get("ssh") or {}).get("alias"),
        "targets": targets,
        "work_guards_required": phase in MAY_CARRY_WORK,
    }
    return {**body, "plan_hash": digest(body)}


# ── Guards ────────────────────────────────────────────────────────────────────

def _result(identifier: str, status: str, detail: str) -> dict:
    return {"id": identifier, "status": status, "detail": detail}


def _unverifiable(identifier: str, results: list[dict],
                  attestation: str | None, reason: str) -> None:
    """Record a guard that could not run, or refuse if nobody attested to it."""
    if not attestation:
        raise GuardNotVerified(reason, guard=identifier)
    results.append(_result(
        identifier, "NOT_VERIFIED",
        f"{reason} -- destroyed on the operator's written attestation: "
        f"{attestation}"))


def evaluate_guards(config: dict, state: dict, plan: dict, *,
                    provider: lifecycle.Provider, probes: Probes,
                    work_attested: str | None = None) -> list[dict]:
    """Evaluate every refusal condition. Raises on the first that refuses.

    Returns the evidence for a receipt. Nothing here mutates anything, so a
    caller can run it to preview whether a teardown would be permitted.

    `work_attested` is the operator's written reason for destroying a host whose
    work guards could not run at all. It exists because of a real deadlock: a
    TRUSTED host that has become unreachable cannot be destroyed by `down` --
    the work guards are mandatory at that phase and need SSH -- nor by
    `abort-up`, which does not accept TRUSTED. A billable machine with no route
    out is a worse outcome than a recorded human decision.

    It is deliberately not a `--force`:

    * It only applies to `GuardNotVerified` -- a check that could not run. A
      guard that ran and *refused* still refuses; an attestation can never turn
      "this host holds unpushed work" into permission to destroy it.
    * The result it produces is `NOT_VERIFIED`, never `PASS`, so the receipt
      verdict is `NOT_VERIFIED` too. "PASS means proven" keeps its meaning
      exactly, and the receipt says forever that nothing was proven and why.
    """
    results: list[dict] = []
    phase = state["primary"]["phase"]

    provider.verify_account()
    results.append(_result("G1_account", "PASS",
                           "credential proven to address the configured project"))

    # Drift: every recorded ID must still denote the recorded thing.
    surfaces = provider.inventory()
    if surfaces["servers"]["status"] != "PASS":
        raise GuardNotVerified("the server surface is unreadable; drift cannot "
                               "be ruled out", guard="G2_drift")
    recorded_server = state["primary"].get("server_id")
    recorded_name = state["primary"].get("server_name")
    if recorded_server is not None:
        live = [item for item in surfaces["servers"]["items"]
                if item.get("id") == recorded_server]
        if not live:
            results.append(_result(
                "G2_drift", "PASS",
                f"server {recorded_server} is already absent; deletion will be skipped"))
        elif recorded_name and live[0].get("name") != recorded_name:
            raise TeardownError(
                f"server {recorded_server} is now named {live[0].get('name')!r}, "
                f"state records {recorded_name!r}; refusing to delete a resource "
                f"this run did not create", guard="G2_drift")
        else:
            results.append(_result("G2_drift", "PASS",
                                   "recorded server id still carries its recorded name"))
    else:
        results.append(_result("G2_drift", "PASS",
                               "no server id was ever recorded"))

    # Unpushed work. Vacuous until READY (rehydrate), mandatory after.
    if phase in NEVER_CARRIED_WORK:
        results.append(_result(
            "G3_work_preserved", "PASS",
            f"vacuous in phase {phase}: the host never reached READY, so no "
            f"host workspace was ever created on it"))
    elif phase in MAY_CARRY_WORK:
        alias = plan.get("alias")
        workspace = (config.get("workspace") or {}).get("path")
        if not alias or not workspace:
            _unverifiable("G3_work_preserved", results, work_attested,
                          f"phase {phase} may carry work but no SSH alias and "
                          f"workspace path are recorded; unpushed work cannot "
                          f"be ruled out")
        else:
            try:
                dirty = probes.uncommitted_or_unpushed(alias, workspace)
            except GuardNotVerified as error:
                _unverifiable("G3_work_preserved", results, work_attested,
                              str(error))
            else:
                # A guard that ran and refused still refuses. No attestation
                # reaches this branch: the answer is known and it is "no".
                if dirty:
                    raise TeardownError(
                        f"{alias}:{workspace} holds uncommitted or unpushed "
                        f"commits; push them or discard them explicitly before "
                        f"teardown", guard="G3_work_preserved")
                results.append(_result("G3_work_preserved", "PASS",
                                       "remote worktree is clean and fully pushed"))
    else:
        # FAILED and DESTROYING: the phase itself does not say whether work
        # exists, so refuse to guess.
        _unverifiable("G3_work_preserved", results, work_attested,
                      f"phase {phase} does not establish whether the host "
                      f"carried work; resolve it to a known phase before "
                      f"teardown")

    # Live sessions. Only meaningful once the host is reachable.
    if phase in MAY_CARRY_WORK:
        try:
            busy = probes.has_active_sessions(plan["alias"])
        except GuardNotVerified as error:
            _unverifiable("G4_no_active_session", results, work_attested,
                          str(error))
        else:
            if busy:
                raise TeardownError(f"{plan['alias']} has an active session; "
                                    f"destroying it would cut somebody off",
                                    guard="G4_no_active_session")
            results.append(_result("G4_no_active_session", "PASS",
                                   "no interactive session other than this check"))
    else:
        results.append(_result("G4_no_active_session", "PASS",
                               f"vacuous in phase {phase}: the host never reached "
                               f"READY, so no interactive host session was "
                               f"established"))

    return results


# ── Apply ─────────────────────────────────────────────────────────────────────

def apply_down(config: dict, state: dict, plan: dict, *, state_path: Path,
               provider: lifecycle.Provider, mutator: provision.Mutator,
               tailscale: provision.TailscaleClient, probes: Probes,
               recorded_at: str, authority: dict,
               work_attested: str | None = None) -> dict:
    """Destroy the recorded resources, then prove they are gone."""
    lifecycle.assert_authorized(plan, authority)
    lifecycle.verify_plan_hash(plan)
    if plan.get("config_digest") != digest(config):
        raise TeardownError("configuration changed after the plan was created")
    if plan.get("state_generation") != state["generation"]:
        raise TeardownError(
            f"plan was built against generation {plan.get('state_generation')}, "
            f"state is now {state['generation']}")
    if state["primary"]["phase"] not in DOWN_PHASES:
        raise TeardownError(f"phase {state['primary']['phase']} is not a teardown phase")

    lock = Lock(state_path)
    lock.acquire()
    try:
        results = evaluate_guards(config, state, plan, provider=provider,
                                  probes=probes, work_attested=work_attested)

        state = provision.record(state_path, state, phase="DESTROYING")

        workspace = plan.get("workspace")
        if workspace and workspace in probes.devpod_workspaces():
            probes.devpod_stop_and_delete(workspace)
            results.append(_result("D1_workspace", "PASS",
                                   "DevPod workspace stopped and deleted without --force"))
        else:
            results.append(_result("D1_workspace", "PASS",
                                   "no DevPod workspace of that name exists"))

        failures: list[str] = []
        for target in plan["targets"]:
            try:
                _destroy(target, mutator=mutator, tailscale=tailscale)
            except LifecycleError as error:
                # Keep going. The server is the resource that costs money, and a
                # Tailscale outage must not be what stops it being deleted.
                failures.append(f"{target['kind']}: {redact(str(error))}")

        absence = _prove_absence(state, provider)
        results.extend(absence["results"])

        if failures:
            results.append(_result("D2_deletions", "FAIL", "; ".join(failures)))
        else:
            results.append(_result("D2_deletions", "PASS",
                                   f"{len(plan['targets'])} recorded resource(s) deleted "
                                   f"by exact id"))

        # ABSENT_VERIFIED means one specific thing: absence was proven by a
        # fresh read. So the phase turns on the absence evidence, not on any
        # NOT_VERIFIED anywhere -- an attested work guard says nothing about
        # whether the resources are gone, and treating it as if it did would
        # strand a destroyed host in FAILED forever.
        #
        # The original guarantee is unchanged and still tested: an absence check
        # that could not run must never produce ABSENT_VERIFIED.
        absence = [entry for entry in results
                   if entry["id"].startswith("D3_absent_")]
        proven = bool(absence) and all(entry["status"] == "PASS"
                                       for entry in absence)
        failed = any(entry["status"] == "FAIL" for entry in results)
        if failed or not proven:
            state = provision.record(state_path, state, phase="FAILED")
        else:
            state = provision.record(state_path, state, phase="ABSENT_VERIFIED")

        receipt = lifecycle.build_receipt(
            plan["run_id"], "down", results, recorded_at,
            config_digest=plan["config_digest"], plan_hash=plan["plan_hash"],
            authority=authority)
        # PASS keeps its meaning: everything was proven. A teardown may also
        # complete on NOT_VERIFIED, but only when every unproven result carries
        # the operator's attestation -- and the receipt says NOT_VERIFIED
        # forever, because nothing was proven and pretending otherwise is the
        # failure this whole module is shaped against.
        unproven = [entry for entry in receipt["results"]
                    if entry["status"] == "NOT_VERIFIED"]
        attested = all("written attestation" in str(entry.get("detail", ""))
                       for entry in unproven)
        if receipt["verdict"] == "FAIL" or (unproven and not attested):
            raise TeardownError(f"teardown verdict is {receipt['verdict']}: "
                                f"{json.dumps(receipt['results'])}")
        return receipt
    finally:
        lock.release()


def _destroy(target: dict, *, mutator: provision.Mutator,
             tailscale: provision.TailscaleClient) -> None:
    kind = target["kind"]
    if kind == "tailscale_device":
        device_id = tailscale.find_device(target["hostname"])
        if device_id:
            tailscale.delete_device(device_id)
    elif kind == "tailscale_key":
        tailscale.delete_key(target["id"])
    elif kind == "server":
        mutator.delete_server(int(target["id"]))
    elif kind == "primary_ip":
        # With ipv4_auto_delete the address goes with the server, so a delete
        # here would fail on a resource that is already correctly gone.
        if mutator.describe_primary_ip(int(target["id"])) is not None:
            mutator.delete_primary_ip(int(target["id"]))
    else:
        raise TeardownError(f"unknown teardown target kind: {kind}")


def _prove_absence(state: dict, provider: lifecycle.Provider) -> dict:
    """Re-read the provider. A successful delete call is not proof of absence."""
    surfaces = provider.inventory()
    results: list[dict] = []
    for surface, recorded in (("servers", state["primary"].get("server_id")),
                              ("primary_ips", state["primary"].get("primary_ipv4_id"))):
        identifier = f"D3_absent_{surface}"
        if recorded is None:
            results.append(_result(identifier, "PASS", "nothing was recorded"))
            continue
        if surfaces[surface]["status"] != "PASS":
            results.append(_result(identifier, "NOT_VERIFIED",
                                   f"the {surface} surface is unreadable, so absence "
                                   f"cannot be confirmed"))
            continue
        still_present = any(item.get("id") == recorded
                            for item in surfaces[surface]["items"])
        results.append(_result(
            identifier, "FAIL" if still_present else "PASS",
            f"{recorded} is {'still present' if still_present else 'absent'} "
            f"in a fresh read"))
    return {"results": results}


# ── Command line ──────────────────────────────────────────────────────────────

def _emit(value: Any) -> int:
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cinderwell teardown",
        description="Destroy one Matchbox host and prove nothing was "
                    "orphaned. Every mutation requires the exact hash of a "
                    "reviewed plan.")
    parser.add_argument("--config", type=Path, default=None,
                        help="configuration (default: XDG machine path)")
    parser.add_argument("--state", type=Path, default=None,
                        help="host state (default: XDG machine path)")
    subparsers = parser.add_subparsers(dest="command", required=True)
    down = subparsers.add_parser("down", help="destroy the recorded server")
    down.add_argument("--plan", action="store_true")
    down.add_argument("--apply", metavar="PLAN_HASH")
    down.add_argument("--plan-file", type=Path)
    down.add_argument("--recorded-at", default=None,
                      help="RFC3339 timestamp for the receipt")
    down.add_argument("--approval", type=Path, default=None,
                      help=lifecycle.APPROVAL_HELP)
    down.add_argument(
        "--work-attested", default=None,
        help="written reason for destroying a host whose work guards could not "
             "run at all -- an unreachable machine, typically. Applies only to "
             "checks that COULD NOT RUN, never to one that ran and refused. The "
             "receipt records NOT_VERIFIED and your words, never PASS.")

    args = parser.parse_args(argv)
    args.config = paths.resolve_config_path(args.config)
    args.state = paths.resolve_state_path(args.state)

    try:
        config = lifecycle.load_config(args.config)
        state = lifecycle.load_state(args.state, digest(config))

        if args.plan:
            return _emit(plan_down(config, state))

        if not args.plan_file or not args.apply:
            raise TeardownError("down --apply requires --plan-file and a hash")
        plan = json.loads(args.plan_file.read_text())
        if plan["plan_hash"] != args.apply:
            raise TeardownError("supplied hash does not match the plan file")
        if not args.recorded_at:
            raise TeardownError("--recorded-at is required so the receipt "
                                "timestamp is an input, not a side effect")

        authority = lifecycle.authorize(
            plan, approval_path=args.approval,
            terminal_present=lifecycle.has_controlling_terminal())

        return _emit(apply_down(
            config, state, plan, state_path=args.state,
            provider=lifecycle.provider_for(config),
            mutator=provision.Mutator(config["hcloud_context"]),
            tailscale=provision.TailscaleClient(config["tailscale"]["tailnet"]),
            probes=Probes(), recorded_at=args.recorded_at,
            authority=authority, work_attested=args.work_attested))

    except LifecycleError as error:
        print(f"{type(error).__name__}: {redact(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
