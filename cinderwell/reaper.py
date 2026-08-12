#!/usr/bin/env python3
"""The lease reaper: a host destroys itself on schedule (unit U6).

The founding requirement for this whole line of work was a **temporary** dev
server. Everything before this unit was temporary only in the sense that
somebody could destroy it -- and "the operator will remember" is not
enforcement. This is the thing outside the agent that enforces the expiry.

**It gets no private path.** The reaper runs the ordinary teardown, guards and
all, through `teardown.apply_down`. It cannot bypass a guard because it does not
have a way to; it authorizes itself with an ordinary approval artifact naming the
ordinary plan, exactly as an agent would. The hazard was never automation. It is
automation that skips a check in order to avoid getting stuck.

So the only genuinely new design question is what happens when a guard refuses,
and the answer is a ladder rather than a choice between two bad options:

1. Run `down`. Every guard passes, the host is gone, done.
2. `G3_work_preserved` refused because the host holds work that exists nowhere
   else. **Preserve first**: commit and push the worktree to a run-scoped ref on
   the approved remote, then re-run the guard. Work that exists in two places is
   safe to delete from one of them.
3. Preservation failed. **Escalate loudly and keep billing.** $0.017/hour is
   cheaper than destroyed work, and this is the one case where the right answer
   is to stop and shout.

Rung 3 is the important one. "Destroy anyway or give up" would have been a false
dilemma; the ladder makes the common case automatic and the dangerous case loud.

Two refusals are never climbed:

* A guard that **could not run** -- an unreachable host, an unreadable surface --
  is escalated immediately. `--work-attested` exists for a human who has looked;
  the reaper has not looked at anything and must never attest.
* A host with **no recorded expiry** is not reaped. Reaping on missing evidence
  is the same mistake as passing a guard on missing evidence.

Where this runs, and where it cannot: not on the ephemeral host, because
deleting a Hetzner server needs a provider token and a disposable host is
exactly the wrong place to keep one -- and `poweroff` is no substitute, since
Hetzner bills for a server that exists rather than one that is running. So it
runs on the operator's own machine under launchd, which survives the agent
process dying and the terminal closing, which are the actual failure modes.
`cinderwell reaper --install` renders the job; see `render_plist` below.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from cinderwell import approve
from cinderwell import lifecycle
from cinderwell import paths
from cinderwell import provision
from cinderwell import teardown
from cinderwell.lifecycle import LeaseError, LifecycleError, digest, redact  # noqa: E402

REAPER_IDENTITY = "lease-reaper"
COMMAND_TIMEOUT_SECONDS = 120
LOST_HISTORY = "(unknown -- the earlier record could not be read)"


class PreservationError(LifecycleError):
    """Work could not be pushed anywhere. The host must stay up."""


# ── Credentials ───────────────────────────────────────────────────────────────

# An interactive operator exports these by hand before running anything, and a
# recipe that checks for them is a helpful early refusal. A launchd job has no
# such environment and nobody to prompt, so the reaper deliberately does NOT
# depend on the caller having exported them, and resolves them here instead.
#
# This was the whole unit failing silently. The job ran every five minutes,
# exited 2 on a missing token before `reap` was ever called, wrote no
# escalation record, and the host billed forever while the operator believed a
# lease was being enforced. A reaper that cannot obtain its credentials has not
# established that there is nothing to do; it has established nothing at all,
# which is an escalation, not a quiet exit.

CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("HCLOUD_TOKEN", "hcloud_token_command"),
    ("TAILSCALE_API_TOKEN", "tailscale_api_token_command"),
)


def read_secret(command: list[str], runner: Callable[..., subprocess.CompletedProcess]
                | None = None) -> str:
    """Run one configured secret command, without ever letting it reach a log.

    argv rather than a shell string, so nothing here needs quoting rules and no
    substitution happens. The output is stripped because a trailing newline in
    a bearer token produces an authentication failure that looks nothing like a
    whitespace problem.
    """
    run = runner or (lambda argv: subprocess.run(
        argv, capture_output=True, text=True, check=False,
        timeout=COMMAND_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL))
    printable = " ".join(command)
    try:
        result = run(list(command))
    except FileNotFoundError as error:
        raise LeaseError(f"{command[0]!r} is not on PATH, so no credential "
                         f"can be resolved without a human") from error
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LeaseError(f"running {printable} failed: "
                         f"{type(error).__name__}") from error
    if result.returncode != 0:
        # The command is a pointer, not a secret, so naming it is how an
        # operator debugs a wrong path. stderr is redacted anyway.
        raise LeaseError(f"cannot resolve {printable}: "
                         f"{redact((result.stderr or '').strip()) or 'command failed'}")
    secret = (result.stdout or "").strip()
    if not secret:
        raise LeaseError(f"{printable} produced no secret")
    return secret


def ensure_credentials(config: dict, environment: dict[str, str] | None = None,
                       runner: Callable[..., subprocess.CompletedProcess]
                       | None = None) -> list[str]:
    """Put both provider credentials in the environment, or raise LeaseError.

    An already-exported value wins, so an interactive run behaves exactly as it
    did before and never runs a secret command at all. Returns the names it had
    to fetch, so a caller can report which path was taken rather than assume one.
    """
    environment = os.environ if environment is None else environment
    resolved: dict[str, str] = {}
    for name, key in CREDENTIALS:
        if environment.get(name):
            continue
        resolved[name] = read_secret(config["credentials"][key], runner)
    # Resolve every miss before exporting any of them, so a second reference
    # that fails cannot leave the first credential sitting in the environment
    # of a process that is about to do something else.
    environment.update(resolved)
    return list(resolved)


# ── Preservation ──────────────────────────────────────────────────────────────

class Preserver:
    """Pushes the host's worktree somewhere it will survive the host.

    A separate object with its own runner seam, matching `teardown.Probes`, so
    tests drive the script this builds rather than a stand-in for it. The
    failures that matter here -- a missing agent, a rejected push -- are all in
    what the remote shell does with the script, not in the decision to run it.
    """

    def __init__(self, runner: Callable[..., subprocess.CompletedProcess]
                 | None = None) -> None:
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(argv: list[str], *, stdin: str,
                        timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run(argv, input=stdin, capture_output=True, text=True,
                              timeout=timeout, check=False)

    @staticmethod
    def script(workspace: str, ref: str) -> str:
        """The exact script the host runs. Built here so a test can read it.

        `git add -A` before the commit is not incidental: `git push HEAD` would
        preserve the commits and silently drop every uncommitted change, which
        is half of what the work guard refused over. Preserving only the half
        that is easy to preserve would be worse than not preserving at all,
        because the guard would then pass and the rest would be destroyed.
        """
        return f"""set -eu
cd {shlex.quote(workspace)} 2>/dev/null || {{
  echo 'PRESERVE-NO-WORKSPACE' >&2; exit 90
}}
umask 022
git add -A
# An empty commit is fine and an empty tree is not an error: the worktree may
# hold unpushed commits and no uncommitted changes, which is still work that
# exists nowhere else.
git -c user.name='factory lease reaper' \\
    -c user.email='lease-reaper@cinderwell.invalid' \\
    commit -q --allow-empty -m 'lease preservation: work in flight on this host'
# --force is safe and necessary here: the ref is scoped to this run and nothing
# else writes it, so the only history this can overwrite is an earlier
# preservation of the same run's work.
git push --force --quiet origin HEAD:{shlex.quote(ref)}
# Record locally that the remote now has it. Without this the work guard still
# reports unpushed work after a successful push -- it asks `--not --remotes`,
# and pushing to a ref outside refs/heads creates no remote-tracking entry --
# so preservation would succeed and the guard would refuse anyway, forever.
# This states a fact that is now true, not a fact we would like to be true:
# the push above is what makes it true, and `set -eu` means a failed push
# never reaches this line.
git update-ref {shlex.quote(tracking_ref(ref))} HEAD
echo "PRESERVE-OK $(git rev-parse HEAD)"
"""

    def preserve(self, alias: str, workspace: str, ref: str) -> str:
        """Commit and push the worktree. Returns the commit that now holds it.

        `-A` forwards the agent so the host can reach the git remote without
        ever holding a key -- the same arrangement rehydration uses. If no agent
        is reachable this raises, which is rung 3, which is correct: a host
        whose work cannot be pushed must keep billing.
        """
        argv = ["ssh", "-A", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes", alias, "bash", "-s"]
        try:
            result = self._runner(argv, stdin=self.script(workspace, ref),
                                  timeout=COMMAND_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PreservationError(
                f"cannot reach {alias} to preserve its work: "
                f"{type(error).__name__}") from error
        if result.returncode != 0:
            raise PreservationError(
                f"preserving {alias}:{workspace} to {ref} failed: "
                f"{redact((result.stderr or '').strip()) or result.returncode}")
        for line in (result.stdout or "").splitlines():
            if line.startswith("PRESERVE-OK "):
                return line.split(" ", 1)[1].strip()
        raise PreservationError(
            f"the preservation script on {alias} reported success without "
            f"naming a commit; treating that as a failure rather than assuming "
            f"the work is safe")


def tracking_ref(ref: str) -> str:
    """The remote-tracking ref that records `ref` existing on origin.

    `refs/lease/run-001` -> `refs/remotes/origin/lease/run-001`. The work guard
    asks git what exists locally and not on any remote, and git answers from
    `refs/remotes/`; a push to a ref outside `refs/heads` populates nothing
    there. So without this, preservation would push successfully and the guard
    would keep refusing.
    """
    return f"refs/remotes/origin/{ref.removeprefix('refs/')}"


def preservation_ref(config: dict, run_id: str) -> str:
    """`refs/lease/<run-id>`, from the namespace the config declares.

    The namespace cannot name a branch: `config.schema.json` refuses anything
    under `refs/heads`, `refs/tags` or `refs/remotes`, so preservation can never
    move a ref a human reads.
    """
    if not run_id:
        raise LeaseError("no run id is recorded, so preserved work would have "
                         "no name to be found under")
    return f"{config['lease']['ref_namespace']}{run_id}"


# ── Is it due? ────────────────────────────────────────────────────────────────

def status(config: dict, state: dict, *, now: str) -> dict:
    """Read-only: what the reaper would do, without doing any of it."""
    primary = state["primary"]
    phase = primary["phase"]
    expires_at = primary.get("expires_at")
    reapable = phase in teardown.DOWN_PHASES
    expired = lifecycle.has_expired(expires_at, now)
    if not reapable:
        action = "nothing to reap"
    elif not expires_at:
        # Never reap on missing evidence. A host recorded before leases existed
        # has no expiry, and destroying it because nobody wrote one down would
        # be the reaper inventing authority it was not given.
        action = "no recorded expiry; refusing to guess"
    elif not expired:
        action = "waiting"
    else:
        action = "reap"
    return {"phase": phase, "run_id": primary.get("run_id"),
            "expires_at": expires_at, "now": now, "expired": expired,
            "action": action}


# ── What actually happened to the host ────────────────────────────────────────

# The three things a failed reap can leave behind. `UNCONFIRMED` is a real
# answer and never collapses into either of the others.
STRANDED = "RUNNING"
DESTROYED = "GONE"
UNCONFIRMED = "UNKNOWN"

_DISPOSITIONS = {
    STRANDED: ("It has been left RUNNING and is still billing."),
    DESTROYED: ("The provider no longer reports the server, so it is NOT "
                "billing -- but the teardown did not finish, so the recorded "
                "state and the receipt may not describe what happened. "
                "Reconcile before planning another run."),
    UNCONFIRMED: ("Its disposition could NOT be confirmed. It may still be "
                  "running and billing. Read the provider before assuming "
                  "either way."),
}


def observed_disposition(provider: lifecycle.Provider, state: dict) -> str:
    """Ask the provider what exists, rather than assume it survived.

    The first version of the escalation asserted "left RUNNING and still
    billing" for every failure. `apply_down` writes state and takes its lock
    *after* the deletion calls, so an `OSError` there produces a durable record
    claiming a destroyed host is burning money -- a lie with a date, which is
    the exact failure the retraction path exists to prevent, inverted and made
    permanent. Absent evidence is not evidence of survival.
    """
    recorded = state["primary"].get("server_id")
    if recorded is None:
        return UNCONFIRMED
    try:
        surfaces = provider.inventory()
    except Exception:
        # Including the provider being unreachable, which is often exactly why
        # the reap failed in the first place.
        return UNCONFIRMED
    servers = surfaces.get("servers", {})
    if servers.get("status") != "PASS":
        return UNCONFIRMED
    return (STRANDED if any(item.get("id") == recorded
                            for item in servers.get("items", []))
            else DESTROYED)


# ── The ladder ────────────────────────────────────────────────────────────────

def reap(config: dict, state: dict, *, now: str, recorded_at: str,
         state_path: Path, provider: lifecycle.Provider,
         mutator: provision.Mutator, tailscale: provision.TailscaleClient,
         probes: teardown.Probes, preserver: Preserver,
         approval_dir: Path | None = None) -> dict:
    """Destroy an expired host, preserving work rather than deciding against it."""
    verdict = status(config, state, now=now)
    if verdict["action"] != "reap":
        # `load_state` synthesises an ABSENT record when the file is missing, so
        # a lost or drifted state path reads as "nothing to reap" -- which used
        # to retract a standing escalation and exit 0. That is the worst
        # available outcome: the host is untouched and still billing, and now
        # nothing on disk says so and nothing exits non-zero. A record may only
        # be retracted against state that was actually read from disk. Asking
        # `standing_escalation` rather than one location is the whole point:
        # the first version asked only the preferred path, so a record that had
        # fallen back reopened this exact hole.
        standing = standing_escalation(state_path)
        if standing is not None and not Path(state_path).exists():
            raise LeaseError(
                f"an escalation stands at {standing} but the state file it "
                f"refers to is gone ({state_path}), so nothing about the host "
                f"it names can be confirmed. The earlier record said: "
                f"{_earlier_reason(state_path)}")
        # A standing escalation claims an expired host could not be destroyed
        # and is still billing. Once that stops being true the record has to
        # go -- however it stopped being true. Retracting only after a reap the
        # reaper itself completed meant a host destroyed by hand left a file
        # insisting it was still burning money, dated, forever. "waiting" also
        # resolves it: the host is running under a lease that has not expired.
        # "no recorded expiry" does not, and must not: something is wrong there
        # and the reaper cannot tell whether it is the same something.
        # No state-file check here: the guard above already refuses whenever a
        # record exists without state to check it against, and `clear_escalation`
        # is a no-op when there is nothing to clear. Repeating the condition
        # would be one fact stated twice, and no test could tell the copies apart.
        cleared = (verdict["action"] in ("nothing to reap", "waiting")
                   and clear_escalation(state_path))
        return {**verdict, "outcome": "skipped", "cleared_escalation": cleared}

    try:
        # Everything from here is inside the guard, because from here on every
        # way out that is not a destroyed host leaves an expired one RUNNING.
        # Building the plan and minting the self-approval used to sit above it:
        # a `retained_resources` entry naming the live host, or an unwritable
        # state directory, raised before the guard was armed and exited 2 or 1
        # with no record -- silent, every five minutes, while the host billed.
        # That is the same shape as the bug this whole guard exists to prevent.
        plan = teardown.plan_down(config, state)
        authority = _self_authorize(plan, approval_dir or Path(state_path).parent,
                                    recorded_at, verdict["expires_at"])

        def destroy() -> dict:
            return teardown.apply_down(
                config, state, plan, state_path=state_path, provider=provider,
                mutator=mutator, tailscale=tailscale, probes=probes,
                recorded_at=recorded_at, authority=authority)

        outcome = _climb(config, verdict, plan, destroy, probes=probes,
                         preserver=preserver)
    except LeaseError:
        raise
    except Exception as error:
        # Deliberately every exception, not LifecycleError. The invariant is
        # about the host, not about which module was unlucky: an OSError from
        # writing the approval or the receipt strands a running host exactly as
        # thoroughly as a refused guard does, and `main` catches neither.
        #
        # What the record must NOT do is guess which of those happened. All
        # three dispositions still escalate -- each one needs a human -- but
        # each says only what was actually read back from the provider.
        raise LeaseError(
            f"the lease on {verdict['run_id']} expired at "
            f"{verdict['expires_at']} and the teardown did not complete: "
            f"{type(error).__name__}: {error}. "
            f"{_DISPOSITIONS[observed_disposition(provider, state)]}") from error

    # Outside the guard on purpose: the host is gone by now, so a failure to
    # retract the record must not be reported as a host that survived.
    outcome["cleared_escalation"] = clear_escalation(state_path)
    return outcome


def _climb(config: dict, verdict: dict, plan: dict,
           destroy: Callable[[], dict], *, probes: teardown.Probes,
           preserver: Preserver) -> dict:
    """The ladder itself: destroy, or preserve and destroy, or refuse."""
    try:
        return {**verdict, "outcome": "destroyed", "receipt": destroy()}
    except teardown.TeardownError as error:
        # Rung 2 is reached only by the guard that ran and said "there is work
        # here". Everything else -- a guard that could not run, a drifted id, a
        # live session -- goes straight to rung 3. In particular a
        # GuardNotVerified is never climbed: `--work-attested` is for a human
        # who has looked at the host, and the reaper has looked at nothing.
        if isinstance(error, teardown.GuardNotVerified) or \
                getattr(error, "guard", None) != "G3_work_preserved":
            raise

        ref = preservation_ref(config, verdict["run_id"])
        workspace = (config.get("workspace") or {}).get("path")
        alias = plan.get("alias")
        try:
            commit = preserver.preserve(alias, workspace, ref)
        except PreservationError as failure:
            # Rung 3. The host stays up and keeps billing, on purpose.
            raise LeaseError(
                f"the lease on {verdict['run_id']} expired at "
                f"{verdict['expires_at']} and the host holds work that exists "
                f"nowhere else. Preserving it failed: {failure}. The host has "
                f"been left RUNNING and is still billing, which is the correct "
                f"outcome -- destroying it would have been the only worse one. "
                f"Push the work by hand, then run the reaper again."
            ) from failure

        # Re-run the same plan. Nothing was written on the refused pass: guards
        # are evaluated before the first state record, so the generation the
        # plan was built against still holds.
        return {**verdict, "outcome": "preserved_then_destroyed",
                "preserved": {"ref": ref, "commit": commit},
                "receipt": destroy()}


def preserve_now(config: dict, state: dict, *, probes: teardown.Probes,
                 preserver: Preserver) -> dict:
    """Push whatever the host is holding, so expiry stops being dangerous (U7).

    The founding principle is that these hosts are **source-only**:
    nothing durable lives on them. The only thing a teardown can destroy is
    work that exists nowhere else -- so remove that category, and a scheduled
    teardown stops being a risk and becomes a chore.

    This runs on every tick, well before any lease expires. It is the reason
    rung 2 of the ladder should almost never fire, and a guard that almost
    never blocks is one that means something when it does.

    **It never raises.** A host that cannot be reached is not a reason to skip
    reaping, and a failed push is not silently forgiven either: the work guard
    will still see unpreserved work and still refuse. The result is reported so
    a reader can tell "nothing to preserve" from "could not preserve".
    """
    phase = state["primary"]["phase"]
    if phase not in teardown.MAY_CARRY_WORK:
        return {"status": "SKIPPED",
                "detail": f"phase {phase} cannot be carrying work"}

    alias = state["primary"].get("alias") or (config.get("ssh") or {}).get("alias")
    workspace = (config.get("workspace") or {}).get("path")
    run_id = state["primary"].get("run_id")
    if not (alias and workspace and run_id):
        return {"status": "NOT_VERIFIED",
                "detail": "no alias, workspace path and run id are recorded"}

    try:
        # Asked first so an idle host does not accrue an empty commit every
        # tick. The answer is the guard's own question, through the guard's own
        # probe, so preservation and teardown can never disagree about whether
        # this host is holding anything.
        if not probes.uncommitted_or_unpushed(alias, workspace):
            return {"status": "PASS", "detail": "nothing to preserve"}
    except teardown.GuardNotVerified as error:
        return {"status": "NOT_VERIFIED", "detail": redact(str(error))}

    try:
        ref = preservation_ref(config, run_id)
        commit = preserver.preserve(alias, workspace, ref)
    except LifecycleError as error:
        return {"status": "NOT_VERIFIED", "detail": redact(str(error))}
    return {"status": "PASS", "detail": f"pushed to {ref}", "ref": ref,
            "commit": commit}


def tick(config: dict, state: dict, **kwargs: Any) -> dict:
    """One pass of the scheduled job: preserve first, then reap if due.

    In this order deliberately. Preserving after the reaping decision would
    leave the common case -- an expired host holding a few minutes of work --
    climbing the escalation ladder every single time, and the ladder is meant
    to be the exception.
    """
    preserved = preserve_now(config, state, probes=kwargs["probes"],
                             preserver=kwargs["preserver"])
    return {**reap(config, state, **kwargs), "preservation": preserved}


def _self_authorize(plan: dict, directory: Path, recorded_at: str,
                    expires_at: str) -> dict:
    """Write the reaper's own approval, and authorize from it.

    Not a special case in the authority system: an ordinary approval artifact,
    written to disk, naming this exact plan hash, and read back through the
    same `authorize` an agent uses. It is left on disk deliberately -- an
    unattended deletion should leave behind the document that authorized it.
    """
    approval = approve.build_approval(
        plan, approved_by=REAPER_IDENTITY, approved_at=recorded_at,
        reason=f"lease expired at {expires_at}")
    path = approve.write_approval(
        Path(directory) / f"reap-{plan['run_id']}.approval.json", approval)
    return lifecycle.authorize(plan, approval_path=path,
                               terminal_present=False)


def write_escalation(path: Path, detail: dict) -> Path:
    """Leave a durable record that a human is needed.

    A reaper running under launchd has no terminal to shout at. Exiting
    non-zero tells launchd; this tells the operator, and survives until they
    read it.

    Written whole or not at all. A five-minute timer can start a tick before
    the previous one has finished, and a reader that arrives mid-write would
    see truncated JSON -- which every consumer here is obliged to treat as a
    record it cannot read, losing the history it actually contains.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(detail, indent=2, sort_keys=True) + "\n"
    scratch = target.with_name(f".{target.name}.{os.getpid()}")
    try:
        scratch.write_text(body)
        os.replace(scratch, target)
    except OSError:
        scratch.unlink(missing_ok=True)
        raise
    return target


def fallback_escalation_path(state_path: Path) -> Path:
    """Somewhere else to leave the record when the usual place is unwritable.

    Deterministic rather than random, so an operator can be told where to look
    without having read the stderr that named it.

    Deliberately NOT under `tempfile.gettempdir()`, which reads `$TMPDIR` and so
    is not one location but two: launchd exports no `TMPDIR`, resolving `/tmp`,
    while an interactive shell resolves `/var/folders/.../T`. The reaper runs
    under launchd, so the record it wrote would be invisible to the operator's
    shell and to the next manual reaper run -- `standing_escalation` returns
    None, the lost-state guard never fires, and the tick exits 0 with the host
    still billing. That is the exact hole this second location exists to close,
    reopened through the environment instead of the path. `Path.home()` agrees
    across both, falling through to the passwd database even with `HOME` unset,
    and is not world-writable the way `/tmp` is.
    """
    stamp = hashlib.sha256(
        str(Path(state_path).resolve()).encode("utf-8")).hexdigest()[:12]
    return (Path.home() / ".local" / "state" / "cinderwell"
            / f"lease-escalation-{stamp}.json")


def escalation_paths_for(state_path: Path) -> tuple[Path, ...]:
    """Every place a record can be, most-preferred first.

    The one function that knows this. The fallback was first added to the
    *writer* alone, so a record that landed there was read by nothing and
    retracted by nothing: the exit-0 hole the fallback existed to close
    reopened directly onto it, and the file became permanent. Anything that
    asks "is there a record?" or "retract the record" has to mean all of them,
    which is only guaranteed if there is one list and no second copy of it.
    """
    return (Path(state_path).parent / "lease-escalation.json",
            fallback_escalation_path(state_path))


def escalation_path_for(state_path: Path) -> Path:
    """Where a record goes when nothing is in the way."""
    return escalation_paths_for(state_path)[0]


def standing_escalation(state_path: Path) -> Path | None:
    """The record currently on disk, wherever it managed to land."""
    for path in escalation_paths_for(state_path):
        if path.exists():
            return path
    return None


def read_escalation(state_path: Path) -> dict | None:
    """The standing record's content, or None if there is no record.

    An unreadable record is still a record: it returns `{}` rather than None,
    so a corrupt file is never mistaken for the absence of a problem.
    """
    path = standing_escalation(state_path)
    if path is None:
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _earlier_reason(state_path: Path) -> str:
    """Carry a standing record's ORIGINAL cause into the one replacing it.

    `main` rewrites the record wholesale, so without this the first account of
    what went wrong is overwritten by the report that it could not be checked.
    Reading `original_reason` in preference to `reason` is what keeps that
    bounded: nesting each run's message inside the next grew the record by a
    couple of hundred bytes every tick, forever, on a five-minute timer.
    """
    record = read_escalation(state_path)
    if record is None:
        return "(none)"
    return str(record.get("original_reason")
               or record.get("reason") or "(unreadable)")


def clear_escalation(state_path: Path) -> bool:
    """Retract a resolved record from every place it could be.

    A file saying "a host is running and billing" that outlives the host is
    worse than no file: the next reader either acts on it and finds nothing, or
    learns to ignore it.

    Every location is attempted even when an earlier one refuses. Stopping at
    the first failure leaves the rest standing, which is precisely the
    permanent, wrong record this exists to prevent -- and the failure is
    likeliest on the location beside the state file, the one whose directory
    was unwritable in the first place. A record that survives the attempt is
    still standing, so the retraction reports itself incomplete rather than
    done.
    """
    stood = standing_escalation(state_path) is not None
    for path in escalation_paths_for(state_path):
        if not path.exists():
            continue
        try:
            path.unlink()
        except OSError as failure:
            print(f"could not retract the escalation at {path}: "
                  f"{type(failure).__name__}: {failure}", file=sys.stderr)
    return stood and standing_escalation(state_path) is None


# ── The launchd job ───────────────────────────────────────────────────────────

PLIST_TEMPLATE_NAME = "com.cinderwell.reaper.plist.tmpl"


def _xml_text(value: str) -> str:
    return (value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def render_plist(factory_bin: Path, state_path: Path, config_path: Path,
                 interval_seconds: int) -> str:
    """Render the launchd plist for the reaper.

    The job must not bake a repository checkout path: the reaper outlives any
    one worktree. It invokes the installed ``factory`` binary with absolute
    ``--config`` and ``--state`` paths, and writes StandardOut/Err under the
    machine state root next to the host state file.
    """
    if interval_seconds < 60:
        raise LeaseError(
            "an interval under a minute is a busy loop against a provider API, "
            "not a reaper")
    binary = Path(factory_bin).expanduser()
    if not binary.is_absolute():
        raise LeaseError(
            f"factory binary for launchd must be an absolute path, got {binary}")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise LeaseError(
            f"factory binary for launchd must be an existing executable: {binary}")
    # A binary inside a linked worktree dies when the worktree is removed after
    # merge. launchd would then exec a missing path every interval with no
    # escalation — the silent non-enforcement this job exists to prevent.
    try:
        top = subprocess.run(
            ["git", "-C", str(binary.parent), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False,
            timeout=COMMAND_TIMEOUT_SECONDS)
        if top.returncode == 0:
            root = Path(top.stdout.strip())
            if root.is_dir() and is_linked_worktree(root):
                raise LeaseError(
                    f"factory binary for launchd is inside a linked worktree "
                    f"({root}); install to a machine path that outlives the "
                    f"worktree (for example a user-local venv) and pass that "
                    f"absolute path")
    except LeaseError:
        raise
    except Exception:
        pass
    config = Path(config_path).expanduser()
    state = Path(state_path).expanduser()
    if not config.is_absolute() or not state.is_absolute():
        raise LeaseError(
            "launchd config and state paths must be absolute so the job does "
            "not depend on a working directory")
    state_root = state.parent
    log_path = state_root / "reaper.log"
    command = (
        f"exec {shlex.quote(str(binary))} reaper "
        f"--config {shlex.quote(str(config))} "
        f"--state {shlex.quote(str(state))} "
        f'--now "$(date -u +%Y-%m-%dT%H:%M:%SZ)"'
    )
    rendered = (lifecycle.resource_text(PLIST_TEMPLATE_NAME)
                .replace("{{PROGRAM}}", _xml_text(command))
                .replace("{{INTERVAL_SECONDS}}", str(interval_seconds))
                .replace("{{LOG_PATH}}", _xml_text(str(log_path))))
    if "{{" in rendered:
        raise LeaseError(
            "plist template still has unsubstituted placeholders: "
            f"{sorted(set(re.findall(r'{{[A-Z_]+}}', rendered)))}")
    if str(Path.cwd()) in rendered:
        raise LeaseError(
            "rendered launchd job still depends on a repository checkout path")
    return rendered



def is_linked_worktree(root: Path,
                       runner: Callable[..., subprocess.CompletedProcess]
                       | None = None) -> bool:
    """Whether `root` is a linked worktree rather than the primary checkout.

    In a linked worktree `--git-dir` points inside `.git/worktrees/<name>` while
    `--git-common-dir` points at the shared `.git`; in the primary checkout they
    are the same directory.
    """
    run = runner or (lambda argv: subprocess.run(
        argv, cwd=str(root), capture_output=True, text=True, check=False,
        timeout=COMMAND_TIMEOUT_SECONDS))
    paths = []
    for flag in ("--git-dir", "--git-common-dir"):
        result = run(["git", "rev-parse", flag])
        if result.returncode != 0:
            return False
        paths.append(Path((result.stdout or "").strip()))
    resolved = [(root / path).resolve() for path in paths]
    return resolved[0] != resolved[1]


# ── Command line ──────────────────────────────────────────────────────────────

def _emit(value: Any) -> int:
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cinderwell reaper",
        description="Destroy a host whose lease has expired, through the "
                    "ordinary teardown and its ordinary guards.")
    parser.add_argument("--config", type=Path, default=None,
                        help="configuration (default: XDG machine path)")
    parser.add_argument("--state", type=Path, default=None,
                        help="host state (default: XDG machine path)")
    parser.add_argument("--now", required=True,
                        help="RFC3339 instant to judge the lease against. An "
                             "input, so a test and an operator can ask the same "
                             "question about a moment that is not this one")
    parser.add_argument("--check", action="store_true",
                        help="report what would happen and change nothing")
    parser.add_argument("--check-credentials", action="store_true",
                        help="prove the unattended credential path works, "
                             "without using what it returns. Run before "
                             "trusting a launchd job to enforce anything")
    parser.add_argument("--render-plist", action="store_true", default=False,
                        help="print the launchd plist for absolute machine paths")
    parser.add_argument("--factory-bin", type=Path, default=None,
                        help="absolute path to factory binary for --render-plist")
    parser.add_argument("--interval", type=int, default=300,
                        help="seconds between reaper runs, for --render-plist")
    args = parser.parse_args(argv)
    args.config = paths.resolve_config_path(args.config)
    args.state = paths.resolve_state_path(args.state)

    if args.render_plist:
        # Outside the escalation path on purpose. Rendering a plist establishes
        # nothing about any host, so a refusal here -- a linked worktree, an
        # interval below the floor -- must not leave a record saying one is
        # stranded. It used to exit 3 with exactly that.
        try:
            print(render_plist(
                paths.require_absolute(
                    Path(args.factory_bin) if args.factory_bin
                    else Path(shutil.which("cinderwell") or "cinderwell"),
                    field="factory_bin"),
                paths.require_absolute(args.state, field="state"),
                paths.require_absolute(args.config, field="config"),
                args.interval), end="")
            return 0
        except (LifecycleError, paths.PathError) as error:
            print(f"{type(error).__name__}: {redact(str(error))}", file=sys.stderr)
            return 2

    try:
        config = lifecycle.load_config(args.config)

        if args.check_credentials:
            # Resolved into a throwaway mapping, never into this process's
            # environment: proving the path works must not be a way to hold a
            # credential for longer than the check.
            fetched = ensure_credentials(config, environment={})
            return _emit({"credentials": "PASS", "resolved": sorted(fetched)})

        if not Path(args.state).exists():
            blockers: list[str] = []
            blockers.extend(lifecycle.discover_alternate_host_states(Path(args.state)))
            if blockers:
                raise LeaseError(
                    "host state is absent at "
                    f"{args.state}, but other host records still exist "
                    f"({', '.join(blockers)}). Pass --state explicitly; "
                    "refusing to treat the lease as idle")

        state = lifecycle.load_state(args.state, digest(config))

        if args.check:
            return _emit(status(config, state, now=args.now))

        # Before anything else that could conclude "nothing to do". A reaper
        # that cannot obtain its credentials has established nothing at all.
        ensure_credentials(config)

        return _emit(tick(
            config, state, now=args.now, recorded_at=args.now,
            state_path=args.state, provider=lifecycle.provider_for(config),
            mutator=provision.Mutator(config["hcloud_context"]),
            tailscale=provision.TailscaleClient(config["tailscale"]["tailnet"]),
            probes=teardown.Probes(), preserver=Preserver()))

    except LeaseError as error:
        # The escalation path. Loud in three places, because the one that
        # matters depends on who is looking: stderr for a person running it,
        # a non-zero exit for launchd, and a file for whoever reads it tomorrow.
        # Read before writing: the replacement must carry the first account of
        # what went wrong, and when it first went wrong. Both are taken from
        # dedicated keys rather than by nesting the previous message inside
        # this one, which grew the record every tick of a five-minute timer.
        standing = read_escalation(args.state)
        if standing is None:
            # Nothing stands, so this tick genuinely is the first account.
            first_at, original = args.now, redact(str(error))
        elif not standing:
            # A record stands but could not be read -- a truncated write, a
            # full disk. Treating it as absent would stamp this tick as the
            # first one and quietly erase a history known to exist. The reader
            # already refuses to make that mistake; so must the writer.
            first_at = original = LOST_HISTORY
        else:
            first_at = (standing.get("first_escalated_at")
                        or standing.get("escalated_at") or args.now)
            original = (standing.get("original_reason")
                        or standing.get("reason") or redact(str(error)))
        detail = {
            "escalated_at": args.now,
            "first_escalated_at": first_at,
            "reason": redact(str(error)),
            "original_reason": original,
        }
        for candidate in escalation_paths_for(args.state):
            try:
                written = write_escalation(candidate, detail)
            except OSError as failure:
                # The first choice lives beside the state file, so the very
                # condition that strands a host -- an unwritable or full state
                # directory -- is also the one that loses the record of it.
                # Swallowing that left exit 3 with nothing on disk to read.
                print(f"could not record the escalation at {candidate}: "
                      f"{type(failure).__name__}: {failure}", file=sys.stderr)
                continue
            print(f"escalation recorded at {written}", file=sys.stderr)
            # Exactly one record survives. Two, disagreeing, is worse than one
            # in the wrong place. Deliberately outside the try above: sweeping
            # up the losing location is a different fact from recording the
            # escalation, and reporting a failed sweep as "could not record the
            # escalation at <the path just written>" states the opposite of
            # what happened to whoever reads that line at 3am.
            for other in escalation_paths_for(args.state):
                if other != written and other.exists():
                    try:
                        other.unlink()
                    except OSError as failure:
                        print(f"could not remove the stale escalation at "
                              f"{other}: {type(failure).__name__}: {failure}",
                              file=sys.stderr)
            break
        print(f"LeaseError: {redact(str(error))}", file=sys.stderr)
        return 3
    except LifecycleError as error:
        print(f"{type(error).__name__}: {redact(str(error))}", file=sys.stderr)
        return 2
    except OSError as error:
        # Reaching the config or the state file at all. Non-zero and named,
        # rather than a traceback and exit 1 -- but deliberately NOT an
        # escalation: nothing here establishes anything about a host.
        print(f"{type(error).__name__}: {redact(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
