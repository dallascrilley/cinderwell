# Cinderwell

**Disposable cloud dev servers that destroy themselves on a lease, and prove it.**

A dev box you spin up for an afternoon should not still be billing you on
Thursday. The usual answer is a reminder, a cron job, or a teammate who
notices. Cinderwell makes the expiry part of the machine's own record: every
host is created under a hash-bound plan that carries the instant it stops being
allowed to exist, a scheduled reaper enforces that instant whether or not
anyone is watching, and the destruction produces a **receipt** — a signed-off
account of which guards ran, which resources were deleted by exact ID, and
whether a *fresh read of the provider* then found nothing.

That last part is the whole point. A delete call that returns zero is not proof
a machine is gone. A second read that finds nothing is.

---

## About this repository

This is an **architectural extract from a private production system**. The
original is not public and will not be.

- **No client data, no account artifacts.** Every provider resource ID, server
  name, firewall, SSH key ID, tailnet, and hostname in this repository is
  synthetic. There are no tokens, no real IPs, and no key fingerprints.
- **The fixtures are synthetic.** The test suite's fakes were written against
  the real provider surfaces, but everything they return is invented.
- **It is a subset.** The system this came from carried more surfaces than
  these — preview environments, host trust attestation, a console reader, a
  scheduled canary. Those depended on infrastructure that could not be
  published, so they are not here. What is here is the spine: plan, approve,
  provision, lease, reap, destroy, prove.

The code is otherwise as it ran: same module structure, same guard ladder, same
receipt schema, same comments explaining why each refusal exists. Several of
those comments describe failures that happened on real hosts. They were worth
keeping.

---

## The proof

Cinderwell ships an executable demonstration. It runs a complete teardown of a
host in phase `READY` whose lease has expired, against fakes — no credentials,
no network, no provider:

```console
$ python3 examples/mock_teardown.py
```

```json
{
  "authority": {
    "kind": "terminal",
    "operation": "down",
    "plan_hash": "85f78f97ce1292569a1e3bf77d57f7ecc63670f0913bc7a38ade9480905d86a7"
  },
  "config_digest": "2fb07f3851e0ece2d5aa651b9bc1c068d9b5eca06f50dd9a0b9d1313346e5381",
  "operation": "down",
  "plan_hash": "85f78f97ce1292569a1e3bf77d57f7ecc63670f0913bc7a38ade9480905d86a7",
  "recorded_at": "2026-08-11T13:00:04Z",
  "results": [
    {
      "detail": "credential proven to address the configured project",
      "id": "G1_account",
      "status": "PASS"
    },
    {
      "detail": "recorded server id still carries its recorded name",
      "id": "G2_drift",
      "status": "PASS"
    },
    {
      "detail": "remote worktree is clean and fully pushed",
      "id": "G3_work_preserved",
      "status": "PASS"
    },
    {
      "detail": "no interactive session other than this check",
      "id": "G4_no_active_session",
      "status": "PASS"
    },
    {
      "detail": "no DevPod workspace of that name exists",
      "id": "D1_workspace",
      "status": "PASS"
    },
    {
      "detail": "900001 is absent in a fresh read",
      "id": "D3_absent_servers",
      "status": "PASS"
    },
    {
      "detail": "900002 is absent in a fresh read",
      "id": "D3_absent_primary_ips",
      "status": "PASS"
    },
    {
      "detail": "4 recorded resource(s) deleted by exact id",
      "id": "D2_deletions",
      "status": "PASS"
    }
  ],
  "run_id": "run-001",
  "schema_version": 1,
  "verdict": "PASS"
}

state after teardown: ABSENT_VERIFIED
```

### How to read it

**`G1`–`G4` are refusal conditions, evaluated before anything is deleted.** The
credential is proven to address the intended project by describing a named
firewall — not by trusting a context label. The recorded server ID is checked
to still carry its recorded name, so a host somebody else renamed is never
destroyed by this run. The remote worktree is checked for uncommitted or
unpushed commits. Live interactive sessions are checked, because destroying a
machine somebody is typing on is its own kind of failure.

**`D2` says what was deleted. `D3` says what a fresh read then found.** Both
are required. `D2` alone would mean "a command succeeded"; `D3` is what turns
that into "the machine is gone". Deletion is always by exact recorded ID —
never a label sweep, never a name glob — so an ID this system did not record is
never touched.

**A guard that could not run is `NOT_VERIFIED`, and `NOT_VERIFIED` stops the
teardown.** The verdict can never be better than its worst result. Absent
evidence is never success. This is the rule the whole design is arranged
around, and it is why the receipt distinguishes *vacuous* from *unchecked*: a
host that never reached `READY` never received a workspace, so "no unpushed
work will be destroyed" is true by construction — and the receipt says so in
those words rather than silently passing.

**`state after teardown: ABSENT_VERIFIED`** is a distinct phase from `ABSENT`.
`ABSENT` is what an empty state file says. `ABSENT_VERIFIED` is what this run
proved.

---

## Quickstart

Everything below runs with no credentials, no network, and no dependencies
beyond Python 3.12+. The commands are copied from a session that executed them.

```console
$ git clone <this-repo> cinderwell && cd cinderwell

$ python3 -m unittest discover -s tests -t tests
[341 dots, interleaved with the diagnostics the failure-path tests
 print as they pass]
Ran 341 tests in 4.4s

OK (skipped=4)

$ python3 examples/mock_teardown.py        # the receipt above
```

Four skips in a bare checkout, and each says why: three cloud-init template
tests skip without a YAML parser installed, and one contract test skips without
the `hcloud` CLI. Install either and they run — the contract test adds about 45
seconds of `hcloud --help` probing when that CLI is present, which is most of
the difference you will see in the suite's wall time. The only other guards are
`skipIf(geteuid() == 0)` on a handful of permission-bit tests, because
root ignores the mode bits they depend on.

Install the CLI. The venv is not optional ceremony: Homebrew and Debian mark
their pythons externally managed (PEP 668) and refuse a bare `pip install .`.

```console
$ python3 -m venv .venv && source .venv/bin/activate
$ pip install .

$ cinderwell --help
usage: cinderwell <command> [options]

commands:
  lifecycle   inventory, price, and plan a host (mutates nothing)
  approve     write an approval naming one plan's exact hash
  provision   apply an approved plan, or abort a half-created host
  teardown    destroy a host and prove it is gone
  reaper      enforce the lease on a schedule
  doctor      report on configuration and state locations

Every command takes --help.

$ cinderwell doctor --config examples/config.example.json
{
  "config_path": "examples/config.example.json",
  "errors": [],
  "legacy_layout": [],
  "missing_fields": [],
  "ok": true,
  "unrecognised_fields": [],
  "warnings": []
}
```

To point it at a real Hetzner project, copy `examples/config.example.json` to
`~/.config/cinderwell/config.json` and replace every value. The example's
resource IDs are deliberately invalid.

---

## How it works

### The plan is the contract

`cinderwell lifecycle up` reads provider state, prices every billable resource,
and emits an immutable plan. It has no `--apply` verb at all — the absence of a
mutation path in the planner is an architectural property, asserted by a test,
not a flag someone could set by mistake.

The plan is content-addressed. `plan_hash` covers every input that could change
what gets created, including the lease. Abridged, from a plan built against the
example config and the suite's fake provider:

```json
{
  "operation": "up",
  "plan_hash": "d2ad4f5c4b12f6cf0137c592cdaf9d6615451c3fb542333a6bd1db1afcb65b30",
  "lease": { "expires_at": "2026-08-11T13:00:00Z", "seconds": 14400 },
  "server": {
    "name": "cinderwell-run-001",
    "type": "cx33",
    "image_id": 100000001,
    "firewall_id": 100000002,
    "labels": { "managed-by": "cinderwell", "run-id": "run-001" }
  },
  "spend": {
    "currency": "USD", "hourly": 0.017, "monthly": 9.59,
    "within_envelope": true
  },
  "preconditions": { "state_generation": 0, "surfaces": { "servers": "4f53cd…" } }
}
```

Edit any byte of that and the hash stops matching, so the approval stops
matching, so the apply refuses. The `preconditions` block digests each provider
surface the plan was made against: if the world moved, the plan is stale and is
refused rather than applied to a different world.

An unpriced resource is refused rather than treated as free.

### Authority is recorded, not assumed

Two ways to authorize a mutation, and no third:

- **An approval artifact** naming this plan's exact hash (`cinderwell approve`).
- **A controlling terminal** where a human confirmed at the prompt.

Neither is silently substituted for the other; the receipt records which one it
was. An unattended run has nobody to prompt, so it must carry an approval — and
the approval is bound to the bytes it saw, so it cannot be reused for a
different plan.

Every apply path takes `authority` as a required keyword-only argument and
checks it as its *first* statement. That is asserted structurally, so the next
apply path cannot be written without it.

### Intent is recorded before the mutation

Every provider call is preceded by a durable state write naming what is about
to be created, then fsynced. A crash between the write and the call leaves a
resource that `abort-up` can find and delete by exact ID. The reverse order
would leak billable resources that nothing knows about.

The expiry is written before the provider is called too, so a machine that
exists always has a readable expiry — including one whose creation then failed.

### The lease is enforced from outside

`--check` is read-only: it reports what the reaper *would* do. Against the
shipped example state file, which records a host whose lease ends at 13:00:

```console
$ cinderwell reaper --check --config examples/config.example.json --state examples/host.example.json \
    --now 2026-08-11T12:00:00Z
{
  "action": "waiting",
  "expired": false,
  "expires_at": "2026-08-11T13:00:00Z",
  "now": "2026-08-11T12:00:00Z",
  "phase": "READY",
  "run_id": "run-001"
}

$ cinderwell reaper --check --config examples/config.example.json --state examples/host.example.json \
    --now 2026-08-11T13:00:01Z
{
  "action": "reap",
  "expired": true,
  "expires_at": "2026-08-11T13:00:00Z",
  "now": "2026-08-11T13:00:01Z",
  "phase": "READY",
  "run_id": "run-001"
}
```

`--now` is an explicit input rather than a call to the clock, so the same
inputs always produce the same answer and a decision can be re-derived after
the fact.

The reaper runs on the operator's machine under launchd — not on the ephemeral
host, because deleting a Hetzner server needs a provider token and a disposable
box is the wrong place to keep one, and because `poweroff` is no substitute
when the provider bills for a server that *exists* rather than one that runs.
`cinderwell reaper --render-plist` emits the scheduled job; the rendered job
names the installed binary, never a repository checkout, because the reaper
outlives any one working copy. That property is enforced, not aspirational:
rendering refuses a binary that lives inside a git checkout — including a
`.venv` created inside this clone — so install somewhere durable first (a venv
outside the repository, or `pipx install .`).

**The reaper gets no private path.** It runs the ordinary teardown, guards and
all, and authorizes itself by writing an ordinary approval artifact naming the
ordinary plan — exactly as a human would. It cannot bypass a guard because it
has no mechanism to. The hazard was never automation; it is automation that
skips a check in order to avoid getting stuck.

So the interesting question is what happens when a guard refuses a host that is
already expired, and the answer is a ladder rather than a choice between two
bad options: **preserve first, then reap.** Before deciding anything, the
reaper pushes whatever the host is holding to a run-scoped ref
(`refs/lease/<run-id>`, never under `refs/heads`, `refs/tags`, or
`refs/remotes`, so it can never surprise someone by moving a branch they read).
Once the work is somewhere it will outlive the host, the work guard has nothing
left to refuse over. If a guard still refuses, the reaper escalates: it writes
a durable record naming what went wrong and when it *first* went wrong, exits
non-zero so the scheduler notices, and leaves the host alone. A file that says
"a host is running and billing" is retracted the moment it stops being true,
because a stale one is worse than none.

### Secrets

Configuration holds **commands that fetch secrets**, never secret values:

```json
"credentials": {
  "hcloud_token_command": ["your-secret-tool", "read", "hcloud/api-token"],
  "tailscale_api_token_command": ["your-secret-tool", "read", "tailscale/api-token"]
}
```

argv, run with no shell. Config loading refuses any value that *looks* like a
credential, because committing this file is the normal case. An already-exported
`HCLOUD_TOKEN` always wins, so interactive runs never invoke the command at
all. Both credentials resolve before either is exported, so a second one that
fails cannot leave the first sitting in the environment of a process about to
go and do something else. Provider output is redacted before it can reach an
error message, a receipt, or the console.

---

## Honest boundaries

Things this repository does **not** do, stated plainly:

- **The provider is mocked in every test.** No test in this suite talks to
  Hetzner or Tailscale. The fakes implement the same interfaces the real
  clients do and record every call, so "planning mutates nothing" and "deletion
  is by exact ID" are asserted rather than assumed — but a passing suite is
  evidence about *this code*, not about the provider's current API.
- **One exception, and it skips loudly.** A single contract test compares the
  flags Cinderwell emits against `hcloud server create --help` on the local
  machine. It is a local binary's help text, not a network call or an
  authenticated one, and it skips when `hcloud` is not installed.
- **Single provider.** Hetzner Cloud only, via the `hcloud` CLI, plus the
  Tailscale API for ephemeral auth keys. There is no provider abstraction
  layer, and adding one honestly would mean rewriting `provision` and
  `teardown` rather than adding an interface.
- **macOS-only scheduling.** The reaper's scheduled job is a launchd plist.
  There is no systemd unit. The reaper logic itself is portable; only the
  installer is not.
- **Cloud-init and the host side are not exercised end to end here.** The
  template ships and is rendered under test, and three tests parse the rendered
  YAML when a parser is installed — but nothing in this repository boots a
  machine to confirm what it does on arrival.
- **`approved_by` is attribution, not authentication.** It is self-asserted.
  An approval proves it was bound to one reviewed plan; it does not prove a
  human was present. The terminal path provides presence; the artifact path
  does not, and the receipt says which one it was.
- **The extract is narrower than the original.** Preview environments, host
  trust attestation, the serial-console reader, and the scheduled canary were
  cut. `cinderwell teardown` still stops and deletes a DevPod workspace when
  one is configured, because the guard is part of the teardown path — but
  DevPod integration beyond that is not here.
- **The `hourly`/`monthly` figures come from Hetzner's pricing endpoint** and
  are net of tax. Treat them as an envelope check, not an invoice.
- **This has not been run by anyone but its author.** It ran in production for
  one operator against one Hetzner project. Expect the rough edges of software
  with a user count of one.

---

## Layout

```
cinderwell/
  paths.py        machine-scoped config and state locations (XDG)
  lifecycle.py    read-only planning, pricing, leases, authority, receipts
  approve.py      write an approval naming one plan's exact hash
  provision.py    apply an approved plan; abort a half-created host
  teardown.py     destroy a host and prove absence by re-reading the provider
  reaper.py       enforce the lease on a schedule, preserving work first
  doctor.py       report on configuration and state locations
  resources/      JSON schemas, cloud-init template, launchd plist template
examples/
  config.example.json   a complete, synthetic configuration
  mock_teardown.py      the receipt above, generated on demand
tests/                  341 tests, hermetic (a throwaway HOME per fixture)
```

The JSON schemas in `cinderwell/resources/` are the durable contract. The
`authority` definition is written down three times — in the approval, state,
and receipt schemas — and a test asserts all three are byte-identical, because
a contract stated twice is a contract that drifts.

---

## License

MIT. See [LICENSE](LICENSE).
